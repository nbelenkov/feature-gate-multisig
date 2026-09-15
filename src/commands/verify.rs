use crate::commands::show::print_members_table;
use crate::constants::DEFAULT_DEVNET_URL;
use crate::output::Output;
use crate::provision::{create_rpc_client, fetch_squads_multisig};
use crate::squads::{Multisig, PERMISSION_VOTE};
use crate::utils::{format_time_lock, get_network_display, validate_pubkey_with_retry, Config};
use crate::verification::{
    config_fingerprint, expected_signers, is_autonomous, is_rekeyed, member_set_warnings_for,
    multisig_safety_warnings, program_warnings, resolve_cluster, verify_feature_gate,
    verify_squads_program, FeatureVerification, ProgramAuthenticity,
};
use eyre::Result;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;

/// Verify a feature gate multisig: the Squads program is authentic, the feature
/// account is in the expected state, and who the owners are. Read-only, and
/// runs across every configured network.
pub fn verify_command(config: &Config, address: Option<Pubkey>) -> Result<()> {
    let multisig = match address {
        Some(address) => address,
        None => validate_pubkey_with_retry("Enter the feature gate multisig address:")?,
    };

    let networks = if config.networks.is_empty() {
        vec![DEFAULT_DEVNET_URL.to_string()]
    } else {
        config.networks.clone()
    };

    Output::header(&format!("🔎 Verifying feature gate multisig {multisig}"));

    let mut seen = Vec::new();
    // Warn-and-exit-0 reads as "verified" to anything checking the exit code, so
    // a check that could not run - or ran and reported a problem - has to fail.
    let mut incomplete = false;
    // Track whether every configured network was read and every copy is
    // rekeyed, so a deliberate decommission reports as one instead of as a
    // failed correctness check. A network that did not answer holds a copy this
    // run never saw, so it disqualifies that claim.
    let mut all_rekeyed = true;
    let mut every_network_read = true;
    for network in &networks {
        println!();
        Output::header(&format!(
            "🌐 {} ({})",
            get_network_display(network),
            network
        ));
        let rpc = create_rpc_client(network);
        // Cluster identity decides how strictly the program is checked, so the
        // endpoint's self-report is cross-checked against the URL and any
        // disagreement stops the run rather than relaxing the audit.
        let mainnet = match resolve_cluster(&rpc, network) {
            Ok((mainnet, true)) => mainnet,
            Ok((fallback, false)) => {
                Output::warning(&format!(
                    "Could not detect the cluster from its genesis hash; using the URL \
                     heuristic (mainnet: {fallback}). The cluster is unverified."
                ));
                incomplete = true;
                fallback
            }
            Err(e) => {
                Output::error(&e.to_string());
                incomplete = true;
                every_network_read = false;
                continue;
            }
        };
        let (found, failed) = verify_on_network(&rpc, &multisig, mainnet, &config.members);
        incomplete |= failed;
        match found {
            Some(ms) => {
                all_rekeyed &= is_rekeyed(&ms);
                seen.push((get_network_display(network), ms));
            }
            None => every_network_read = false,
        }
    }

    // Drift between clusters means at least one deployment is tampered or stale.
    incomplete |= report_cross_network_consistency(&seen);

    if incomplete {
        // A rekeyed multisig is not a broken one, it is a decommissioned one.
        // Reporting "has not been shown to be correct" for an intentional,
        // irreversible end state trains people to shrug at that sentence -- the
        // exact sentence that must still mean something when a real check fails.
        // Still a non-zero exit, so `verify && approve` cannot sail through.
        if every_network_read && all_rekeyed {
            return Err(eyre::eyre!(
                "This multisig is DECOMMISSIONED: it has been rekeyed on every configured \
                 network, so no proposal can ever pass and its feature gate is frozen where it \
                 stands. Nothing further can be done with it. If you expected a live multisig, \
                 you have the wrong address. Any other warnings above still stand."
            ));
        }
        return Err(eyre::eyre!(
            "Verification failed: see the warnings above. The multisig has not been shown to be correct."
        ));
    }
    Ok(())
}

/// Returns the multisig if readable, and whether any check failed - either
/// because it could not run, or because it ran and reported a problem. The
/// latter is the stronger negative of the two, so it fails the command too.
fn verify_on_network(
    rpc: &RpcClient,
    multisig: &Pubkey,
    is_mainnet: bool,
    expected_members: &[String],
) -> (Option<Multisig>, bool) {
    let mut failed = false;
    match verify_squads_program(rpc) {
        Ok(p) => failed |= display_program_authenticity(&p, is_mainnet),
        Err(e) => {
            Output::warning(&format!("Could not verify Squads program: {e}"));
            failed = true;
        }
    }
    // Read the multisig before the feature account: a rekeyed multisig can
    // never act again, which changes what its feature's status *means*. "Fresh"
    // on a live multisig is a pending job; on a rekeyed one it is a permanent
    // dead end, and the report should not read the same in both cases.
    let ms = fetch_squads_multisig(rpc, multisig, "multisig");
    let rekeyed = ms.as_ref().map(is_rekeyed).unwrap_or(false);

    match verify_feature_gate(rpc, multisig) {
        Ok(v) => failed |= display_feature(&v, rekeyed),
        Err(e) => {
            Output::warning(&format!("Could not read feature gate account: {e}"));
            failed = true;
        }
    }
    match ms {
        Ok(ms) => {
            failed |= display_owners(&ms, is_mainnet, expected_members);
            (Some(ms), failed)
        }
        Err(e) => {
            Output::warning(&format!("Multisig not readable on this network: {e}"));
            (None, true)
        }
    }
}

/// Flag governance-config drift across networks. The tool deploys identical
/// config everywhere, so any difference between the clusters where the multisig
/// exists points to a tampered or stale deployment.
/// Returns true when the deployments disagree.
pub(crate) fn report_cross_network_consistency(seen: &[(&str, Multisig)]) -> bool {
    if seen.len() < 2 {
        return false;
    }
    println!();
    Output::header("🔗 Cross-network Consistency");

    let (first_net, first_ms) = &seen[0];
    let reference = config_fingerprint(first_ms);
    let mismatched: Vec<&str> = seen
        .iter()
        .skip(1)
        .filter(|(_, ms)| config_fingerprint(ms) != reference)
        .map(|(net, _)| *net)
        .collect();

    if mismatched.is_empty() {
        // Name the networks compared: "all N" counted only the endpoints that
        // answered, so a dropped cluster shrank the claim without saying so.
        Output::success(&format!(
            "Multisig config is identical across the {} networks compared ({}).",
            seen.len(),
            seen.iter()
                .map(|(net, _)| *net)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        false
    } else {
        Output::warning(&format!(
            "Multisig config on {} differs from {}; the deployment is inconsistent across networks.",
            mismatched.join(", "),
            first_net
        ));
        true
    }
}

/// Returns true when the program failed authenticity checks.
fn display_program_authenticity(p: &ProgramAuthenticity, is_mainnet: bool) -> bool {
    println!();
    Output::header("⚙️ Squads Program Authenticity");
    Output::field("Program", &p.program_id.to_string());
    Output::field("Executable", &p.executable.to_string());
    Output::field(
        "Owned by upgradeable loader",
        &p.loader_owner_ok.to_string(),
    );

    if is_mainnet {
        Output::field("Immutable (frozen)", &p.immutable.to_string());
        Output::field("Bytecode hash matches", &p.hash_matches.to_string());
    } else {
        Output::field(
            "Upgrade authority",
            &p.upgrade_authority
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none".to_string()),
        );
        Output::info(
            "Immutability and the verified bytecode hash are only asserted on mainnet; Squads keeps its devnet/testnet deployments upgradeable.",
        );
    }

    let warnings = program_warnings(p, is_mainnet);
    if warnings.is_empty() {
        if is_mainnet {
            Output::success("Program is the authentic, immutable Squads v4.");
        } else {
            Output::success("Squads program is present and loaded by the upgradeable loader.");
        }
        false
    } else {
        for warning in &warnings {
            Output::warning(warning);
        }
        true
    }
}

/// Returns true when the feature account is in an unexpected state - an owner or
/// data length this tool does not recognise.
fn display_feature(v: &FeatureVerification, multisig_rekeyed: bool) -> bool {
    use crate::verification::FeatureGateStatus;
    println!();
    Output::header("🪄 Feature Gate");
    Output::field("Feature gate ID (vault 0)", &v.feature_id.to_string());
    // A rekeyed multisig can never pass another proposal, so a feature it still
    // governs is frozen wherever it stands. Saying only "Fresh" or "Pending"
    // reads as work outstanding when it is actually a terminal state.
    let status = match (&v.status, multisig_rekeyed) {
        (FeatureGateStatus::Activated { .. }, _) => format!("{:?}", v.status),
        (s, true) => format!(
            "{s:?} - PERMANENT: the multisig is rekeyed, so this can never be activated or revoked"
        ),
        (s, false) => format!("{s:?}"),
    };
    Output::field("Status", &status);
    Output::field("Lamports", &v.lamports.to_string());
    Output::field("Rent-exempt", &v.rent_exempt.to_string());
    if let crate::verification::FeatureGateStatus::Unexpected { owner, data_len } = &v.status {
        Output::warning(&format!(
            "Feature gate account is in an unexpected state: owner {owner}, {data_len} bytes."
        ));
        return true;
    }
    false
}

/// Returns true when this multisig should not be acted on: a config authority
/// can rewrite members and threshold unilaterally, it has been rekeyed, the
/// voting members differ from the expected set, or (on mainnet) there is no
/// expected set at all. A time lock only warns.
fn display_owners(ms: &Multisig, is_mainnet: bool, expected_members: &[String]) -> bool {
    let voting_members = ms
        .members
        .iter()
        .filter(|m| m.permissions.mask & PERMISSION_VOTE != 0)
        .count();

    println!();
    Output::header("👥 Owners");
    Output::field(
        "Threshold",
        &format!("{} of {} voting members", ms.threshold, voting_members),
    );
    Output::field(
        "Autonomous (config by vote)",
        &is_autonomous(ms).to_string(),
    );
    Output::field("Time lock", &format_time_lock(ms.time_lock));
    let rekeyed = is_rekeyed(ms);
    if rekeyed {
        Output::warning(
            "This multisig has been rekeyed: its voting keys cannot meet the threshold, so no proposal can ever pass and the configuration is permanently frozen.",
        );
    }
    print_members_table(ms);

    for warning in multisig_safety_warnings(ms) {
        Output::warning(&warning);
    }
    // Check members against the vendored set when this build has one,
    // otherwise the operator's configured members. No expectation at all is
    // reported, not silently passed.
    //
    // Skipped entirely once rekeyed. Rekeying *is* "every expected signer was
    // removed and an unsignable dummy put in their place", so comparing the
    // member set against expectations restates the rekey warning once per
    // signer and buries the one fact that matters. The rekey itself already
    // forces a non-zero exit below.
    let (member_warnings, unconfigured_signer_set) = if rekeyed {
        Output::info(
            "This multisig has been rekeyed: there are no governance signers left to check \
             against, so the owner check was skipped.",
        );
        (Vec::new(), false)
    } else {
        match expected_signers(expected_members) {
            Some((expected, source)) => {
                Output::field("Owners checked against", source);
                (member_set_warnings_for(ms, &expected), false)
            }
            None => {
                Output::warning(
                    "No expected signer set to check against: KNOWN_SIGNERS is empty in this \
                     build and no members are saved in your config. Add the expected signers \
                     to `members` in your config file (`config` prints its path; \
                     config.example.json shows the shape). The member list above was displayed \
                     but not verified against anything.",
                );
                (Vec::new(), is_mainnet)
            }
        }
    };
    for warning in &member_warnings {
        Output::warning(warning);
    }

    // Each of these is a reason not to act; all must reach the exit code so
    // `verify && approve` cannot sail through.
    !is_autonomous(ms) || rekeyed || !member_warnings.is_empty() || unconfigured_signer_set
}
