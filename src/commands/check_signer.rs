//! `check-signer`: confirm a signer is usable before an activation depends on it.
//! Reading the public key needs the device present and unlocked but signs
//! nothing, so an unreachable device or a non-member key surfaces days ahead
//! instead of mid-signing.

use crate::output::Output;
use crate::provision::{create_rpc_client, fetch_squads_multisig};
use crate::squads::{Member, PERMISSION_EXECUTE, PERMISSION_INITIATE, PERMISSION_VOTE};
use crate::utils::{choose_network_from_config, load_signer, resolve_network_arg, Config};
use crate::verification::is_rekeyed;
use eyre::Result;
use solana_pubkey::Pubkey;

/// Resolve `keypair_path` to a public key and, when a multisig is given, report
/// whether that key can act on it. Signs nothing.
pub fn check_signer_command(
    config: &Config,
    keypair_path: Option<String>,
    multisig: Option<Pubkey>,
    network: Option<String>,
) -> Result<()> {
    let path = keypair_path
        .or_else(|| config.fee_payer_path.clone())
        .ok_or_else(|| {
            eyre::eyre!("No signer to check: pass --keypair, or save one with `config`")
        })?;

    Output::header("🔑 Checking signer");
    Output::field("Path", &path);
    if path.starts_with("usb://") {
        Output::info("Reading the public key from the device. It must be plugged in, unlocked, and on the Solana app. Nothing is signed.");
    }

    // The error text matters: "no device found" means plug it in, while
    // "hidapi crate compilation disabled" means this build cannot talk to a
    // hardware wallet at all.
    let signer = load_signer(&path, "signer")?;
    let pubkey = signer.pubkey();
    Output::success(&format!("Signer resolved: {pubkey}"));

    let Some(multisig) = multisig else {
        Output::hint("Pass --multisig <ADDRESS> to also check this key can act on it.");
        return Ok(());
    };
    // --network keeps this scriptable; the picker is interactive-only.
    let rpc_url = match network {
        Some(arg) => resolve_network_arg(config, &arg)?,
        None => choose_network_from_config(config)?,
    };
    let ms = fetch_squads_multisig(&create_rpc_client(&rpc_url), &multisig, "multisig")?;
    Output::field("Multisig", &multisig.to_string());
    Output::field("Network", &rpc_url);

    let Some(member) = ms.members.iter().find(|m| m.key == pubkey) else {
        return Err(eyre::eyre!(
            "{pubkey} is not a member of multisig {multisig}. This signer cannot act on it - \
             check you are using the right device, derivation path, or multisig address."
        ));
    };

    Output::field("Permissions", &describe_permissions(member));
    if member.permissions.mask & PERMISSION_VOTE == 0 {
        return Err(eyre::eyre!(
            "{pubkey} is a member of {multisig} but cannot vote, so it cannot approve or reject \
             proposals. Only an Initiate-only key (the contributor) looks like this."
        ));
    }

    Output::success("This signer is a voting member and can approve proposals on this multisig.");
    if member.permissions.mask & PERMISSION_EXECUTE == 0 {
        Output::warning("It cannot execute, so someone else has to send the final transaction.");
    }
    // Membership means nothing on a frozen multisig, so say so even though the
    // signer checks all passed.
    if is_rekeyed(&ms) {
        Output::warning(
            "This multisig has been rekeyed: its voting keys cannot meet the threshold, so no \
             proposal can ever pass and this signer's vote can never be exercised.",
        );
    }
    Ok(())
}

fn describe_permissions(member: &Member) -> String {
    let mut parts = Vec::new();
    for (mask, name) in [
        (PERMISSION_INITIATE, "Initiate"),
        (PERMISSION_VOTE, "Vote"),
        (PERMISSION_EXECUTE, "Execute"),
    ] {
        if member.permissions.mask & mask != 0 {
            parts.push(name);
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::squads::Permissions;

    fn member(mask: u8) -> Member {
        Member {
            key: Pubkey::new_unique(),
            permissions: Permissions { mask },
        }
    }

    #[test]
    fn permissions_render_in_a_fixed_order() {
        assert_eq!(
            describe_permissions(&member(
                PERMISSION_INITIATE | PERMISSION_VOTE | PERMISSION_EXECUTE
            )),
            "Initiate, Vote, Execute"
        );
        assert_eq!(
            describe_permissions(&member(PERMISSION_INITIATE)),
            "Initiate"
        );
        assert_eq!(
            describe_permissions(&member(PERMISSION_VOTE | PERMISSION_EXECUTE)),
            "Vote, Execute"
        );
        assert_eq!(describe_permissions(&member(0)), "none");
    }
}
