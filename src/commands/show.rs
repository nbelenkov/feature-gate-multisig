use crate::commands::proposal::{
    describe_transaction, proposal_status_label, proposal_status_timestamp, ProposalKind,
};
use crate::commands::verify::report_cross_network_consistency;
use crate::constants::MAX_LISTED_PROPOSALS;
use crate::output::Output;
use crate::provision::{
    create_rpc_client, fetch_proposal, fetch_squads_multisig, get_squads_account_data_with_retry,
};
use crate::squads::{
    deserialize_squads_account, get_proposal_pda, get_transaction_pda, get_vault_pda, ConfigAction,
    ConfigTransaction, Multisig, Proposal, ProposalStatus, VaultTransaction,
    CONFIG_TRANSACTION_ACCOUNT_DISCRIMINATOR, PERMISSION_VOTE, PROPOSAL_ACCOUNT_DISCRIMINATOR,
    VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR,
};
use crate::utils::*;
use crate::verification::{
    expected_signers, is_autonomous, is_rekeyed, known_signer_name, member_set_warnings_for,
    multisig_safety_warnings, program_warnings, resolve_cluster, verify_feature_gate,
    verify_squads_program, FeatureGateStatus,
};
use colored::*;
use eyre::Result;
use inquire::Select;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use std::io::IsTerminal;
use tabled::{settings::Style, Table, Tabled};

pub fn show_command(
    config: &Config,
    address: Option<Pubkey>,
    network: Option<String>,
    detail_index: Option<u64>,
) -> Result<()> {
    // The address is already a key: it was parsed by the CLI value parser, or
    // by the prompt below. Nothing downstream re-validates a string.
    let address = match address {
        Some(address) => address,
        None => validate_pubkey_with_retry("Enter the feature gate multisig address:")?,
    };
    let rpc_url = match network {
        Some(arg) => resolve_network_arg(config, &arg)?,
        None => choose_network_from_config(config)?,
    };
    show_multisig(config, address, &rpc_url, detail_index)
}

/// The newest proposal indices a listing walks, capped. `transaction_index` is
/// unbounded data from the endpoint, so it must not size an allocation or drive
/// one network round trip per unit.
fn listed_indices(transaction_index: u64) -> Vec<u64> {
    if transaction_index == 0 {
        return Vec::new();
    }
    let oldest = transaction_index
        .saturating_sub(MAX_LISTED_PROPOSALS - 1)
        .max(1);
    (oldest..=transaction_index).collect()
}

fn show_multisig(
    config: &Config,
    multisig_pubkey: Pubkey,
    rpc_url: &str,
    detail_index: Option<u64>,
) -> Result<()> {
    let rpc_client = create_rpc_client(rpc_url);
    // fetch_squads_multisig validates owner == Squads program before deserializing,
    // so a spoofed look-alike account is rejected rather than rendered as a multisig.
    let multisig = fetch_squads_multisig(&rpc_client, &multisig_pubkey, "multisig")?;
    let vault0 = get_vault_pda(&multisig_pubkey, 0).0;

    // Classify every transaction up front: it feeds the proposals table and
    // tells us what this multisig is. A parent (voting) multisig's proposals
    // wrap actions on child multisigs; a feature gate multisig's proposals
    // act on the feature account.
    // transaction_index is unbounded remote data and the PDA binding does not
    // constrain it, so cap the sweep instead of allocating and fetching per the
    // endpoint's count. Same window the interactive picker uses.
    let shown = listed_indices(multisig.transaction_index);
    if let Some(oldest) = shown.first().filter(|oldest| **oldest > 1) {
        Output::info(&format!(
            "Showing proposals {oldest}-{}; {} older ones are not listed.",
            multisig.transaction_index,
            oldest - 1
        ));
    }
    let kinds: Vec<ProposalKind> = shown
        .iter()
        .map(|index| describe_transaction(&rpc_client, &multisig_pubkey, *index))
        .collect();
    let looks_like_parent = kinds
        .iter()
        .any(|kind| matches!(kind, ProposalKind::ChildAction));

    println!();
    // Always sweep the endpoint being inspected. Reading proposals from it but
    // feature state only from the saved list meant a `--network <url>` outside
    // that list reported another cluster's state, and skipped the rekey check
    // for the one on screen.
    let mut networks = config.networks.clone();
    if !networks.iter().any(|n| n == rpc_url) {
        networks.insert(0, rpc_url.to_string());
    }
    let mut network_multisigs: Vec<(&str, Multisig)> = Vec::new();

    if looks_like_parent {
        Output::header(&format!("📋 Squads Multisig {multisig_pubkey}"));
        Output::info(
            "This looks like a parent (voting) multisig: its proposals act on child multisigs.",
        );
        Output::field(
            "Voting identity (vault 0)",
            &format!("{vault0} (appears as a member on child multisigs)"),
        );
    } else {
        Output::header(&format!("📋 Feature Gate Multisig {multisig_pubkey}"));
        Output::field("Feature gate (vault 0)", &vault0.to_string());
    }

    // One sweep for both layouts. Keeping it out of the branch above means vault
    // 0's on-chain state is always reported: the parent layout is chosen by a
    // heuristic any member can trip with a single unapproved proposal, and it
    // used to suppress this line entirely.
    let mut states: Vec<String> = Vec::new();
    let mut unreadable: Vec<&str> = Vec::new();
    for url in &networks {
        let client = create_rpc_client(url);
        let state = match verify_feature_gate(&client, &multisig_pubkey) {
            Ok(v) => feature_status_label(&v.status),
            Err(_) => "unreachable".to_string(),
        };
        states.push(format!("{}: {}", get_network_display(url), state));
        // Name a network that drops out. Silently omitting it shrank the
        // denominator behind the consistency and rekey verdicts below.
        match fetch_squads_multisig(&client, &multisig_pubkey, "multisig") {
            Ok(ms) => network_multisigs.push((get_network_display(url), ms)),
            Err(e) => {
                Output::warning(&format!(
                    "Multisig not readable on {}: {e}",
                    get_network_display(url)
                ));
                unreadable.push(get_network_display(url));
            }
        }
    }
    let state_label = if looks_like_parent {
        "Vault 0 state"
    } else {
        "Feature state"
    };
    Output::field(state_label, &states.join(" | "));

    let voting_members = multisig
        .members
        .iter()
        .filter(|m| m.permissions.mask & PERMISSION_VOTE != 0)
        .count();
    Output::field(
        "Threshold",
        &format!(
            "{} of {} voting members",
            multisig.threshold, voting_members
        ),
    );
    Output::field(
        "Autonomous (config by vote)",
        &is_autonomous(&multisig).to_string(),
    );
    Output::field("Time lock", &format_time_lock(multisig.time_lock));

    // Rekey is per network: each cluster's multisig is independent state, so
    // one can be frozen while the others remain active.
    let rekeyed_on: Vec<&str> = network_multisigs
        .iter()
        .filter(|(_, ms)| is_rekeyed(ms))
        .map(|(network, _)| *network)
        .collect();
    if !rekeyed_on.is_empty() {
        let scope = if rekeyed_on.len() == network_multisigs.len() && unreadable.is_empty() {
            String::new()
        } else if !unreadable.is_empty() {
            format!(
                "; {} was not readable and has not been checked",
                unreadable.join(", ")
            )
        } else {
            "; the other networks remain active".to_string()
        };
        Output::warning(&format!(
            "Rekeyed (permanently frozen) on {}: voting keys there cannot meet the threshold, so no proposal can ever pass{}.",
            rekeyed_on.join(", "),
            scope
        ));
    }
    // The same program-authenticity check `verify` runs, on the inspected
    // network (this is the expensive one: it downloads the program bytecode).
    match verify_squads_program(&rpc_client) {
        Ok(program) => {
            // Same cross-check as `verify`: the endpoint must not be able to
            // pick how strictly its own program is checked.
            let mainnet = match resolve_cluster(&rpc_client, rpc_url) {
                Ok((mainnet, _)) => mainnet,
                Err(e) => {
                    Output::error(&e.to_string());
                    return Err(e);
                }
            };
            let warnings = program_warnings(&program, mainnet);
            if warnings.is_empty() {
                let status = if mainnet {
                    "authentic, immutable Squads v4 (bytecode verified)"
                } else {
                    "present; bytecode and immutability are asserted on mainnet only"
                };
                Output::field("Squads program", status);
            } else {
                for warning in warnings {
                    Output::warning(&warning);
                }
            }
        }
        Err(e) => Output::warning(&format!("Could not verify Squads program: {e}")),
    }
    for warning in multisig_safety_warnings(&multisig) {
        Output::warning(&warning);
    }
    // The same member-set check `verify` runs, warnings only: `show` gates
    // nothing, so there is no exit code or mainnet refusal here.
    match expected_signers(&config.members) {
        Some((expected, source)) => {
            Output::field("Owners checked against", source);
            for warning in member_set_warnings_for(&multisig, &expected) {
                Output::warning(&warning);
            }
        }
        None => Output::warning(
            "No expected signer set to check against: KNOWN_SIGNERS is empty in this build \
             and no members are saved in your config. Add the expected signers to `members` \
             in your config file (`config` prints its path; config.example.json shows the \
             shape). The member list below was displayed but not verified against anything.",
        ),
    }
    println!();

    print_members_table(&multisig);

    display_proposals_summary(&rpc_client, &multisig_pubkey, &multisig, &kinds);

    report_cross_network_consistency(&network_multisigs);
    if !unreadable.is_empty() {
        Output::warning(&format!(
            "This sweep is incomplete: {} could not be read, so nothing above accounts for {}.",
            unreadable.join(", "),
            if unreadable.len() == 1 { "it" } else { "them" }
        ));
    }

    if let Some(index) = detail_index {
        if index == 0 || index > multisig.transaction_index {
            return Err(eyre::eyre!(
                "Proposal index must be between 1 and {} for this multisig",
                multisig.transaction_index
            ));
        }
        display_full_details(&rpc_client, &multisig_pubkey, index);
        return Ok(());
    }
    offer_detail_drilldown(&rpc_client, &multisig_pubkey, &multisig)
}

fn feature_status_label(status: &FeatureGateStatus) -> String {
    match status {
        FeatureGateStatus::Fresh => "Fresh (not activated)".to_string(),
        FeatureGateStatus::Pending => "Pending activation".to_string(),
        FeatureGateStatus::Activated { slot } => format!("Activated (slot {slot})"),
        FeatureGateStatus::Unexpected { .. } => "Unexpected state".to_string(),
    }
}

/// One row per proposal: what it does and where it stands, on the selected
/// network. The instruction-level view stays available via the drill-down.
fn display_proposals_summary(
    rpc_client: &RpcClient,
    multisig_pubkey: &Pubkey,
    multisig: &Multisig,
    kinds: &[ProposalKind],
) {
    println!("{}", "🔄 PROPOSALS".bright_yellow().bold());
    println!();
    if multisig.transaction_index == 0 {
        println!("  No proposals yet.");
        println!();
        return;
    }

    #[derive(Tabled)]
    struct ProposalRow {
        #[tabled(rename = "#")]
        index: u64,
        #[tabled(rename = "Kind")]
        kind: &'static str,
        #[tabled(rename = "Status")]
        status: String,
        #[tabled(rename = "Approvals")]
        approvals: String,
        #[tabled(rename = "Rejections")]
        rejections: String,
        #[tabled(rename = "Updated")]
        updated: String,
    }

    // Print vote counts as progress against their cutoffs: approvals vs the
    // threshold, rejections vs the count that makes approval impossible.
    let voting_members = multisig
        .members
        .iter()
        .filter(|m| m.permissions.mask & PERMISSION_VOTE != 0)
        .count() as u64;
    let approve_cutoff = u64::from(multisig.threshold);
    let reject_cutoff = voting_members.saturating_sub(approve_cutoff) + 1;

    let mut rows = Vec::new();
    for index in listed_indices(multisig.transaction_index) {
        let kind = kinds
            .get(index as usize - 1)
            .map_or("Unknown", |k| k.label());
        let proposal = fetch_proposal(rpc_client, multisig_pubkey, index).ok();
        let (status, approvals, rejections, updated) = match proposal {
            Some(p) => (
                proposal_status_label(&p.status).to_string(),
                format!("{}/{}", p.approved.len(), approve_cutoff),
                format!("{}/{}", p.rejected.len(), reject_cutoff),
                proposal_status_timestamp(&p.status)
                    .map_or_else(|| "-".to_string(), format_relative_age),
            ),
            None => (
                "missing".to_string(),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
            ),
        };
        rows.push(ProposalRow {
            index,
            kind,
            status,
            approvals,
            rejections,
            updated,
        });
    }
    let mut table = Table::new(rows);
    table.with(Style::rounded());
    println!("{table}");
    println!();
}

/// Full on-chain detail for one proposal index: PDAs, the decoded transaction
/// at instruction level, and the raw proposal record. The debugging view.
fn display_full_details(rpc_client: &RpcClient, multisig_pubkey: &Pubkey, tx_index: u64) {
    println!(
        "{}",
        format!("📋 TRANSACTION INDEX {}", tx_index)
            .bright_cyan()
            .bold()
    );
    println!("{}", "─".repeat(50).bright_cyan());
    let (transaction_pda, _) = get_transaction_pda(multisig_pubkey, tx_index);
    let (proposal_pda, _) = get_proposal_pda(multisig_pubkey, tx_index);
    println!(
        "🎯 Transaction PDA: {}",
        transaction_pda.to_string().bright_white()
    );
    println!(
        "🎯 Proposal PDA: {}",
        proposal_pda.to_string().bright_white()
    );
    println!();
    if let Err(e) =
        fetch_and_display_transaction(rpc_client, multisig_pubkey, &transaction_pda, tx_index)
    {
        println!(
            "❌ Failed to fetch transaction {}: {}",
            tx_index,
            e.to_string().bright_red()
        );
    }
    if let Err(e) = fetch_and_display_proposal(rpc_client, multisig_pubkey, &proposal_pda, tx_index)
    {
        println!(
            "❌ Failed to fetch proposal {}: {}",
            tx_index,
            e.to_string().bright_red()
        );
    }
    println!();
}

/// Offer the instruction-level view interactively. Skipped when not attached
/// to a terminal or in non-interactive modes; `--index` reaches it directly.
fn offer_detail_drilldown(
    rpc_client: &RpcClient,
    multisig_pubkey: &Pubkey,
    multisig: &Multisig,
) -> Result<()> {
    if multisig.transaction_index == 0
        || !std::io::stdin().is_terminal()
        || is_e2e_test_mode()
        || is_assume_yes()
    {
        return Ok(());
    }
    loop {
        let mut options: Vec<String> = listed_indices(multisig.transaction_index)
            .into_iter()
            .map(|i| format!("#{i}"))
            .collect();
        options.push("Done".to_string());
        let selection = match Select::new("View full details for a proposal (debugging)?", options)
            .raw_prompt()
        {
            Ok(selection) => selection,
            Err(inquire::InquireError::OperationCanceled) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if selection.index as u64 >= multisig.transaction_index {
            return Ok(());
        }
        display_full_details(rpc_client, multisig_pubkey, selection.index as u64 + 1);
    }
}

/// Print the multisig members table (member index, pubkey, decoded permissions,
/// bitmask). Shared by `show` and `verify`.
pub(crate) fn print_members_table(multisig: &Multisig) {
    #[derive(Tabled)]
    struct MemberInfo {
        #[tabled(rename = "#")]
        index: usize,
        #[tabled(rename = "Public Key")]
        pubkey: String,
        #[tabled(rename = "Permissions")]
        permissions: String,
        #[tabled(rename = "Bitmask")]
        bitmask: u8,
    }

    // Break out voting members: the threshold above is stated against them,
    // not the plain total.
    let total = multisig.members.len();
    let voting = multisig
        .members
        .iter()
        .filter(|m| m.permissions.mask & PERMISSION_VOTE != 0)
        .count();
    let breakdown = if voting == total {
        format!("{total} total, all voting")
    } else {
        format!(
            "{total} total: {voting} voting, {} non-voting",
            total - voting
        )
    };
    println!("{} ({breakdown})", "👥 MEMBERS".bright_blue().bold());
    println!();

    let member_data: Vec<MemberInfo> = multisig
        .members
        .iter()
        .enumerate()
        .map(|(i, member)| {
            let perms = decode_permissions(member.permissions.mask);
            let pubkey = match known_signer_name(&member.key) {
                Some(name) => format!("{} ({name})", member.key),
                None => member.key.to_string(),
            };
            MemberInfo {
                index: i + 1,
                pubkey,
                permissions: if perms.is_empty() {
                    "None".to_string()
                } else {
                    perms.join(", ")
                },
                bitmask: member.permissions.mask,
            }
        })
        .collect();

    let mut members_table = Table::new(member_data);
    members_table.with(Style::rounded());
    println!("{}", members_table);
    println!();
}

/// Enum to hold either transaction type
enum TransactionType {
    Vault(VaultTransaction),
    Config(ConfigTransaction),
}

fn fetch_and_display_transaction(
    rpc_client: &RpcClient,
    multisig_pubkey: &Pubkey,
    transaction_pda: &Pubkey,
    tx_index: u64,
) -> Result<()> {
    println!("📦 Transaction Account Data:");

    // Fetch the transaction account
    let account_data = match get_squads_account_data_with_retry(rpc_client, transaction_pda) {
        Ok(data) => data,
        Err(e) => {
            if e.to_string().contains("AccountNotFound") {
                println!("  ⚠️  Transaction account not found");
                return Ok(());
            }
            return Err(eyre::eyre!("Failed to fetch transaction account: {}", e));
        }
    };

    if account_data.len() < 8 {
        println!("  ❌ Account data too small");
        return Ok(());
    }

    // Identify the transaction type by its account discriminator
    let result = if account_data[..8] == *VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR {
        deserialize_squads_account::<VaultTransaction>(
            &account_data,
            VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR,
            "vault transaction",
        )
        .map(TransactionType::Vault)
    } else if account_data[..8] == *CONFIG_TRANSACTION_ACCOUNT_DISCRIMINATOR {
        deserialize_squads_account::<ConfigTransaction>(
            &account_data,
            CONFIG_TRANSACTION_ACCOUNT_DISCRIMINATOR,
            "config transaction",
        )
        .map(TransactionType::Config)
    } else {
        println!("  ❌ Account discriminator matches neither Vault nor Config transaction");
        return Ok(());
    };

    let transaction = match result {
        Ok(tx) => tx,
        Err(e) => {
            println!("  ❌ {}", crate::output::scrub(&e.to_string()));
            return Ok(());
        }
    };

    // This view exists so an operator can inspect a proposal the classifier
    // could not vouch for, so it must not render a record that belongs to some
    // other multisig or index as though it were this one.
    let (claimed_multisig, claimed_index) = match &transaction {
        TransactionType::Vault(tx) => (tx.multisig, tx.index),
        TransactionType::Config(tx) => (tx.multisig, tx.index),
    };
    if claimed_multisig != *multisig_pubkey || claimed_index != tx_index {
        println!(
            "  ❌ Account records multisig {} index {}, not multisig {} index {}; not displaying it",
            claimed_multisig, claimed_index, multisig_pubkey, tx_index
        );
        return Ok(());
    }

    match transaction {
        TransactionType::Vault(transaction) => {
            display_vault_transaction(&transaction, tx_index);
        }
        TransactionType::Config(transaction) => {
            display_config_transaction(&transaction, tx_index);
        }
    }

    Ok(())
}

fn display_config_transaction(transaction: &ConfigTransaction, tx_index: u64) {
    #[derive(Tabled)]
    struct TransactionInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let tx_info = vec![
        TransactionInfo {
            property: "Type".to_string(),
            value: "Config Transaction".to_string(),
        },
        TransactionInfo {
            property: "Index".to_string(),
            value: transaction.index.to_string(),
        },
        TransactionInfo {
            property: "Creator".to_string(),
            value: transaction.creator.to_string(),
        },
        TransactionInfo {
            property: "Multisig".to_string(),
            value: transaction.multisig.to_string(),
        },
        TransactionInfo {
            property: "Account Bump".to_string(),
            value: transaction.bump.to_string(),
        },
        TransactionInfo {
            property: "Actions".to_string(),
            value: transaction.actions.len().to_string(),
        },
    ];

    let mut tx_table = Table::new(tx_info);
    tx_table.with(Style::rounded());
    println!("{}", tx_table);

    // Display config actions
    if !transaction.actions.is_empty() {
        println!();
        println!("📋 Config Actions:");

        for (i, action) in transaction.actions.iter().enumerate() {
            let action_desc = match action {
                ConfigAction::AddMember { new_member } => {
                    format!(
                        "Add Member: {} (permissions: {})",
                        new_member.key, new_member.permissions.mask
                    )
                }
                ConfigAction::RemoveMember { old_member } => {
                    format!("Remove Member: {}", old_member)
                }
                ConfigAction::ChangeThreshold { new_threshold } => {
                    format!("Change Threshold to: {}", new_threshold)
                }
            };
            println!("  {}. {}", i + 1, action_desc.bright_white());
        }
    }

    println!("  ✅ Transaction {} details retrieved", tx_index);
    println!();
}

fn display_vault_transaction(transaction: &VaultTransaction, tx_index: u64) {
    // Display transaction details in a table
    #[derive(Tabled)]
    struct TransactionInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let tx_info = vec![
        TransactionInfo {
            property: "Index".to_string(),
            value: transaction.index.to_string(),
        },
        TransactionInfo {
            property: "Creator".to_string(),
            value: transaction.creator.to_string(),
        },
        TransactionInfo {
            property: "Multisig".to_string(),
            value: transaction.multisig.to_string(),
        },
        TransactionInfo {
            property: "Vault Index".to_string(),
            value: transaction.vault_index.to_string(),
        },
        TransactionInfo {
            property: "Vault Bump".to_string(),
            value: transaction.vault_bump.to_string(),
        },
        TransactionInfo {
            property: "Account Bump".to_string(),
            value: transaction.bump.to_string(),
        },
        TransactionInfo {
            property: "Ephemeral Signers".to_string(),
            value: transaction.ephemeral_signer_bumps.len().to_string(),
        },
    ];

    let mut tx_table = Table::new(tx_info);
    tx_table.with(Style::rounded());
    println!("{}", tx_table);

    // Display transaction message details
    println!();
    println!("📋 Transaction Message Details:");

    #[derive(Tabled)]
    struct MessageInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let msg_info = vec![
        MessageInfo {
            property: "Signers".to_string(),
            value: transaction.message.num_signers.to_string(),
        },
        MessageInfo {
            property: "Writable Signers".to_string(),
            value: transaction.message.num_writable_signers.to_string(),
        },
        MessageInfo {
            property: "Writable Non-Signers".to_string(),
            value: transaction.message.num_writable_non_signers.to_string(),
        },
        MessageInfo {
            property: "Account Keys".to_string(),
            value: transaction.message.account_keys.len().to_string(),
        },
        MessageInfo {
            property: "Instructions".to_string(),
            value: transaction.message.instructions.len().to_string(),
        },
        MessageInfo {
            property: "Address Table Lookups".to_string(),
            value: transaction.message.address_table_lookups.len().to_string(),
        },
    ];

    let mut msg_table = Table::new(msg_info);
    msg_table.with(Style::rounded());
    println!("{}", msg_table);

    // Display detailed instruction breakdown
    if !transaction.message.instructions.is_empty() {
        println!();
        println!("📋 Instructions Details:");

        #[derive(Tabled)]
        struct InstructionDetails {
            #[tabled(rename = "Instruction #")]
            instruction_num: String,
            #[tabled(rename = "Program ID")]
            program_id: String,
            #[tabled(rename = "Accounts")]
            accounts: String,
            #[tabled(rename = "Data (bytes)")]
            data: String,
        }

        let instruction_details: Vec<InstructionDetails> = transaction
            .message
            .instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                // Get the program ID from account_keys
                let program_id = if (instruction.program_id_index as usize)
                    < transaction.message.account_keys.len()
                {
                    transaction.message.account_keys[instruction.program_id_index as usize]
                        .to_string()
                } else {
                    format!("Invalid index ({})", instruction.program_id_index)
                };

                // Format account indexes with their corresponding pubkeys
                let accounts_info = if instruction.account_indexes.is_empty() {
                    "None".to_string()
                } else {
                    instruction
                        .account_indexes
                        .iter()
                        .map(|&account_idx| {
                            if (account_idx as usize) < transaction.message.account_keys.len() {
                                format!(
                                    "{}:{}",
                                    account_idx,
                                    &transaction.message.account_keys[account_idx as usize]
                                        .to_string()[..8]
                                )
                            } else {
                                format!("{}:Invalid", account_idx)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                // Print data in full. Truncating hid the tail of an `assign`,
                // whose last 32 bytes are the new owner - the field that tells a
                // hijack from a real activation, in the view meant for judging
                // exactly that.
                let data_str = if instruction.data.is_empty() {
                    "Empty".to_string()
                } else {
                    instruction
                        .data
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                };

                InstructionDetails {
                    instruction_num: (i + 1).to_string(),
                    program_id,
                    accounts: accounts_info,
                    data: data_str,
                }
            })
            .collect();

        let mut instructions_table = Table::new(instruction_details);
        instructions_table.with(Style::rounded());
        println!("{}", instructions_table);

        // Display account keys reference table
        if !transaction.message.account_keys.is_empty() {
            println!();
            println!("🔑 Account Keys Reference:");

            #[derive(Tabled)]
            struct AccountKeyInfo {
                #[tabled(rename = "Index")]
                index: usize,
                #[tabled(rename = "Public Key")]
                pubkey: String,
                #[tabled(rename = "Role")]
                role: String,
            }

            let account_key_info: Vec<AccountKeyInfo> = transaction
                .message
                .account_keys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| {
                    // Writability comes from the same function that builds the
                    // real execution metas, so the displayed role always matches
                    // what Squads applies. Computing it here summed two u8 header
                    // fields before widening, which wrapped above 255 and showed
                    // writable accounts as read-only.
                    let signer = i < usize::from(transaction.message.num_signers);
                    let writable = transaction.message.is_static_writable_index(i);
                    let role = match (signer, writable) {
                        (true, true) => "Writable Signer",
                        (true, false) => "Read-only Signer",
                        (false, true) => "Writable Non-signer",
                        (false, false) => "Read-only Non-signer",
                    };

                    AccountKeyInfo {
                        index: i,
                        pubkey: pubkey.to_string(),
                        role: role.to_string(),
                    }
                })
                .collect();

            let mut account_keys_table = Table::new(account_key_info);
            account_keys_table.with(Style::rounded());
            println!("{}", account_keys_table);
        }
    }

    println!("  ✅ Transaction {} details retrieved", tx_index);
    println!();
}

fn fetch_and_display_proposal(
    rpc_client: &RpcClient,
    multisig_pubkey: &Pubkey,
    proposal_pda: &Pubkey,
    tx_index: u64,
) -> Result<()> {
    println!("🗳️  Proposal Account Data:");

    // Fetch the proposal account
    let account_data = match get_squads_account_data_with_retry(rpc_client, proposal_pda) {
        Ok(data) => data,
        Err(e) => {
            if e.to_string().contains("AccountNotFound") {
                println!("  ⚠️  Proposal account not found");
                return Ok(());
            }
            return Err(eyre::eyre!("Failed to fetch proposal account: {}", e));
        }
    };

    if account_data.len() < 8 {
        println!("  ❌ Account data too small");
        return Ok(());
    }

    // Deserialize the Proposal
    let proposal: Proposal =
        match deserialize_squads_account(&account_data, PROPOSAL_ACCOUNT_DISCRIMINATOR, "proposal")
        {
            Ok(prop) => prop,
            Err(e) => {
                println!("  ❌ {}", crate::output::scrub(&e.to_string()));
                return Ok(());
            }
        };

    // The approval and rejection rosters below are what an operator counts votes
    // from, so the record has to belong to the multisig and index being viewed.
    if proposal.multisig != *multisig_pubkey || proposal.transaction_index != tx_index {
        println!(
            "  ❌ Proposal records multisig {} index {}, not multisig {} index {}; not displaying it",
            proposal.multisig, proposal.transaction_index, multisig_pubkey, tx_index
        );
        return Ok(());
    }

    // Display proposal details in a table
    #[derive(Tabled)]
    struct ProposalInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let status_str = match &proposal.status {
        ProposalStatus::Draft { timestamp } => format!("Draft ({})", timestamp),
        ProposalStatus::Active { timestamp } => format!("Active ({})", timestamp),
        ProposalStatus::Rejected { timestamp } => format!("Rejected ({})", timestamp),
        ProposalStatus::Approved { timestamp } => format!("Approved ({})", timestamp),
        ProposalStatus::Executed { timestamp } => format!("Executed ({})", timestamp),
        ProposalStatus::Cancelled { timestamp } => format!("Cancelled ({})", timestamp),
        #[allow(deprecated)]
        ProposalStatus::Executing => "Executing (deprecated)".to_string(),
    };

    let proposal_info = vec![
        ProposalInfo {
            property: "Transaction Index".to_string(),
            value: proposal.transaction_index.to_string(),
        },
        ProposalInfo {
            property: "Multisig".to_string(),
            value: proposal.multisig.to_string(),
        },
        ProposalInfo {
            property: "Status".to_string(),
            value: status_str,
        },
        ProposalInfo {
            property: "Account Bump".to_string(),
            value: proposal.bump.to_string(),
        },
        ProposalInfo {
            property: "Approved Count".to_string(),
            value: proposal.approved.len().to_string(),
        },
        ProposalInfo {
            property: "Rejected Count".to_string(),
            value: proposal.rejected.len().to_string(),
        },
        ProposalInfo {
            property: "Cancelled Count".to_string(),
            value: proposal.cancelled.len().to_string(),
        },
    ];

    let mut proposal_table = Table::new(proposal_info);
    proposal_table.with(Style::rounded());
    println!("{}", proposal_table);

    // Display voting details if there are votes
    if !proposal.approved.is_empty()
        || !proposal.rejected.is_empty()
        || !proposal.cancelled.is_empty()
    {
        println!();
        println!("🗳️  Voting Details:");

        #[derive(Tabled)]
        struct VoteInfo {
            #[tabled(rename = "Vote Type")]
            vote_type: String,
            #[tabled(rename = "Member")]
            member: String,
        }

        let mut votes = Vec::new();

        for member in &proposal.approved {
            votes.push(VoteInfo {
                vote_type: "Approved".to_string(),
                member: member.to_string(),
            });
        }

        for member in &proposal.rejected {
            votes.push(VoteInfo {
                vote_type: "Rejected".to_string(),
                member: member.to_string(),
            });
        }

        for member in &proposal.cancelled {
            votes.push(VoteInfo {
                vote_type: "Cancelled".to_string(),
                member: member.to_string(),
            });
        }

        let mut votes_table = Table::new(votes);
        votes_table.with(Style::rounded());
        println!("{}", votes_table);
    }

    println!("  ✅ Proposal {} details retrieved", tx_index);
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `transaction_index` is unbounded remote data and the PDA binding does not
    /// constrain it, so it must never size an allocation or drive one network
    /// round trip per unit. u64::MAX previously aborted the process on the
    /// capacity reservation alone.
    #[test]
    fn proposal_listing_is_bounded_by_the_window() {
        assert!(listed_indices(0).is_empty());

        // Fewer than the cap: everything, oldest first.
        assert_eq!(listed_indices(3), vec![1, 2, 3]);

        // Exactly the cap.
        assert_eq!(
            listed_indices(MAX_LISTED_PROPOSALS).len() as u64,
            MAX_LISTED_PROPOSALS
        );
        assert_eq!(listed_indices(MAX_LISTED_PROPOSALS)[0], 1);

        // Beyond it: the newest window, never more.
        let many = listed_indices(1_000);
        assert_eq!(many.len() as u64, MAX_LISTED_PROPOSALS);
        assert_eq!(*many.last().unwrap(), 1_000);
        assert_eq!(many[0], 1_000 - MAX_LISTED_PROPOSALS + 1);

        // The hostile case: a fabricated counter must not be allocated for.
        let absurd = listed_indices(u64::MAX);
        assert_eq!(absurd.len() as u64, MAX_LISTED_PROPOSALS);
        assert_eq!(*absurd.last().unwrap(), u64::MAX);
    }
}
