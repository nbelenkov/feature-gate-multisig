use crate::commands::proposal::{
    describe_transaction, proposal_status_label, unverifiable_proposal_error, ProposalKind,
};
use crate::commands::{
    check_signer_command, config_command, create_command, proposal_command, show_command,
    verify_command, ProposalCommand, ProposalCommandArgs, TransactionKind,
};
use crate::output::Output;
use crate::provision::{create_rpc_client, fetch_proposal, fetch_squads_multisig};
use crate::squads::{get_vault_pda, ProposalStatus};
use crate::utils::*;
use eyre::Result;
use inquire::{Confirm, Select, Text};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use std::str::FromStr;

pub fn interactive_mode() -> Result<()> {
    let mut config = load_config()?;
    // Session memory: the multisig acted on last, pre-filled on the next pass.
    // Useful when driving the same feature gate across several networks.
    let mut last_multisig: Option<String> = None;

    loop {
        let options = vec![
            "Create new feature gate multisig",
            "Show feature gate multisig details",
            "Verify feature gate multisig",
            "Check signer (signs nothing)",
            "Show configuration",
            "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)",
            "Exit",
        ];

        let choice: &str = match Select::new("What would you like to do?", options).prompt() {
            Ok(choice) => choice,
            // Esc at the top level means quit.
            Err(inquire::InquireError::OperationCanceled) => break,
            Err(e) => return Err(e.into()),
        };

        let result = match choice {
            "Create new feature gate multisig" => prompt_for_fee_payer_path(&config)
                .and_then(|path| create_command(&mut config, None, Some(path))),
            "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)" => {
                handle_proposal_action(&config, &mut last_multisig)
            }
            // Both commands prompt for the address themselves, with the same
            // retry-on-typo loop, so there is one place that turns text into a
            // key rather than one per entry point.
            "Show feature gate multisig details" => show_command(&config, None, None, None),
            "Verify feature gate multisig" => verify_command(&config, None),
            "Check signer (signs nothing)" => handle_check_signer(&config, &last_multisig),
            "Show configuration" => config_command(&config),
            "Exit" => break,
            _ => unreachable!(),
        };

        // Esc inside an action cancels back to the menu. A failed action is
        // reported and also returns to the menu: an unreachable RPC endpoint or
        // a rejected input is a reason to retry or pick another action, not to
        // lose the session.
        match result {
            Ok(()) => {}
            Err(e) if is_prompt_cancellation(&e) => Output::info("Cancelled."),
            Err(e) => Output::error(&format!("{e:#}")),
        }

        println!("\n");
    }

    Ok(())
}

/// Interactive `check-signer`: prompt for a keypair path and an optional
/// multisig, then run the same checks as the CLI subcommand.
fn handle_check_signer(config: &Config, last_multisig: &Option<String>) -> Result<()> {
    let default_path = config.fee_payer_path.as_deref().unwrap_or("usb://ledger");
    let path = Text::new("Enter the signer keypair path to check:")
        .with_default(default_path)
        .prompt()?;
    let path = expand_tilde_path(&path)?;

    let multisig = loop {
        let mut text = Text::new("Multisig to check membership against (leave empty to skip):");
        if let Some(last) = last_multisig.as_deref() {
            text = text.with_default(last);
        }
        let input = text.prompt()?;
        let input = input.trim();
        if input.is_empty() {
            break None;
        }
        match Pubkey::from_str(input) {
            Ok(key) => break Some(key),
            Err(_) => Output::warning("Invalid public key, please try again."),
        }
    };

    check_signer_command(config, Some(path), multisig, None)
}

/// True when the error is the user pressing Esc in an inquire prompt.
fn is_prompt_cancellation(error: &eyre::Report) -> bool {
    matches!(
        error.downcast_ref::<inquire::InquireError>(),
        Some(inquire::InquireError::OperationCanceled)
    )
}

fn handle_proposal_action(config: &Config, last_multisig: &mut Option<String>) -> Result<()> {
    println!("In the current setup, only the fee payer keypair is used for transactions, hence for EOA voting fee payer = voting account. For multisig setup, the fee payer needs to be a member of the parent multisig.\n");

    let multisig = prompt_for_pubkey_with_default(
        "Enter the feature gate multisig address:",
        last_multisig.as_deref(),
    )?;
    *last_multisig = Some(multisig.to_string());
    let feature_gate_id = get_vault_pda(&multisig, 0).0;

    // Pick the network once up front: the proposal picker queries it, and the
    // single-network config makes the downstream flows skip their own prompt.
    // The original `config` stays around for prompts that persist defaults.
    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);
    let network_config = Config {
        networks: vec![rpc_url.clone()],
        ..config.clone()
    };

    // Name the kinds inline: Revoke and Rekey are only reachable through Create,
    // and a bare "Create" gave no hint that they exist.
    const CREATE: &str = "Create (Activate / Revoke / Rekey)";
    let action_options = vec![CREATE, "Approve", "Reject", "Execute", "Cancel"];
    let action_choice: &str = Select::new("Select action:", action_options).prompt()?;
    if action_choice == "Cancel" {
        return Ok(());
    }

    // Create picks a kind (nothing exists to infer from); the other actions pick
    // a live proposal, and its kind comes from the on-chain transaction shape.
    let (command, kind, index) = if action_choice == CREATE {
        let Some(kind) = prompt_for_transaction_kind()? else {
            return Ok(());
        };
        (ProposalCommand::Propose, kind, None)
    } else {
        let command = match action_choice {
            "Approve" => ProposalCommand::Approve,
            "Reject" => ProposalCommand::Reject,
            "Execute" => ProposalCommand::Execute,
            _ => unreachable!(),
        };

        let (index, proposal_kind) = prompt_for_proposal_index(&rpc_client, &multisig, command)?;
        // Nothing could be established about an Unknown proposal, and the flow
        // below refuses it anyway - so say so here rather than walking the user
        // through choosing a type for a proposal that cannot be acted on.
        if proposal_kind.is_unverifiable() {
            return Err(unverifiable_proposal_error(index));
        }
        let kind = match proposal_kind.transaction_kind() {
            Some(kind) => kind,
            // Not a shape this tool creates; the user has to say how to route it.
            None => {
                Output::warning(
                    "Could not classify this proposal from its on-chain transaction; select its type:",
                );
                let Some(kind) = prompt_for_transaction_kind()? else {
                    return Ok(());
                };
                kind
            }
        };

        // Name the endpoint: the same governance address exists on several
        // clusters, so which one is being signed against is part of the decision.
        let confirmed = Confirm::new(&format!(
            "You're about to {} proposal #{} ({}) on feature gate {} via {} ({}). Continue?",
            action_choice.to_lowercase(),
            index,
            proposal_kind.label(),
            feature_gate_id,
            get_network_display(&rpc_url),
            rpc_url,
        ))
        .with_default(true)
        .prompt()?;
        if !confirmed {
            return Ok(());
        }

        (command, kind, Some(index))
    };

    // Prompt with the saved default pre-filled (editable), and pass the key
    // explicitly: interactive users always see which identity is voting.
    let voting_key = prompt_for_voting_key(config)?;

    // Same entry point as the CLI subcommands; the fee payer resolves from the
    // saved config default, prompting only when absent.
    proposal_command(
        &network_config,
        command,
        ProposalCommandArgs {
            multisig,
            kind,
            voting_key: Some(voting_key),
            keypair: None,
            index,
        },
    )
}

/// Ask which kind of transaction to work with. Returns None on cancel.
fn prompt_for_transaction_kind() -> Result<Option<TransactionKind>> {
    let options = vec![
        "Activate Feature Gate",
        "Revoke Feature Gate",
        "Rekey Multisig (this will brick the multisig)",
        "Cancel",
    ];
    let choice: &str = Select::new("Select transaction type:", options).prompt()?;
    Ok(match choice {
        "Activate Feature Gate" => Some(TransactionKind::Activate),
        "Revoke Feature Gate" => Some(TransactionKind::Revoke),
        "Rekey Multisig (this will brick the multisig)" => Some(TransactionKind::Rekey),
        _ => None,
    })
}

/// Whether `action` can still be performed on a proposal, given its status and
/// staleness. Voting (approve/reject) requires an Active proposal that is not
/// stale. Execution requires an Approved proposal; a stale but approved vault
/// transaction can still execute, while a stale config transaction cannot.
pub(crate) fn is_actionable(
    action: ProposalCommand,
    status: &ProposalStatus,
    kind: ProposalKind,
    index: u64,
    stale_index: u64,
) -> bool {
    match action {
        ProposalCommand::Approve | ProposalCommand::Reject => {
            matches!(status, ProposalStatus::Active { .. }) && index > stale_index
        }
        ProposalCommand::Execute => {
            matches!(status, ProposalStatus::Approved { .. })
                && (index > stale_index || !matches!(kind, ProposalKind::Rekey))
        }
        ProposalCommand::Propose => true,
    }
}

/// List the multisig's proposals that `action` can still act on - with what
/// they do, their status, and vote counts - and let the user pick one instead
/// of typing an index from memory. Executed, rejected, cancelled, and stale
/// proposals are skipped (with a note). Falls back to manual entry when
/// nothing is listable or the user prefers. Returns the chosen index and its
/// classified kind. Errors when the multisig cannot be read or has issued no
/// proposals: both leave nothing to bound a typed index with.
fn prompt_for_proposal_index(
    rpc_client: &RpcClient,
    multisig: &Pubkey,
    action: ProposalCommand,
) -> Result<(u64, ProposalKind)> {
    const MAX_LISTED: u64 = crate::constants::MAX_LISTED_PROPOSALS;

    // The multisig read is what bounds the index the user is about to act on.
    // Without it there is nothing to check a manually entered index against, so
    // an unreadable multisig - or one that has issued no proposals - ends the
    // action here instead of walking the user into an index that cannot exist.
    let ms = fetch_squads_multisig(rpc_client, multisig, "multisig").map_err(|e| {
        eyre::eyre!(
            "Could not read multisig {multisig}: {e} Its proposals cannot be listed, so there is \
             nothing to {} against. Retry, or read the multisig from a different RPC endpoint.",
            action_verb(action)
        )
    })?;
    if ms.transaction_index == 0 {
        return Err(eyre::eyre!(
            "Multisig {multisig} has no proposals yet, so there is nothing to {}.",
            action_verb(action)
        ));
    }

    let mut entries: Vec<(u64, ProposalKind)> = Vec::new();
    let mut options: Vec<String> = Vec::new();
    let mut skipped = 0u64;
    let first = ms.transaction_index.saturating_sub(MAX_LISTED - 1).max(1);
    if first > 1 {
        Output::info(&format!(
            "Showing the last {MAX_LISTED} proposals; older ones (#1-#{}) via manual entry.",
            first - 1
        ));
    }
    for index in first..=ms.transaction_index {
        // Authenticated: the status below decides whether this proposal
        // is offered at all, so an unauthenticated record could hide a
        // live one or invent a vote count next to a trustworthy label.
        let proposal = match fetch_proposal(rpc_client, multisig, index) {
            Ok(proposal) => proposal,
            Err(e) => {
                let msg = e.to_string();
                // Missing accounts are normal (closed/reclaimed); only a
                // real fetch failure deserves a warning, so the list is
                // never silently incomplete.
                if !msg.contains("AccountNotFound") && !msg.contains("could not find account") {
                    Output::warning(&format!("Could not fetch proposal #{index}: {e}"));
                }
                continue;
            }
        };
        let kind = describe_transaction(rpc_client, multisig, index);
        if !is_actionable(
            action,
            &proposal.status,
            kind,
            index,
            ms.stale_transaction_index,
        ) {
            skipped += 1;
            continue;
        }
        entries.push((index, kind));
        options.push(format!(
            "#{index} - {} - {} - {} approval(s), {} rejection(s)",
            kind.label(),
            proposal_status_label(&proposal.status),
            proposal.approved.len(),
            proposal.rejected.len(),
        ));
    }

    if skipped > 0 {
        Output::info(&format!(
            "Skipped {skipped} proposal(s) this action can no longer apply to (executed/rejected/cancelled/stale)."
        ));
    }

    if !options.is_empty() {
        options.push("Enter an index manually".to_string());
        let selection = Select::new("Select a proposal:", options).raw_prompt()?;
        if selection.index < entries.len() {
            return Ok(entries[selection.index]);
        }
    } else {
        Output::info("No proposals are currently actionable for this action.");
    }

    let index_str = Text::new("Enter the proposal index:").prompt()?;
    let index: u64 = index_str
        .parse()
        .map_err(|_| eyre::eyre!("Invalid proposal index"))?;
    validate_manual_index(index, ms.transaction_index)?;
    Ok((index, describe_transaction(rpc_client, multisig, index)))
}

/// What `action` does, for messages that have to say what cannot be done.
fn action_verb(action: ProposalCommand) -> &'static str {
    match action {
        ProposalCommand::Propose => "propose",
        ProposalCommand::Approve => "approve",
        ProposalCommand::Reject => "reject",
        ProposalCommand::Execute => "execute",
    }
}

/// A typed index only means something inside the range the multisig has issued.
fn validate_manual_index(index: u64, known_max: u64) -> Result<()> {
    if index == 0 || index > known_max {
        return Err(eyre::eyre!(
            "Proposal index must be between 1 and {known_max} for this multisig"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manually entered index used to be accepted unchecked whenever the
    /// multisig could not be read; the range now always comes from a live read.
    #[test]
    fn manual_index_must_be_within_the_issued_range() {
        validate_manual_index(1, 3).unwrap();
        validate_manual_index(3, 3).unwrap();

        for index in [0, 4, u64::MAX] {
            let err = validate_manual_index(index, 3).unwrap_err().to_string();
            assert!(err.contains("between 1 and 3"), "got: {err}");
        }
    }

    #[test]
    fn action_verbs_name_the_action() {
        assert_eq!(action_verb(ProposalCommand::Approve), "approve");
        assert_eq!(action_verb(ProposalCommand::Reject), "reject");
        assert_eq!(action_verb(ProposalCommand::Execute), "execute");
        assert_eq!(action_verb(ProposalCommand::Propose), "propose");
    }

    #[test]
    fn actionability_matrix() {
        let active = ProposalStatus::Active { timestamp: 0 };
        let approved = ProposalStatus::Approved { timestamp: 0 };
        let executed = ProposalStatus::Executed { timestamp: 0 };
        let rejected = ProposalStatus::Rejected { timestamp: 0 };
        let cancelled = ProposalStatus::Cancelled { timestamp: 0 };

        // Voting works only on Active, non-stale proposals.
        for action in [ProposalCommand::Approve, ProposalCommand::Reject] {
            assert!(is_actionable(action, &active, ProposalKind::Activate, 5, 2));
            // stale (index <= stale_index)
            assert!(!is_actionable(
                action,
                &active,
                ProposalKind::Activate,
                2,
                2
            ));
            for status in [&approved, &executed, &rejected, &cancelled] {
                assert!(!is_actionable(action, status, ProposalKind::Activate, 5, 2));
            }
        }

        // Execute requires Approved; terminal states are out.
        assert!(is_actionable(
            ProposalCommand::Execute,
            &approved,
            ProposalKind::Activate,
            5,
            2
        ));
        for status in [&active, &executed, &rejected, &cancelled] {
            assert!(!is_actionable(
                ProposalCommand::Execute,
                status,
                ProposalKind::Activate,
                5,
                2
            ));
        }

        // Stale exception: an approved vault transaction can still execute,
        // but a stale config (rekey) transaction cannot.
        assert!(is_actionable(
            ProposalCommand::Execute,
            &approved,
            ProposalKind::Revoke,
            2,
            2
        ));
        assert!(!is_actionable(
            ProposalCommand::Execute,
            &approved,
            ProposalKind::Rekey,
            2,
            2
        ));
    }
}
