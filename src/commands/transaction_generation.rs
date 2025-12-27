use eyre::Result;
use solana_clap_v3_utils::keypair::signer_from_path;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

use crate::squads::{get_vault_pda, Multisig as SquadsMultisig, TransactionMessage};
use crate::{
    output,
    provision::{
        create_child_create_config_transaction_and_proposal_message,
        create_child_execute_config_transaction_message, create_child_execute_transaction_message,
        create_common_activation_transaction_message, create_common_reject_transaction_message,
        create_execute_config_transaction_message, create_execute_transaction_message,
        create_parent_approve_proposal_message, create_rpc_client,
        create_transaction_and_proposal_message, get_proposal_status_and_threshold,
    },
    utils::{
        choose_network_from_config, create_child_vote_approve_transaction_message,
        create_child_vote_reject_transaction_message, Config,
    },
};
use borsh::BorshDeserialize;
use inquire::Confirm;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionKind {
    Activate,
    Revoke,
    Rekey,
}

#[derive(Debug, Clone, Copy)]
pub enum ProposalAction {
    Approve,
    Reject,
    Execute,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildTransactionFlavor {
    Vault,
    Config,
}

#[derive(Debug, Clone, Copy)]
enum ProposalFlavor {
    Vault(TransactionKind),
    Config,
}

#[derive(Clone)]
enum ParentFlowPayload {
    None,
    Execute(Vec<solana_instruction::AccountMeta>),
    Create(TransactionMessage),
}

impl TransactionKind {
    pub fn label(&self) -> &'static str {
        match self {
            TransactionKind::Activate => "Feature Gate Activate",
            TransactionKind::Revoke => "Feature Gate Revoke",
            TransactionKind::Rekey => "Rekey Multisig",
        }
    }
}

/// Build config actions for multisig configuration operations.
/// Returns a vector of ConfigActions appropriate for the transaction kind.
fn build_config_actions_for_kind(
    kind: TransactionKind,
    multisig_members: &[crate::squads::Member],
) -> Result<Vec<crate::squads::ConfigAction>> {
    match kind {
        TransactionKind::Rekey => {
            let mut actions = Vec::new();

            // Add dummy PDA member first (Pubkey::default() cannot sign)
            // This ensures we always have at least 1 member before changing threshold
            // Add a dummy member with full permissions. This satisfies multisig invariants
            // (requires at least one proposer/voter/executor) while remaining practically
            // unusable because the dummy Pubkey::default() cannot sign.
            actions.push(crate::squads::ConfigAction::AddMember {
                new_member: crate::squads::Member {
                    key: Pubkey::default(),
                    permissions: crate::squads::Permissions {
                        mask: (crate::squads::Permission::Initiate as u8)
                            | (crate::squads::Permission::Vote as u8)
                            | (crate::squads::Permission::Execute as u8),
                    },
                },
            });

            // Set threshold to 1 (only the dummy member will remain)
            // Safe because we just added the dummy member
            actions.push(crate::squads::ConfigAction::ChangeThreshold { new_threshold: 1 });

            // Remove all current members last (after adding dummy and setting threshold)
            for member in multisig_members {
                actions.push(crate::squads::ConfigAction::RemoveMember {
                    old_member: member.key,
                });
            }

            Ok(actions)
        }
        // Other transaction kinds (Activate, Revoke) use vault transactions, not config transactions
        TransactionKind::Activate | TransactionKind::Revoke => Err(eyre::eyre!(
            "build_config_actions_for_kind called with non-config TransactionKind"
        )),
    }
}

/// Attempt to load an account as a Squads multisig; returns Ok(None) if not found or not deserializable.
fn load_multisig_if_any(
    rpc_client: &solana_client::rpc_client::RpcClient,
    key: &Pubkey,
) -> Result<Option<SquadsMultisig>> {
    let acc = match rpc_client.get_account(key) {
        Ok(acc) => acc,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("AccountNotFound") || msg.contains("could not find account") {
                return Ok(None);
            }
            return Err(eyre::eyre!("Failed to fetch account {}: {}", key, e));
        }
    };

    if acc.data.len() < 8 {
        return Ok(None);
    }

    match SquadsMultisig::deserialize(&mut &acc.data[8..]) {
        Ok(ms) => Ok(Some(ms)),
        Err(_) => Ok(None),
    }
}

/// Common flow for creating and optionally executing a parent multisig proposal
/// that operates on a child multisig.
///
/// This handles:
/// - Validating parent vault PDA has required permissions on child
/// - Creating parent transaction+proposal
/// - Optionally approving the parent proposal
/// - Optionally executing the parent proposal (if threshold met)
async fn handle_parent_multisig_flow(
    program_id: &Pubkey,
    parent_multisig: Pubkey,
    feature_gate_multisig_address: Pubkey,
    proposal_index: u64,
    kind: TransactionKind,
    child_flavor: ChildTransactionFlavor,
    fee_payer_signer: &Box<dyn Signer>,
    rpc_url: &str,
    operation: ProposalAction,
    payload: ParentFlowPayload,
) -> Result<()> {
    let rpc_client = create_rpc_client(rpc_url);

    // Fetch parent's next transaction index
    let parent_acc = rpc_client
        .get_account(&parent_multisig)
        .map_err(|e| eyre::eyre!("Failed to fetch parent multisig account: {}", e))?;
    let parent_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &parent_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize parent multisig: {}", e))?;
    let parent_next_index = parent_ms.transaction_index + 1;

    // The fee payer must be a member of the parent multisig with Initiate permission to create proposals
    let fee_payer_member = parent_ms
        .members
        .iter()
        .find(|m| m.key == fee_payer_signer.pubkey());
    if fee_payer_member.is_none() {
        output::Output::error(
            "Fee payer must be a member of the parent multisig to create/approve/execute proposals.",
        );
        output::Output::hint(&format!(
            "Current fee payer: {}\nParent multisig: {}\nAdd the fee payer as a member (with Initiate permission) or choose a fee payer that is already a member with Initiate.",
            fee_payer_signer.pubkey(), parent_multisig,
        ));
        return Err(eyre::eyre!(
            "Fee payer is not a member of the parent multisig"
        ));
    }

    let fee_payer_has_initiate = fee_payer_member
        .map(|m| (m.permissions.mask & (1 << 0)) != 0)
        .unwrap_or(false);
    if !fee_payer_has_initiate {
        output::Output::error("Fee payer lacks Initiate permission on the parent multisig.");
        return Err(eyre::eyre!(
            "Fee payer missing Initiate permission on parent multisig"
        ));
    }

    // Prefer using the parent vault PDA as the child member
    let parent_vault_member = get_vault_pda(&parent_multisig, 0, None).0;

    // Validate the child multisig includes the parent vault PDA with required permission
    let child_acc = rpc_client
        .get_account(&feature_gate_multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch child multisig: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize child multisig: {}", e))?;

    // Check required permission based on operation type
    let (required_permission_mask, permission_name, action_description) = match &operation {
        ProposalAction::Approve => (
            1 << 1, // Vote permission
            "Vote",
            format!("Approve {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Reject => (
            1 << 1, // Vote permission
            "Vote",
            format!("Reject {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Execute => (
            1 << 2, // Execute permission
            "Execute",
            format!("Execute {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Create => (
            (1 << 0) | (1 << 1), // Initiate + Vote required on child for creation
            "Initiate+Vote",
            format!(
                "Create {} proposal at index {}",
                kind.label(),
                proposal_index
            ),
        ),
    };

    let action_description = action_description.as_str();

    let parent_vault_has_permission = child_ms.members.iter().any(|m| {
        m.key == parent_vault_member
            && (m.permissions.mask & required_permission_mask) == required_permission_mask
    });

    if !parent_vault_has_permission {
        let parent_multisig_is_member = child_ms.members.iter().any(|m| m.key == parent_multisig);
        if parent_multisig_is_member {
            output::Output::error(&format!(
                "Child multisig has the parent multisig address as a member, but not the parent vault PDA. The parent program cannot sign as the multisig address during CPI."
            ));
            output::Output::hint(&format!(
                "Please add the parent vault PDA as a member with {} permission on the child: {}",
                permission_name, parent_vault_member
            ));
        } else {
            output::Output::error(&format!(
                "Child multisig is missing the parent vault PDA as a member with {} permission.",
                permission_name
            ));
            output::Output::hint(&format!(
                "Add this key as a member with {}: {}",
                permission_name, parent_vault_member
            ));
        }
        return Err(eyre::eyre!(
            "Child multisig missing required member for programmatic {}",
            permission_name.to_lowercase()
        ));
    }

    // Display information about the parent multisig transaction
    output::Output::header(&format!(
        "Parent Multisig {} Transaction Details:",
        permission_name
    ));
    output::Output::field("Parent Multisig:", &parent_multisig.to_string());
    output::Output::field(
        "Child Multisig:",
        &feature_gate_multisig_address.to_string(),
    );
    output::Output::field("Parent Transaction Index:", &parent_next_index.to_string());
    output::Output::field("Child Proposal Index:", &proposal_index.to_string());
    output::Output::field("Transaction Type:", kind.label());
    output::Output::field("Action:", action_description);

    // Ask for confirmation before creating the parent multisig proposal
    let confirmation_prompt = match &operation {
        ProposalAction::Approve => "Create parent multisig proposal for this transaction?",
        ProposalAction::Reject => "Create parent multisig proposal to reject this transaction?",
        ProposalAction::Execute => "Create parent multisig proposal to execute child transaction?",
        ProposalAction::Create => {
            "Create parent multisig proposal to create a new child transaction/proposal?"
        }
    };

    // Non-interactive mode for E2E tests - auto-confirm
    if std::env::var("E2E_TEST_MODE").is_err() {
        if !Confirm::new(confirmation_prompt)
            .with_default(true)
            .prompt()
            .unwrap_or(false)
        {
            output::Output::info("Parent multisig proposal creation cancelled.");
            return Ok(());
        }
    }

    // Create the transaction message based on operation type
    let tx_message = match (operation, child_flavor, payload) {
        (ProposalAction::Approve, _, ParentFlowPayload::None) => {
            create_child_vote_approve_transaction_message(
                feature_gate_multisig_address,
                proposal_index,
                parent_vault_member,
            )
        }
        (ProposalAction::Reject, _, ParentFlowPayload::None) => {
            create_child_vote_reject_transaction_message(
                feature_gate_multisig_address,
                proposal_index,
                parent_vault_member,
            )
        }
        (
            ProposalAction::Execute,
            ChildTransactionFlavor::Vault,
            ParentFlowPayload::Execute(exec),
        ) => create_child_execute_transaction_message(
            feature_gate_multisig_address,
            proposal_index,
            parent_vault_member,
            exec,
        ),
        (ProposalAction::Execute, ChildTransactionFlavor::Config, ParentFlowPayload::None) => {
            create_child_execute_config_transaction_message(
                feature_gate_multisig_address,
                proposal_index,
                parent_vault_member,
            )
        }
        (ProposalAction::Create, ChildTransactionFlavor::Vault, ParentFlowPayload::Create(msg)) => {
            crate::provision::create_child_create_vault_transaction_and_proposal_message(
                feature_gate_multisig_address,
                proposal_index,
                parent_vault_member,
                fee_payer_signer.pubkey(),
                msg,
            )
        }
        (ProposalAction::Create, _, ParentFlowPayload::Create(msg)) => msg,
        (ProposalAction::Execute, ChildTransactionFlavor::Vault, _) => {
            return Err(eyre::eyre!(
                "Execution accounts required for Execute operation"
            ))
        }
        (ProposalAction::Create, _, _) => {
            return Err(eyre::eyre!(
                "Creation message required for Create operation"
            ))
        }
        _ => {
            return Err(eyre::eyre!(
                "Invalid parent flow payload for requested operation"
            ))
        }
    };

    let blockhash = rpc_client.get_latest_blockhash()?;
    let (msg, tx_pda, prop_pda) = create_transaction_and_proposal_message(
        None,
        &fee_payer_signer.pubkey(),
        &fee_payer_signer.pubkey(),
        &parent_multisig,
        parent_next_index,
        0,
        tx_message,
        Some(crate::constants::DEFAULT_PRIORITY_FEE as u32),
        Some(crate::constants::DEFAULT_COMPUTE_UNITS),
        blockhash,
    )?;
    output::Output::address("Parent transaction PDA:", &tx_pda.to_string());
    output::Output::address("Parent proposal PDA:", &prop_pda.to_string());

    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(msg), &[fee_payer_signer.as_ref()])?;
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send parent transaction: {}", e))?;

    output::Output::header(&format!(
        "Parent Multisig {} Transaction Created & Sent:",
        permission_name
    ));
    output::Output::field("Signature:", &signature);

    // Offer to approve the parent proposal immediately
    // In E2E test mode, auto-approve
    let should_approve = std::env::var("E2E_TEST_MODE").is_ok()
        || Confirm::new("Approve this parent proposal now?")
            .with_default(true)
            .prompt()
            .unwrap_or(false);

    if should_approve {
        let parent_proposal_index = parent_next_index;
        let approve_msg = create_parent_approve_proposal_message(
            program_id,
            &parent_multisig,
            &fee_payer_signer.pubkey(),
            &fee_payer_signer.pubkey(),
            parent_proposal_index,
            blockhash,
        )?;
        let approve_tx = VersionedTransaction::try_new(
            VersionedMessage::V0(approve_msg),
            &[fee_payer_signer.as_ref()],
        )?;
        let approve_sig = crate::provision::send_and_confirm_transaction(&approve_tx, &rpc_client)
            .map_err(|e| eyre::eyre!("Failed to approve parent proposal: {}", e))?;
        output::Output::field("Parent proposal approved (sig):", &approve_sig);

        // If approvals meet threshold, offer to execute the parent proposal now
        let (approved, threshold, _status) = get_proposal_status_and_threshold(
            program_id,
            &parent_multisig,
            parent_proposal_index,
            &rpc_client,
        )?;
        let is_fee_payer_member = parent_ms
            .members
            .iter()
            .any(|m| m.key == fee_payer_signer.pubkey());
        let has_execute_permission = parent_ms
            .members
            .iter()
            .find(|m| m.key == fee_payer_signer.pubkey())
            .map(|m| (m.permissions.mask & (1 << 2)) != 0)
            .unwrap_or(false);

        if approved as u16 >= threshold && is_fee_payer_member && has_execute_permission {
            // Auto-execute in E2E test mode
            let should_execute = std::env::var("E2E_TEST_MODE").is_ok()
                || Confirm::new("Execute this parent proposal now?")
                    .with_default(true)
                    .prompt()
                    .unwrap_or(false);

            if should_execute {
                let fresh_blockhash = rpc_client.get_latest_blockhash()?;
                let exec_msg = create_execute_transaction_message(
                    program_id,
                    &parent_multisig,
                    &fee_payer_signer.pubkey(),
                    &fee_payer_signer.pubkey(),
                    parent_proposal_index,
                    &rpc_client,
                    fresh_blockhash,
                )?;
                let exec_tx = VersionedTransaction::try_new(
                    VersionedMessage::V0(exec_msg),
                    &[fee_payer_signer.as_ref()],
                )?;
                let exec_sig =
                    crate::provision::send_and_confirm_transaction(&exec_tx, &rpc_client)
                        .map_err(|e| eyre::eyre!("Failed to execute parent proposal: {}", e))?;
                output::Output::field("Parent proposal executed (sig):", &exec_sig);

                // Display success message based on operation type
                match operation {
                    ProposalAction::Approve => {
                        output::Output::success(
                            "Child proposal has been approved via parent multisig!",
                        );
                    }
                    ProposalAction::Reject => {
                        output::Output::success(
                            "Child proposal has been rejected via parent multisig!",
                        );
                    }
                    ProposalAction::Execute => {
                        output::Output::success(
                            "Child transaction has been executed via parent multisig!",
                        );
                    }
                    ProposalAction::Create => {
                        output::Output::success(
                            "Child proposal has been created via parent multisig!",
                        );
                    }
                }
            }
        } else if !is_fee_payer_member {
            output::Output::hint(
                "Fee payer is not a member of the parent multisig; cannot auto-execute.",
            );
        } else if !has_execute_permission {
            output::Output::hint(
                "Executor does not have Execute permission on the parent multisig.",
            );
        } else {
            output::Output::hint(&format!(
                "Parent approvals {}/{} — waiting for more confirmations before execution.",
                approved, threshold
            ));
        }
    }
    Ok(())
}

pub async fn approve_common_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    proposal_index: u64,
    kind: TransactionKind,
) -> Result<()> {
    approve_common_proposal(
        config,
        feature_gate_multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        proposal_index,
        ProposalFlavor::Vault(kind),
    )
    .await
}

pub async fn reject_common_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    proposal_index: u64,
    kind: TransactionKind,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);
    let blockhash = rpc_client.get_latest_blockhash()?;

    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    if is_parent_multisig {
        // Use Config flavor for Rekey, Vault flavor for Activate/Revoke
        let child_flavor = if kind == TransactionKind::Rekey {
            ChildTransactionFlavor::Config
        } else {
            ChildTransactionFlavor::Vault
        };

        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            proposal_index,
            kind,
            child_flavor,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Reject,
            ParentFlowPayload::None,
        )
        .await;
    }

    let transaction_message = create_common_reject_transaction_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        blockhash,
        proposal_index,
    )
    .map_err(|e| {
        eyre::eyre!(
            "Failed to create reject {} transaction message: {}",
            kind.label(),
            e
        )
    })?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(transaction_message),
        &[fee_payer_signer.as_ref()],
    )?;

    let should_send = if std::env::var("E2E_TEST_MODE").is_ok() {
        true
    } else {
        Confirm::new("Send this reject transaction now?")
            .with_default(true)
            .prompt()
            .unwrap_or(false)
    };
    if !should_send {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send reject transaction: {}", e))?;
    output::Output::field("Reject transaction sent successfully:", &signature);
    Ok(())
}

pub async fn execute_common_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    proposal_index: u64,
    kind: TransactionKind,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer = signer_from_path(
        &Default::default(), // matches
        &fee_payer_path,
        "fee payer",
        &mut None, // wallet_manager
    )
    .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);

    // Readiness check: ensure approvals >= threshold on child proposal
    let (approved, threshold, _status) = get_proposal_status_and_threshold(
        &program_id,
        &feature_gate_multisig_address,
        proposal_index,
        &rpc_client,
    )?;
    if (approved as u16) < threshold {
        output::Output::hint(&format!(
            "Proposal at index {} not ready to execute yet: approvals {}/{}",
            proposal_index, approved, threshold
        ));
        return Err(eyre::eyre!("Insufficient approvals to execute"));
    }

    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    if is_parent_multisig {
        // If this is a config transaction (Rekey), use the config execute path without extra metas.
        if kind == TransactionKind::Rekey {
            return handle_parent_multisig_flow(
                &program_id,
                voting_key,
                feature_gate_multisig_address,
                proposal_index,
                TransactionKind::Rekey,
                ChildTransactionFlavor::Config,
                &fee_payer_signer,
                &rpc_url,
                ProposalAction::Execute,
                ParentFlowPayload::None,
            )
            .await;
        }

        // Vault transaction execute path (Activate/Revoke)
        use crate::squads::{get_transaction_pda, VaultTransaction};
        let (child_transaction_pda, _) = get_transaction_pda(
            &feature_gate_multisig_address,
            proposal_index,
            Some(&program_id),
        );
        let child_transaction_account_data = rpc_client
            .get_account_data(&child_transaction_pda)
            .map_err(|e| eyre::eyre!("Failed to fetch child transaction account: {}", e))?;
        let child_transaction_contents =
            VaultTransaction::try_from_slice(&child_transaction_account_data[8..])
                .map_err(|e| eyre::eyre!("Failed to deserialize child transaction: {}", e))?;
        let child_transaction_message = child_transaction_contents.message;

        // Build execution account metas from the child transaction
        let mut child_execution_account_metas = Vec::new();
        for (i, account_key) in child_transaction_message.account_keys.iter().enumerate() {
            // Preserve writability but do NOT mark any of the child execution
            // accounts as signers. The Squads program will derive the required
            // signer PDA(s) from the stored transaction message, and marking
            // them as signers in the outer Execute instruction confuses the
            // account grouping (leading to InvalidAccount during CPI).
            let is_signer = false;
            let is_writable = child_transaction_message.is_static_writable_index(i);
            if is_writable {
                child_execution_account_metas.push(solana_instruction::AccountMeta::new(
                    *account_key,
                    is_signer,
                ));
            } else {
                child_execution_account_metas.push(solana_instruction::AccountMeta::new_readonly(
                    *account_key,
                    is_signer,
                ));
            }
        }

        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            proposal_index,
            kind,
            ChildTransactionFlavor::Vault,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Execute,
            ParentFlowPayload::Execute(child_execution_account_metas),
        )
        .await;
    }

    // Permission check: voting_key must be a member with Execute permission on the child multisig
    let child_acc = rpc_client
        .get_account(&feature_gate_multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig account: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;
    let is_member = child_ms.members.iter().any(|m| m.key == voting_key);
    let has_execute = child_ms
        .members
        .iter()
        .find(|m| m.key == voting_key)
        .map(|m| (m.permissions.mask & (1 << 2)) != 0)
        .unwrap_or(false);
    if !is_member {
        output::Output::error("Executor key is not a member of the multisig.");
        return Err(eyre::eyre!("Executor must be a multisig member"));
    }
    if !has_execute {
        output::Output::error("Executor key does not have Execute permission.");
        return Err(eyre::eyre!("Missing Execute permission for executor"));
    }

    // Fresh blockhash and build execute message for the proposal
    let blockhash = rpc_client.get_latest_blockhash()?;
    let exec_msg = create_execute_transaction_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        proposal_index,
        &rpc_client,
        blockhash,
    )?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(exec_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    // Confirm before sending on-chain (EOA execute path)
    let should_send = Confirm::new("Send this execute transaction now?")
        .with_default(true)
        .prompt()
        .unwrap_or(false);
    if !should_send {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    // Send and confirm
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to execute proposal: {}", e))?;
    output::Output::field("Proposal executed (sig):", &signature);
    Ok(())
}

pub async fn create_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    kind: TransactionKind,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);

    // Fetch the feature gate multisig to get transaction index
    let feature_gate_acc = rpc_client
        .get_account(&feature_gate_multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch feature gate multisig: {}", e))?;

    let feature_gate_ms: SquadsMultisig =
        BorshDeserialize::deserialize(&mut &feature_gate_acc.data[8..])
            .map_err(|e| eyre::eyre!("Failed to deserialize feature gate multisig: {}", e))?;

    let next_tx_index = feature_gate_ms.transaction_index + 1;

    // Feature ID is the child vault address (vault 0)
    let feature_id = get_vault_pda(&feature_gate_multisig_address, 0, None).0;

    // Detect if voting_key is itself a Squads multisig (parent)
    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    output::Output::header(&format!("🎯 Create {} Proposal", kind.label()));
    output::Output::field("Feature ID", &feature_id.to_string());
    output::Output::field("Multisig", &feature_gate_multisig_address.to_string());
    output::Output::field("Next Vault Transaction Index", &next_tx_index.to_string());
    output::Output::field("Next Config Transaction Index", &(next_tx_index + 1).to_string());

    // Determine config action based on kind
    let (config_actions, config_memo) = match kind {
        TransactionKind::Activate => (
            vec![crate::squads::ConfigAction::ChangeThreshold { new_threshold: 1 }],
            Some("Lower threshold to 1 for safe revocation".to_string()),
        ),
        TransactionKind::Revoke => (
            vec![crate::squads::ConfigAction::ChangeThreshold {
                new_threshold: feature_gate_ms.threshold,
            }],
            Some(format!("Restore threshold to {}", feature_gate_ms.threshold)),
        ),
        _ => return Err(eyre::eyre!("Unsupported kind for feature gate proposal")),
    };

    if is_parent_multisig {
        output::Output::info("Parent multisig detected - creating bundled proposals (vault + config)");

        let vault_tx_message =
            crate::provision::create_feature_gate_transaction_message(feature_id, feature_id, kind);

        let config_index = next_tx_index + 1;

        // Build paired proposals message (4 instructions in ONE parent tx)
        // Note: Memo is set to None to reduce transaction size for parent multisig flows
        let paired_message = crate::provision::create_child_create_paired_proposals_message(
            feature_gate_multisig_address,
            next_tx_index,
            config_index,
            voting_key, // parent vault PDA
            fee_payer_signer.pubkey(),
            vault_tx_message,
            config_actions,
            None, // No memo to save transaction size (~64 bytes)
        );

        handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            next_tx_index, // Parent proposal relates to first child proposal
            kind,
            ChildTransactionFlavor::Vault, // Primary flavor
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Create,
            ParentFlowPayload::Create(paired_message),
        )
        .await?;

        output::Output::field("Vault proposal index:", &next_tx_index.to_string());
        output::Output::field("Config proposal index:", &config_index.to_string());
        output::Output::info("Both proposals created in a single parent transaction");

        return Ok(());
    }

    // EOA voting path - create paired proposals (vault + config)
    output::Output::info(&format!("Creating paired {} proposals (vault + config)...", kind.label()));

    // Verify voting_key has Initiate permission
    let is_member = feature_gate_ms.members.iter().any(|m| m.key == voting_key);
    let has_initiate = feature_gate_ms
        .members
        .iter()
        .find(|m| m.key == voting_key)
        .map(|m| (m.permissions.mask & (1 << 0)) != 0)
        .unwrap_or(false);

    if !is_member {
        output::Output::error("Creator key is not a member of the multisig.");
        return Err(eyre::eyre!("Creator must be a multisig member"));
    }
    if !has_initiate {
        output::Output::error("Creator key does not have Initiate permission.");
        return Err(eyre::eyre!("Missing Initiate permission for creator"));
    }

    // Verify voting_key is the same as fee_payer in EOA mode
    if voting_key != fee_payer_signer.pubkey() {
        return Err(eyre::eyre!(
            "In EOA mode, voting_key must match fee_payer. Got voting_key={}, fee_payer={}",
            voting_key,
            fee_payer_signer.pubkey()
        ));
    }

    let vault_message =
        crate::provision::create_feature_gate_transaction_message(feature_id, feature_id, kind);

    // Create BOTH proposals in ONE transaction using bundled creation
    let config_index = next_tx_index + 1;

    // In EOA mode, voting_key == fee_payer, so we can use fee_payer_signer as contributor
    crate::utils::create_and_send_paired_proposals(
        &rpc_url,
        &fee_payer_signer,
        fee_payer_signer.as_ref(),
        &feature_gate_multisig_address,
        next_tx_index,   // Vault proposal index
        config_index,    // Config proposal index
        vault_message,
        config_actions.clone(),
        config_memo.clone(),
    ).await?;

    output::Output::field("Vault proposal index:", &next_tx_index.to_string());
    output::Output::field("Config proposal index:", &config_index.to_string());
    output::Output::info("Both proposals created in a single transaction");

    output::Output::info(
        "Next step: Gather approvals from other members, then execute the proposals.",
    );
    Ok(())
}

pub async fn rekey_multisig_feature_gate(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);

    // Fetch the feature gate multisig to get its members
    let feature_gate_acc = rpc_client
        .get_account(&feature_gate_multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch feature gate multisig: {}", e))?;

    let feature_gate_ms: SquadsMultisig =
        BorshDeserialize::deserialize(&mut &feature_gate_acc.data[8..])
            .map_err(|e| eyre::eyre!("Failed to deserialize feature gate multisig: {}", e))?;

    // Build config actions for rekey
    let actions = build_config_actions_for_kind(TransactionKind::Rekey, &feature_gate_ms.members)?;

    output::Output::header("🔑 Rekey Multisig - Config Actions");
    output::Output::field("Actions count", &actions.len().to_string());
    for (i, action) in actions.iter().enumerate() {
        match action {
            crate::squads::ConfigAction::RemoveMember { old_member } => {
                output::Output::numbered_field(i + 1, "Remove Member", &old_member.to_string());
            }
            crate::squads::ConfigAction::AddMember { new_member } => {
                output::Output::numbered_field(
                    i + 1,
                    "Add Member (Dummy)",
                    &new_member.key.to_string(),
                );
            }
            crate::squads::ConfigAction::ChangeThreshold { new_threshold } => {
                output::Output::numbered_field(i + 1, "Set Threshold", &new_threshold.to_string());
            }
        }
    }

    // Final confirmation
    if std::env::var("E2E_TEST_MODE").is_err() {
        let confirm =
            Confirm::new("This will permanently disable voting on this multisig. Are you sure?")
                .with_default(false)
                .prompt()?;

        if !confirm {
            output::Output::hint("Rekey cancelled.");
            return Ok(());
        }
    }

    // Fetch next transaction index (child)
    let next_tx_index = feature_gate_ms.transaction_index + 1;

    // Detect if voting_key is itself a Squads multisig (parent)
    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    if is_parent_multisig {
        output::Output::info("Parent multisig voting detected - creating parent proposal on child");
        let parent_vault_member = get_vault_pda(&voting_key, 0, None).0;

        let child_tx_message = create_child_create_config_transaction_and_proposal_message(
            feature_gate_multisig_address,
            next_tx_index,
            parent_vault_member,
            fee_payer_signer.pubkey(),
            actions.clone(),
            Some("Rekey multisig - disable voting".to_string()),
        );

        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            next_tx_index,
            TransactionKind::Rekey,
            ChildTransactionFlavor::Config,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Create,
            ParentFlowPayload::Create(child_tx_message),
        )
        .await;
    }

    // EOA voting path - create config transaction and proposal
    output::Output::info("Creating config transaction for rekey...");

    // Get transaction & proposal PDAs
    let (tx_pda, _) = crate::squads::get_transaction_pda(
        &feature_gate_multisig_address,
        next_tx_index,
        Some(&program_id),
    );
    let (proposal_pda, _) = crate::squads::get_proposal_pda(
        &feature_gate_multisig_address,
        next_tx_index,
        Some(&program_id),
    );

    // Build create transaction instruction
    let create_tx_data = crate::squads::ConfigTransactionCreateData {
        args: crate::squads::ConfigTransactionCreateArgs {
            actions: actions.clone(),
            memo: Some("Rekey multisig - disable voting".to_string()),
        },
    };

    let create_tx_instruction = solana_instruction::Instruction::new_with_bytes(
        program_id,
        &create_tx_data.data(),
        vec![
            solana_instruction::AccountMeta::new(feature_gate_multisig_address, false),
            solana_instruction::AccountMeta::new(tx_pda, false),
            solana_instruction::AccountMeta::new_readonly(voting_key, true), // creator (signer)
            solana_instruction::AccountMeta::new(fee_payer_signer.pubkey(), true), // rent_payer (signer, mutable)
            solana_instruction::AccountMeta::new_readonly(
                Pubkey::from_str_const("11111111111111111111111111111111"),
                false,
            ), // system_program
        ],
    );

    // Build create proposal instruction paired with the config transaction
    let create_proposal_instruction = solana_instruction::Instruction::new_with_bytes(
        program_id,
        &crate::squads::MultisigCreateProposalData {
            args: crate::squads::MultisigCreateProposalArgs {
                transaction_index: next_tx_index,
                is_draft: false,
            },
        }
        .data(),
        crate::squads::MultisigCreateProposalAccounts {
            multisig: feature_gate_multisig_address,
            proposal: proposal_pda,
            creator: voting_key,
            rent_payer: fee_payer_signer.pubkey(),
            system_program: Pubkey::from_str_const("11111111111111111111111111111111"),
        }
        .to_account_metas(None),
    );

    // Confirm before sending
    let should_send = Confirm::new("Send rekey proposal now?")
        .with_default(true)
        .prompt()
        .unwrap_or(false);
    if !should_send {
        output::Output::hint("Skipped sending. You can rerun to send.");
        return Ok(());
    }

    // Get fresh blockhash right before sending
    let blockhash = rpc_client.get_latest_blockhash()?;

    // Verify voting_key is the same as fee_payer in EOA mode
    if voting_key != fee_payer_signer.pubkey() {
        return Err(eyre::eyre!(
            "In EOA mode, voting_key must match fee_payer. Got voting_key={}, fee_payer={}",
            voting_key,
            fee_payer_signer.pubkey()
        ));
    }

    // Build a v0 message for config rekey creation (tx + proposal)
    let v0_message = solana_message::v0::Message::try_compile(
        &fee_payer_signer.pubkey(),
        &[create_tx_instruction, create_proposal_instruction],
        &[],
        blockhash,
    )?;

    // In EOA mode, fee_payer IS the voting_key/creator - one signer covers both
    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(v0_message),
        &[fee_payer_signer.as_ref()],
    )?;

    // Send and confirm
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to create rekey proposal: {}", e))?;
    output::Output::field("Rekey proposal created (sig):", &signature);
    output::Output::field("Proposal index:", &next_tx_index.to_string());

    // Offer to approve the config proposal immediately
    if Confirm::new("Approve this config proposal now?")
        .with_default(true)
        .prompt()
        .unwrap_or(false)
    {
        approve_common_config_change(
            config,
            feature_gate_multisig_address,
            voting_key,
            fee_payer_path,
            Some(program_id),
            next_tx_index,
        )
        .await?;
    }

    output::Output::info(
        "Next step: Gather approvals from other members, then execute the config transaction.",
    );
    Ok(())
}

pub async fn approve_common_config_change(
    config: &Config,
    multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    transaction_index: u64,
) -> Result<()> {
    approve_common_proposal(
        config,
        multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        transaction_index,
        ProposalFlavor::Config,
    )
    .await
}

async fn approve_common_proposal(
    config: &Config,
    multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    proposal_index: u64,
    flavor: ProposalFlavor,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);
    let blockhash = rpc_client.get_latest_blockhash()?;

    // Decide flavor/kind for parent flow and labeling
    let (child_flavor, kind_for_label) = match flavor {
        ProposalFlavor::Vault(kind) => (ChildTransactionFlavor::Vault, kind),
        ProposalFlavor::Config => (ChildTransactionFlavor::Config, TransactionKind::Rekey),
    };

    // Detect if voting_key is itself a Squads multisig (parent)
    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    if is_parent_multisig {
        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            multisig_address,
            proposal_index,
            kind_for_label,
            child_flavor,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Approve,
            ParentFlowPayload::None,
        )
        .await;
    }

    // EOA voting path - approve proposal
    // 1) Validate voter membership and Vote permission on the child multisig
    let child_acc = rpc_client
        .get_account(&multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;
    let is_member = child_ms.members.iter().any(|m| m.key == voting_key);
    let has_vote = child_ms
        .members
        .iter()
        .find(|m| m.key == voting_key)
        .map(|m| (m.permissions.mask & (1 << 1)) != 0)
        .unwrap_or(false);
    if !is_member {
        output::Output::error("Approver key is not a member of the multisig.");
        return Err(eyre::eyre!("Approver must be a multisig member"));
    }
    if !has_vote {
        output::Output::error("Approver key does not have Vote permission.");
        return Err(eyre::eyre!("Missing Vote permission for approver"));
    }

    let approve_msg = create_common_activation_transaction_message(
        &program_id,
        &multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        blockhash,
        proposal_index,
    )
    .map_err(|e| {
        eyre::eyre!(
            "Failed to create approve {} transaction message: {}",
            kind_for_label.label(),
            e
        )
    })?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(approve_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    let should_send = if std::env::var("E2E_TEST_MODE").is_ok() {
        true
    } else {
        Confirm::new("Send this approve transaction now?")
            .with_default(true)
            .prompt()
            .unwrap_or(false)
    };
    if !should_send {
        output::Output::hint(
            "Skipped sending. You can submit the above encoded transaction manually or rerun to send.",
        );
        return Ok(());
    }

    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send approval transaction: {}", e))?;

    let success_label = match flavor {
        ProposalFlavor::Vault(_) => "Transaction sent successfully:",
        ProposalFlavor::Config => "Config change approved (sig):",
    };
    output::Output::field(success_label, &signature);
    Ok(())
}

pub async fn execute_common_config_change(
    config: &Config,
    multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    transaction_index: u64,
) -> Result<()> {
    let program_id = program_id
        .unwrap_or_else(|| Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"));

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    let rpc_url = choose_network_from_config(config)?;
    let rpc_client = create_rpc_client(&rpc_url);

    // Readiness check: ensure approvals >= threshold on config proposal
    let (approved, threshold, _status) = get_proposal_status_and_threshold(
        &program_id,
        &multisig_address,
        transaction_index,
        &rpc_client,
    )?;
    if (approved as u16) < threshold {
        output::Output::hint(&format!(
            "Config proposal at index {} not ready to execute yet: approvals {}/{}",
            transaction_index, approved, threshold
        ));
        return Err(eyre::eyre!("Insufficient approvals to execute"));
    }

    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    if is_parent_multisig {
        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            multisig_address,
            transaction_index,
            TransactionKind::Rekey,
            ChildTransactionFlavor::Config,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Execute,
            ParentFlowPayload::None,
        )
        .await;
    }

    // Permission check: voting_key must be a member with Execute permission on the multisig
    let multisig_acc = rpc_client
        .get_account(&multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig account: {}", e))?;
    let multisig: SquadsMultisig = BorshDeserialize::deserialize(&mut &multisig_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;
    let is_member = multisig.members.iter().any(|m| m.key == voting_key);
    let has_execute = multisig
        .members
        .iter()
        .find(|m| m.key == voting_key)
        .map(|m| (m.permissions.mask & (1 << 2)) != 0)
        .unwrap_or(false);
    if !is_member {
        output::Output::error("Executor key is not a member of the multisig.");
        return Err(eyre::eyre!("Executor must be a multisig member"));
    }
    if !has_execute {
        output::Output::error("Executor key does not have Execute permission.");
        return Err(eyre::eyre!("Missing Execute permission for executor"));
    }

    output::Output::header("Config Execute - Signer Details");
    output::Output::field("Fee payer", &fee_payer_signer.pubkey().to_string());
    output::Output::field("Voting key (member)", &voting_key.to_string());

    // Fresh blockhash and build execute message for the config transaction
    let blockhash = rpc_client.get_latest_blockhash()?;
    let (proposal_pda, _) =
        crate::squads::get_proposal_pda(&multisig_address, transaction_index, Some(&program_id));
    let exec_msg = create_execute_config_transaction_message(
        &program_id,
        &multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        Some(fee_payer_signer.pubkey()),
        transaction_index,
        blockhash,
    )?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(exec_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    // Confirm before sending on-chain (EOA execute path)
    let should_send = if std::env::var("E2E_TEST_MODE").is_ok() {
        true
    } else {
        Confirm::new("Send this execute transaction now?")
            .with_default(true)
            .prompt()
            .unwrap_or(false)
    };
    if !should_send {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    // Send and confirm
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to execute config change: {}", e))?;
    output::Output::field("Config change executed (sig):", &signature);
    Ok(())
}
