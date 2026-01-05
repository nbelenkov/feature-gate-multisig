use eyre::Result;
use solana_clap_v3_utils::keypair::signer_from_path;
use solana_client::rpc_client::RpcClient;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::squads::{
    get_vault_pda, Multisig as SquadsMultisig, TransactionMessage,
    PERMISSION_EXECUTE, PERMISSION_INITIATE, PERMISSION_VOTE,
    PROPOSAL_APPROVE_DISCRIMINATOR, PROPOSAL_REJECT_DISCRIMINATOR,
};
use crate::{
    output,
    provision::{
        create_child_create_config_transaction_and_proposal_message,
        create_child_execute_config_transaction_message, create_child_execute_transaction_message,
        create_execute_config_transaction_message, create_execute_transaction_message,
        create_rpc_client, create_transaction_and_proposal_message,
        create_vote_proposal_message, get_proposal_status_and_threshold,
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
    ApprovePaired { vault_index: u64, config_index: u64 },
    ExecutePaired { vault_index: u64, config_index: u64 },
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

/// Check if a key is a member of the multisig with the required permission mask.
/// Returns (is_member, has_permission).
fn check_member_permission(ms: &SquadsMultisig, key: &Pubkey, permission_mask: u8) -> (bool, bool) {
    let member = ms.members.iter().find(|m| m.key == *key);
    let is_member = member.is_some();
    let has_permission = member
        .map(|m| (m.permissions.mask & permission_mask) == permission_mask)
        .unwrap_or(false);
    (is_member, has_permission)
}

/// Verify a key has the required permission, returning descriptive error if not.
fn verify_member_permission(
    ms: &SquadsMultisig,
    key: &Pubkey,
    permission: u8,
    role_name: &str,
) -> Result<()> {
    let (is_member, has_permission) = check_member_permission(ms, key, permission);
    if !is_member {
        output::Output::error(&format!("{} key is not a member of the multisig.", role_name));
        return Err(eyre::eyre!("{} must be a multisig member", role_name));
    }
    if !has_permission {
        let perm_name = match permission {
            PERMISSION_VOTE => "Vote",
            PERMISSION_EXECUTE => "Execute",
            PERMISSION_INITIATE => "Initiate",
            _ => "required",
        };
        output::Output::error(&format!(
            "{} key does not have {} permission.",
            role_name, perm_name
        ));
        return Err(eyre::eyre!(
            "Missing {} permission for {}",
            perm_name,
            role_name.to_lowercase()
        ));
    }
    Ok(())
}

/// Interactive confirmation - auto-confirms in E2E test mode
fn confirm_action(prompt: &str, default: bool) -> bool {
    if std::env::var("E2E_TEST_MODE").is_ok() {
        return true;
    }
    Confirm::new(prompt)
        .with_default(default)
        .prompt()
        .unwrap_or(false)
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

    // The fee payer must be a member of the parent multisig with Initiate permission
    let (is_member, has_initiate) =
        check_member_permission(&parent_ms, &fee_payer_signer.pubkey(), PERMISSION_INITIATE);
    if !is_member {
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
    if !has_initiate {
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
            PERMISSION_VOTE,
            "Vote",
            format!("Approve {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Reject => (
            PERMISSION_VOTE,
            "Vote",
            format!("Reject {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Execute => (
            PERMISSION_EXECUTE,
            "Execute",
            format!("Execute {} at index {}", kind.label(), proposal_index),
        ),
        ProposalAction::Create => (
            PERMISSION_INITIATE | PERMISSION_VOTE,
            "Initiate+Vote",
            format!(
                "Create {} proposal at index {}",
                kind.label(),
                proposal_index
            ),
        ),
    };

    let action_description = action_description.as_str();

    let (_, parent_vault_has_permission) =
        check_member_permission(&child_ms, &parent_vault_member, required_permission_mask);

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

    if !confirm_action(confirmation_prompt, true) {
        output::Output::info("Parent multisig proposal creation cancelled.");
        return Ok(());
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
        (
            ProposalAction::Approve,
            ChildTransactionFlavor::Vault,
            ParentFlowPayload::ApprovePaired {
                vault_index,
                config_index,
            },
        ) => crate::provision::create_child_approve_paired_proposals_message(
            feature_gate_multisig_address,
            vault_index,
            config_index,
            parent_vault_member,
        ),
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
        )?,
        (ProposalAction::Execute, ChildTransactionFlavor::Config, ParentFlowPayload::None) => {
            create_child_execute_config_transaction_message(
                feature_gate_multisig_address,
                proposal_index,
                parent_vault_member,
            )?
        }
        (
            ProposalAction::Execute,
            ChildTransactionFlavor::Vault,
            ParentFlowPayload::ExecutePaired {
                vault_index,
                config_index,
            },
        ) => {
            // Fetch the vault transaction from chain to get execution accounts
            use crate::squads::{get_transaction_pda, VaultTransaction};
            let (vault_transaction_pda, _) = get_transaction_pda(
                &feature_gate_multisig_address,
                vault_index,
                Some(&program_id),
            );
            let vault_transaction_account_data = rpc_client
                .get_account_data(&vault_transaction_pda)
                .map_err(|e| eyre::eyre!("Failed to fetch vault transaction account: {}", e))?;
            let vault_tx =
                VaultTransaction::try_from_slice(&vault_transaction_account_data[8..])
                    .map_err(|e| eyre::eyre!("Failed to deserialize vault transaction: {}", e))?;

            crate::provision::create_child_execute_paired_proposals_message(
                feature_gate_multisig_address,
                vault_index,
                vault_tx,
                config_index,
                parent_vault_member,
            )?
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
    if confirm_action("Approve this parent proposal now?", true) {
        let parent_proposal_index = parent_next_index;
        let approve_msg = create_vote_proposal_message(
            program_id,
            &parent_multisig,
            &fee_payer_signer.pubkey(),
            &fee_payer_signer.pubkey(),
            parent_proposal_index,
            blockhash,
            PROPOSAL_APPROVE_DISCRIMINATOR,
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
        let (is_fee_payer_member, has_execute_permission) =
            check_member_permission(&parent_ms, &fee_payer_signer.pubkey(), PERMISSION_EXECUTE);

        if approved as u16 >= threshold
            && is_fee_payer_member
            && has_execute_permission
            && confirm_action("Execute this parent proposal now?", true)
        {
                let fresh_blockhash = rpc_client.get_latest_blockhash()?;
                // Parent multisig always stores vault transactions, even when creating config on child
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
    // Auto-detect if this is Activate or Revoke and use paired approval logic
    if matches!(kind, TransactionKind::Activate | TransactionKind::Revoke) {
        let program_id = program_id.unwrap_or_else(|| {
            Pubkey::from_str_const("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")
        });

        let fee_payer_signer =
            signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
                .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

        let rpc_url = choose_network_from_config(config)?;
        let rpc_client = create_rpc_client(&rpc_url);

        // Detect if voting_key is itself a Squads multisig (parent)
        let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

        let vault_index = proposal_index;
        let config_index = proposal_index + 1;

        if is_parent_multisig {
            // Parent multisig flow - use paired approval
            return handle_parent_multisig_flow(
                &program_id,
                voting_key,
                feature_gate_multisig_address,
                proposal_index,
                kind,
                ChildTransactionFlavor::Vault,
                &fee_payer_signer,
                &rpc_url,
                ProposalAction::Approve,
                ParentFlowPayload::ApprovePaired {
                    vault_index,
                    config_index,
                },
            )
            .await;
        }

        // EOA flow - approve both proposals atomically in a single transaction
        vote_paired_proposals_eoa(
            &program_id,
            &feature_gate_multisig_address,
            &voting_key,
            &fee_payer_signer,
            vault_index,
            config_index,
            &rpc_client,
            crate::squads::PROPOSAL_APPROVE_DISCRIMINATOR,
            "approve",
        )
        .await?;

        Ok(())
    } else {
        // Rekey or other kinds - use single proposal approval
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

    let is_parent_multisig = load_multisig_if_any(&rpc_client, &voting_key)?.is_some();

    // For Activate/Revoke, we need to reject both vault and config proposals
    if matches!(kind, TransactionKind::Activate | TransactionKind::Revoke) {
        let vault_index = proposal_index;
        let config_index = proposal_index + 1;

        if is_parent_multisig {
            // Parent multisig flow - reject vault proposal only
            // (config proposal rejection would need a separate parent transaction)
            return handle_parent_multisig_flow(
                &program_id,
                voting_key,
                feature_gate_multisig_address,
                proposal_index,
                kind,
                ChildTransactionFlavor::Vault,
                &fee_payer_signer,
                &rpc_url,
                ProposalAction::Reject,
                ParentFlowPayload::None,
            )
            .await;
        }

        // EOA flow - reject both proposals atomically in a single transaction
        return vote_paired_proposals_eoa(
            &program_id,
            &feature_gate_multisig_address,
            &voting_key,
            &fee_payer_signer,
            vault_index,
            config_index,
            &rpc_client,
            crate::squads::PROPOSAL_REJECT_DISCRIMINATOR,
            "reject",
        )
        .await;
    }

    // For Rekey and other kinds - use single proposal rejection
    if is_parent_multisig {
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

    let blockhash = rpc_client.get_latest_blockhash()?;
    let transaction_message = create_vote_proposal_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        proposal_index,
        blockhash,
        PROPOSAL_REJECT_DISCRIMINATOR,
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

    if !confirm_action("Send this reject transaction now?", true) {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send reject transaction: {}", e))?;
    output::Output::field("Reject transaction sent successfully:", &signature);
    Ok(())
}

/// Helper function to execute a single proposal via EOA (direct execution)
async fn execute_single_proposal_eoa(
    program_id: &Pubkey,
    multisig_address: &Pubkey,
    voting_key: &Pubkey,
    fee_payer_signer: &Box<dyn Signer>,
    proposal_index: u64,
    rpc_client: &RpcClient,
) -> Result<()> {
    // Permission check: voting_key must be a member with Execute permission
    let child_acc = rpc_client
        .get_account(multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig account: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;

    verify_member_permission(&child_ms, voting_key, PERMISSION_EXECUTE, "Executor")?;

    // Build and send execute transaction
    let blockhash = rpc_client.get_latest_blockhash()?;
    let exec_msg = create_execute_transaction_message(
        program_id,
        multisig_address,
        voting_key,
        &fee_payer_signer.pubkey(),
        proposal_index,
        rpc_client,
        blockhash,
    )?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(exec_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    if !confirm_action(&format!("Execute proposal {} now?", proposal_index), true) {
        output::Output::hint("Skipped sending execute transaction.");
        return Ok(());
    }

    let signature = crate::provision::send_and_confirm_transaction(&transaction, rpc_client)
        .map_err(|e| {
            eyre::eyre!(
                "Failed to send execute transaction for index {}: {}",
                proposal_index,
                e
            )
        })?;
    output::Output::field(
        &format!("Execute transaction {} sent successfully:", proposal_index),
        &signature,
    );
    Ok(())
}

/// Helper function to vote on paired proposals (vault + config) via EOA in a single transaction
async fn vote_paired_proposals_eoa(
    program_id: &Pubkey,
    multisig_address: &Pubkey,
    voting_key: &Pubkey,
    fee_payer_signer: &Box<dyn Signer>,
    vault_index: u64,
    config_index: u64,
    rpc_client: &RpcClient,
    discriminator: &[u8],
    action_name: &str,
) -> Result<()> {
    // Permission check: voting_key must be a member with Vote permission
    let child_acc = rpc_client
        .get_account(multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig account: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;

    verify_member_permission(&child_ms, voting_key, PERMISSION_VOTE, "Voter")?;

    // Build and send paired vote transaction
    let blockhash = rpc_client.get_latest_blockhash()?;
    let vote_msg = crate::provision::create_vote_paired_proposals_message_eoa(
        program_id,
        multisig_address,
        voting_key,
        &fee_payer_signer.pubkey(),
        vault_index,
        config_index,
        blockhash,
        discriminator,
    )?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(vote_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    if !confirm_action(&format!("Send this {} transaction now?", action_name), true) {
        output::Output::hint(&format!("Skipped sending {} transaction.", action_name));
        return Ok(());
    }

    let signature = crate::provision::send_and_confirm_transaction(&transaction, rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send {} transaction: {}", action_name, e))?;
    output::Output::field(&format!("{} transaction sent successfully:", action_name), &signature);
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

    // Auto-detect if this is Activate or Revoke and use paired execution logic
    if matches!(kind, TransactionKind::Activate | TransactionKind::Revoke) {
        let vault_index = proposal_index;
        let config_index = proposal_index + 1;

        // For paired execution, also verify the config proposal is approved
        let (config_approved, config_threshold, config_status) = get_proposal_status_and_threshold(
            &program_id,
            &feature_gate_multisig_address,
            config_index,
            &rpc_client,
        )?;
        if !matches!(config_status, crate::squads::ProposalStatus::Approved { .. }) {
            output::Output::hint(&format!(
                "Config proposal at index {} is not Approved (approvals: {}/{})",
                config_index, config_approved, config_threshold
            ));
            return Err(eyre::eyre!(
                "Config proposal at index {} must be Approved before paired execution",
                config_index
            ));
        }

        if is_parent_multisig {
            // Parent multisig flow - use paired execution
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
                ParentFlowPayload::ExecutePaired {
                    vault_index,
                    config_index,
                },
            )
            .await;
        }

        // EOA flow - execute both proposals sequentially
        // Execute vault proposal first (uses VaultTransaction execute)
        execute_single_proposal_eoa(
            &program_id,
            &feature_gate_multisig_address,
            &voting_key,
            &fee_payer_signer,
            vault_index,
            &rpc_client,
        )
        .await?;

        // Execute config proposal second (uses ConfigTransaction execute)
        // Note: Permission was already checked in execute_single_proposal_eoa above
        let blockhash = rpc_client.get_latest_blockhash()?;
        let exec_msg = crate::provision::create_execute_config_transaction_message(
            &program_id,
            &feature_gate_multisig_address,
            &voting_key,
            &fee_payer_signer.pubkey(),
            Some(fee_payer_signer.pubkey()),
            config_index,
            blockhash,
        )?;

        let transaction = VersionedTransaction::try_new(
            VersionedMessage::V0(exec_msg),
            &[fee_payer_signer.as_ref()],
        )?;

        if !confirm_action(&format!("Execute config proposal {} now?", config_index), true) {
            output::Output::hint("Skipped sending config execute transaction.");
            return Ok(());
        }

        let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
            .map_err(|e| {
                eyre::eyre!(
                    "Failed to send execute transaction for config index {}: {}",
                    config_index,
                    e
                )
            })?;
        output::Output::field(
            &format!("Execute config transaction {} sent:", config_index),
            &signature,
        );

        return Ok(());
    }

    // Rekey or other kinds - use single proposal execution
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

        // Vault transaction execute path
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

    verify_member_permission(&child_ms, &voting_key, PERMISSION_EXECUTE, "Executor")?;

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
    if !confirm_action("Send this execute transaction now?", true) {
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
    output::Output::field(
        "Next Config Transaction Index",
        &(next_tx_index + 1).to_string(),
    );

    // Determine config action based on kind
    let (config_actions, config_memo) = match kind {
        TransactionKind::Activate => (
            vec![crate::squads::ConfigAction::ChangeThreshold { new_threshold: 1 }],
            None, // Remove memo to reduce tx size
        ),
        TransactionKind::Revoke => (
            vec![crate::squads::ConfigAction::ChangeThreshold {
                new_threshold: config.threshold, // Use original threshold from config
            }],
            None, // Remove memo to reduce tx size
        ),
        _ => return Err(eyre::eyre!("Unsupported kind for feature gate proposal")),
    };

    if is_parent_multisig {
        output::Output::info("Parent multisig detected - creating paired proposals sequentially");

        // voting_key is the parent multisig address, derive the vault PDA from it
        let parent_vault_pda = crate::squads::get_vault_pda(&voting_key, 0, Some(&program_id)).0;
        output::Output::field(
            "Parent vault PDA (creator/rent_payer):",
            &parent_vault_pda.to_string(),
        );

        let vault_tx_message =
            crate::provision::create_feature_gate_transaction_message(feature_id, feature_id, kind);

        // Pass the raw vault transaction message - handle_parent_multisig_flow will wrap it
        // in create_child_create_vault_transaction_and_proposal_message
        handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            next_tx_index,
            kind,
            ChildTransactionFlavor::Vault,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Create,
            ParentFlowPayload::Create(vault_tx_message),
        )
        .await?;

        output::Output::field(
            "Vault proposal created at index:",
            &next_tx_index.to_string(),
        );

        // Fetch the current transaction_index after vault creation to get the correct index for config
        let updated_ms_acc = rpc_client
            .get_account(&feature_gate_multisig_address)
            .map_err(|e| eyre::eyre!("Failed to fetch multisig after vault creation: {}", e))?;
        let updated_ms: SquadsMultisig =
            BorshDeserialize::deserialize(&mut &updated_ms_acc.data[8..])
                .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;
        let config_index = updated_ms.transaction_index + 1;

        output::Output::field("Config index (from chain):", &config_index.to_string());

        let config_message =
            crate::provision::create_child_create_config_transaction_and_proposal_message(
                feature_gate_multisig_address,
                config_index,
                parent_vault_pda, // parent vault PDA acts as creator (signed via CPI)
                parent_vault_pda, // parent vault PDA provides rent (funded with SOL, signed via CPI)
                config_actions,
                None, // No memo
            );

        handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            config_index,
            kind,
            ChildTransactionFlavor::Config,
            &fee_payer_signer,
            &rpc_url,
            ProposalAction::Create,
            ParentFlowPayload::Create(config_message),
        )
        .await?;

        output::Output::field(
            "Config proposal created at index:",
            &config_index.to_string(),
        );
        output::Output::info("Both proposals created successfully");

        return Ok(());
    }

    // EOA voting path - create paired proposals (vault + config)
    output::Output::info(&format!(
        "Creating paired {} proposals (vault + config)...",
        kind.label()
    ));

    // Verify voting_key has Initiate permission
    verify_member_permission(&feature_gate_ms, &voting_key, PERMISSION_INITIATE, "Creator")?;

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
        next_tx_index, // Vault proposal index
        config_index,  // Config proposal index
        vault_message,
        config_actions.clone(),
        config_memo.clone(),
    )
    .await?;

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
        .to_account_metas(),
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
    // Validate voter membership and Vote permission on the child multisig
    let child_acc = rpc_client
        .get_account(&multisig_address)
        .map_err(|e| eyre::eyre!("Failed to fetch multisig: {}", e))?;
    let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize multisig: {}", e))?;

    verify_member_permission(&child_ms, &voting_key, PERMISSION_VOTE, "Approver")?;

    let approve_msg = create_vote_proposal_message(
        &program_id,
        &multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        proposal_index,
        blockhash,
        PROPOSAL_APPROVE_DISCRIMINATOR,
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

    if !confirm_action("Send this approve transaction now?", true) {
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

    verify_member_permission(&multisig, &voting_key, PERMISSION_EXECUTE, "Executor")?;

    output::Output::header("Config Execute - Signer Details");
    output::Output::field("Fee payer", &fee_payer_signer.pubkey().to_string());
    output::Output::field("Voting key (member)", &voting_key.to_string());

    // Fresh blockhash and build execute message for the config transaction
    let blockhash = rpc_client.get_latest_blockhash()?;
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
    if !confirm_action("Send this execute transaction now?", true) {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    // Send and confirm
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to execute config change: {}", e))?;
    output::Output::field("Config change executed (sig):", &signature);
    Ok(())
}
