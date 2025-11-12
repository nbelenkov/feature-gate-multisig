use eyre::Result;
use solana_clap_v3_utils::keypair::signer_from_path;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::squads::{get_vault_pda, Multisig as SquadsMultisig};
use crate::{
    output,
    provision::{
        create_child_execute_transaction_message, create_common_activation_transaction_message,
        create_execute_transaction_message, create_parent_approve_proposal_message,
        create_rpc_client, create_transaction_and_proposal_message,
        get_proposal_status_and_threshold,
    },
    utils::{choose_network_from_config, create_child_vote_approve_transaction_message, Config},
};
use borsh::BorshDeserialize;
use inquire::Confirm;

/// Helper enum to specify the type of parent multisig operation
#[derive(Debug, Clone)]
enum ParentMultisigOperation {
    Approve,
    Execute,
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
    activation_or_revocation: u64,
    fee_payer_signer: &Box<dyn Signer>,
    rpc_url: &str,
    operation: ParentMultisigOperation,
    execution_accounts: Option<Vec<solana_instruction::AccountMeta>>,
) -> Result<()> {
    let rpc_client = create_rpc_client(rpc_url);

    // Fetch parent's next transaction index
    let parent_acc = rpc_client
        .get_account(&parent_multisig)
        .map_err(|e| eyre::eyre!("Failed to fetch parent multisig account: {}", e))?;
    let parent_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &parent_acc.data[8..])
        .map_err(|e| eyre::eyre!("Failed to deserialize parent multisig: {}", e))?;
    let parent_next_index = parent_ms.transaction_index + 1;

    // The fee payer must be a member of the parent multisig to initiate proposals
    let fee_payer_is_member = parent_ms
        .members
        .iter()
        .any(|m| m.key == fee_payer_signer.pubkey());
    if !fee_payer_is_member {
        output::Output::error(
            "Fee payer must be a member of the parent multisig to create/approve/execute proposals.",
        );
        output::Output::hint(&format!(
            "Current fee payer: {}\nParent multisig: {}\nAdd the fee payer as a member (with {} permission) or choose a fee payer that is already a member.",
            fee_payer_signer.pubkey(),
            parent_multisig,
            match operation {
                ParentMultisigOperation::Approve => "Vote",
                ParentMultisigOperation::Execute => "Execute",
            }
        ));
        return Err(eyre::eyre!(
            "Fee payer is not a member of the parent multisig"
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
        ParentMultisigOperation::Approve => (
            1 << 1, // Vote permission
            "Vote",
            if activation_or_revocation == 1 {
                "Approve Feature Gate Activation"
            } else {
                "Approve Feature Gate Revocation"
            },
        ),
        ParentMultisigOperation::Execute => (
            1 << 2, // Execute permission
            "Execute",
            if activation_or_revocation == 1 {
                "Execute Feature Gate Activation"
            } else {
                "Execute Feature Gate Revocation"
            },
        ),
    };

    let parent_vault_has_permission = child_ms.members.iter().any(|m| {
        m.key == parent_vault_member && (m.permissions.mask & required_permission_mask) != 0
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
    if matches!(operation, ParentMultisigOperation::Execute) {
        output::Output::field(
            "Child Transaction Index:",
            &activation_or_revocation.to_string(),
        );
    }
    output::Output::field("Action:", action_description);

    // Ask for confirmation before creating the parent multisig proposal
    let confirmation_prompt = match &operation {
        ParentMultisigOperation::Approve => "Create parent multisig proposal for this transaction?",
        ParentMultisigOperation::Execute => {
            "Create parent multisig proposal to execute child transaction?"
        }
    };

    if !Confirm::new(confirmation_prompt)
        .with_default(true)
        .prompt()
        .unwrap_or(false)
    {
        output::Output::info("Parent multisig proposal creation cancelled.");
        return Ok(());
    }

    // Create the transaction message based on operation type
    let tx_message = match operation {
        ParentMultisigOperation::Approve => create_child_vote_approve_transaction_message(
            feature_gate_multisig_address,
            activation_or_revocation,
            parent_vault_member,
        ),
        ParentMultisigOperation::Execute => create_child_execute_transaction_message(
            feature_gate_multisig_address,
            activation_or_revocation,
            parent_vault_member,
            execution_accounts
                .ok_or_else(|| eyre::eyre!("Execution accounts required for Execute operation"))?,
        ),
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
        Some(5000),
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
    if Confirm::new("Approve this parent proposal now?")
        .with_default(true)
        .prompt()
        .unwrap_or(false)
    {
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
            if Confirm::new("Execute this parent proposal now?")
                .with_default(true)
                .prompt()
                .unwrap_or(false)
            {
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
                if matches!(operation, ParentMultisigOperation::Execute) {
                    output::Output::success(
                        "Child transaction has been executed via parent multisig!",
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

pub async fn approve_feature_gate_activation_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
) -> Result<()> {
    approve_common_feature_gate_proposal(
        config,
        feature_gate_multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        1, // activation
    )
    .await
}

pub async fn approve_feature_gate_activation_revocation_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
) -> Result<()> {
    approve_common_feature_gate_proposal(
        config,
        feature_gate_multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        2, // revocation
    )
    .await
}

pub async fn approve_common_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    activation_or_revocation: u64,
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
    let blockhash = rpc_client.get_latest_blockhash()?;

    // Detect if voting_key is itself a Squads multisig (parent)
    let is_parent_multisig = rpc_client
        .get_account(&voting_key)
        .ok()
        .and_then(|acc| {
            if acc.data.len() >= 8 {
                let slice = &acc.data[8..];
                SquadsMultisig::deserialize(&mut &slice[..]).ok()
            } else {
                None
            }
        })
        .is_some();

    if is_parent_multisig {
        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            activation_or_revocation,
            &fee_payer_signer,
            &rpc_url,
            ParentMultisigOperation::Approve,
            None,
        )
        .await;
    }

    let transaction_message = create_common_activation_transaction_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        blockhash,
        activation_or_revocation,
    )
    .map_err(|e| {
        eyre::eyre!(
            "Failed to create approve activation transaction message: {}",
            e
        )
    })?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(transaction_message),
        &[fee_payer_signer.as_ref()],
    )?;

    // Confirm before sending on-chain (EOA approval path)
    let should_send = Confirm::new("Send this approve transaction now?")
        .with_default(true)
        .prompt()
        .unwrap_or(false);
    if !should_send {
        output::Output::hint("Skipped sending. You can submit the above encoded transaction manually or rerun to send.");
        return Ok(());
    }

    // Send it now and print signature
    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send transaction and proposal: {}", e))?;
    output::Output::field("Transaction sent successfully:", &signature);
    Ok(())
}

pub async fn execute_feature_gate_activation_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
) -> Result<()> {
    execute_common_feature_gate_proposal(
        config,
        feature_gate_multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        1,
    )
    .await
}

pub async fn execute_feature_gate_revocation_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
) -> Result<()> {
    execute_common_feature_gate_proposal(
        config,
        feature_gate_multisig_address,
        voting_key,
        fee_payer_path,
        program_id,
        2,
    )
    .await
}

pub async fn execute_common_feature_gate_proposal(
    config: &Config,
    feature_gate_multisig_address: Pubkey,
    voting_key: Pubkey,
    fee_payer_path: String,
    program_id: Option<Pubkey>,
    activation_or_revocation: u64,
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

    // Readiness check: ensure approvals >= threshold on child proposal index 1
    let (approved, threshold, _status) = get_proposal_status_and_threshold(
        &program_id,
        &feature_gate_multisig_address,
        activation_or_revocation,
        &rpc_client,
    )?;
    if (approved as u16) < threshold {
        output::Output::hint(&format!(
            "Proposal not ready to execute yet: approvals {}/{}",
            approved, threshold
        ));
        return Err(eyre::eyre!("Insufficient approvals to execute"));
    }

    let is_parent_multisig = rpc_client
        .get_account(&voting_key)
        .ok()
        .and_then(|acc| {
            if acc.data.len() >= 8 {
                let slice = &acc.data[8..];
                SquadsMultisig::deserialize(&mut &slice[..]).ok()
            } else {
                None
            }
        })
        .is_some();

    if is_parent_multisig {
        // Fetch the child transaction to get its account metas for execution
        use crate::squads::{get_transaction_pda, VaultTransaction};
        let (child_transaction_pda, _) = get_transaction_pda(
            &feature_gate_multisig_address,
            activation_or_revocation,
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
            let is_writable = child_transaction_message.is_static_writable_index(i);
            if is_writable {
                child_execution_account_metas
                    .push(solana_instruction::AccountMeta::new(*account_key, false));
            } else {
                child_execution_account_metas.push(solana_instruction::AccountMeta::new_readonly(
                    *account_key,
                    false,
                ));
            }
        }

        return handle_parent_multisig_flow(
            &program_id,
            voting_key,
            feature_gate_multisig_address,
            activation_or_revocation,
            &fee_payer_signer,
            &rpc_url,
            ParentMultisigOperation::Execute,
            Some(child_execution_account_metas),
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

    // Fresh blockhash and build execute message for proposal index 1
    let blockhash = rpc_client.get_latest_blockhash()?;
    let exec_msg = create_execute_transaction_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        activation_or_revocation,
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
