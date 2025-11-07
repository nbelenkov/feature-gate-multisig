use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eyre::Result;
use solana_clap_v3_utils::keypair::signer_from_path;
use solana_client::nonblocking::rpc_client::RpcClient as AsyncRpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::squads::{get_vault_pda, Multisig as SquadsMultisig};
use crate::{
    output,
    provision::{
        create_common_activation_transaction_message, create_execute_transaction_message,
        create_parent_approve_proposal_message, create_rpc_client,
        create_transaction_and_proposal_message, get_proposal_status_and_threshold,
    },
    utils::{
        choose_network_from_config, create_child_vote_approve_transaction_message,
        load_fee_payer_keypair, Config,
    },
};
use borsh::BorshDeserialize;
use inquire::Confirm;

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
        1, // activation
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
        // Create a parent multisig transaction+proposal that will cast the vote on the child (activation = tx index 1)
        let parent_multisig = voting_key;

        // Fetch parent's next transaction index
        let parent_acc = rpc_client
            .get_account(&parent_multisig)
            .map_err(|e| eyre::eyre!("Failed to fetch parent multisig account: {}", e))?;
        let parent_ms: SquadsMultisig =
            BorshDeserialize::deserialize(&mut &parent_acc.data[8..])
                .map_err(|e| eyre::eyre!("Failed to deserialize parent multisig: {}", e))?;
        let parent_next_index = parent_ms.transaction_index + 1;

        // Prefer using the parent vault PDA as the child member so the parent program can sign via seeds.
        let parent_vault_member = get_vault_pda(&parent_multisig, 0, None).0;

        // Validate the child multisig includes the parent vault PDA with Vote permission
        let child_acc = rpc_client
            .get_account(&feature_gate_multisig_address)
            .map_err(|e| eyre::eyre!("Failed to fetch child multisig: {}", e))?;
        let child_ms: SquadsMultisig = BorshDeserialize::deserialize(&mut &child_acc.data[8..])
            .map_err(|e| eyre::eyre!("Failed to deserialize child multisig: {}", e))?;
        let parent_vault_is_member_with_vote = child_ms
            .members
            .iter()
            .any(|m| m.key == parent_vault_member && (m.permissions.mask & (1 << 1)) != 0);

        if !parent_vault_is_member_with_vote {
            // Helpful diagnostic: detect if the parent multisig address itself is a member (common misconfig)
            let parent_multisig_is_member =
                child_ms.members.iter().any(|m| m.key == parent_multisig);
            if parent_multisig_is_member {
                output::Output::error("Child multisig has the parent multisig address as a member, but not the parent vault PDA. The parent program cannot sign as the multisig address during CPI.");
                output::Output::hint(&format!(
                    "Please add the parent vault PDA as a member with Vote permission on the child: {}",
                    parent_vault_member
                ));
            } else {
                output::Output::error("Child multisig is missing the parent vault PDA as a member with Vote permission.");
                output::Output::hint(&format!(
                    "Add this key as a member with Vote: {}",
                    parent_vault_member
                ));
            }
            return Err(eyre::eyre!(
                "Child multisig missing required member for programmatic approval"
            ));
        }

        let tx_message = create_child_vote_approve_transaction_message(
            feature_gate_multisig_address,
            activation_or_revocation,
            parent_vault_member,
        );

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
        let signature =
            crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
                .map_err(|e| eyre::eyre!("Failed to send parent vote transaction: {}", e))?;

        output::Output::header("Parent Multisig Vote Transaction Created & Sent:");
        output::Output::field("Signature:", &signature);

        // Offer to approve the parent proposal immediately (casts one Approve vote)
        if Confirm::new("Approve this parent proposal now?")
            .with_default(true)
            .prompt()
            .unwrap_or(false)
        {
            let parent_proposal_index = parent_next_index;
            let approve_msg = create_parent_approve_proposal_message(
                &program_id,
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
            let approve_sig =
                crate::provision::send_and_confirm_transaction(&approve_tx, &rpc_client)
                    .map_err(|e| eyre::eyre!("Failed to approve parent proposal: {}", e))?;
            output::Output::field("Parent proposal approved (sig):", &approve_sig);

            // If approvals meet threshold, offer to execute the parent proposal now
            let async_client =
                AsyncRpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
            let (approved, threshold, _status) = get_proposal_status_and_threshold(
                &program_id,
                &parent_multisig,
                parent_proposal_index,
                &async_client,
            )
            .await?;
            let is_fee_payer_member = parent_ms
                .members
                .iter()
                .any(|m| m.key == fee_payer_signer.pubkey());
            // Ensure executor has Execute permission on parent multisig
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
                    // Refresh blockhash before building execute tx
                    let fresh_blockhash = async_client.get_latest_blockhash().await?;
                    let exec_msg = create_execute_transaction_message(
                        &program_id,
                        &parent_multisig,
                        &fee_payer_signer.pubkey(),
                        &fee_payer_signer.pubkey(),
                        parent_proposal_index,
                        &async_client,
                        fresh_blockhash,
                    )
                    .await?;
                    let exec_tx = VersionedTransaction::try_new(
                        VersionedMessage::V0(exec_msg),
                        &[fee_payer_signer.as_ref()],
                    )?;
                    let exec_sig =
                        crate::provision::send_and_confirm_transaction(&exec_tx, &rpc_client)
                            .map_err(|e| eyre::eyre!("Failed to execute parent proposal: {}", e))?;
                    output::Output::field("Parent proposal executed (sig):", &exec_sig);
                }
            } else if !is_fee_payer_member {
                output::Output::hint("Fee payer is not a member of the parent multisig; cannot auto-execute. Use a parent member as the executor.");
            } else if !has_execute_permission {
                output::Output::hint("Executor does not have Execute permission on the parent multisig; use a member with Execute to run execution.");
            } else {
                output::Output::hint(&format!(
                    "Parent approvals {}/{} — waiting for more confirmations before execution.",
                    approved, threshold
                ));
            }
        }
        return Ok(());
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
    let serialized_transaction = bincode::serialize(&transaction)?;

    let transaction_encoded_bs58 = bs58::encode(&serialized_transaction).into_string();
    let transaction_encoded_base64 = B64.encode(&serialized_transaction);

    output::Output::header("Encoded Transactions:");
    output::Output::separator();
    output::Output::field("Base58:", &transaction_encoded_bs58);
    output::Output::separator();
    output::Output::field("Base64:", &transaction_encoded_base64);
    output::Output::separator();

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
    // Non-blocking client for data fetches, blocking for simulate/send
    let async_client = AsyncRpcClient::new(rpc_url.clone());
    let rpc_client = create_rpc_client(&rpc_url);

    // Readiness check: ensure approvals >= threshold on child proposal index 1
    let (approved, threshold, _status) = get_proposal_status_and_threshold(
        &program_id,
        &feature_gate_multisig_address,
        activation_or_revocation,
        &async_client,
    )
    .await?;
    if (approved as u16) < threshold {
        output::Output::hint(&format!(
            "Proposal not ready to execute yet: approvals {}/{}",
            approved, threshold
        ));
        return Err(eyre::eyre!("Insufficient approvals to execute"));
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
    let blockhash = async_client.get_latest_blockhash().await?;
    let exec_msg = create_execute_transaction_message(
        &program_id,
        &feature_gate_multisig_address,
        &voting_key,
        &fee_payer_signer.pubkey(),
        activation_or_revocation,
        &async_client,
        blockhash,
    )
    .await?;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::V0(exec_msg),
        &[fee_payer_signer.as_ref()],
    )?;

    let serialized_transaction = bincode::serialize(&transaction)?;

    let transaction_encoded_bs58 = bs58::encode(&serialized_transaction).into_string();
    let transaction_encoded_base64 = B64.encode(&serialized_transaction);

    output::Output::header("Encoded Transactions:");
    output::Output::separator();
    output::Output::field("Base58:", &transaction_encoded_bs58);
    output::Output::separator();
    output::Output::field("Base64:", &transaction_encoded_base64);

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
