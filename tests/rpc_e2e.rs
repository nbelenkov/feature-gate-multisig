//! RPC-based E2E tests against a running surfpool instance.
//! Run `surfpool start` first, which will load Squads BPF and start a local validator.

use std::env;
use std::path::PathBuf;

use borsh::BorshDeserialize;

use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair, signer::Signer,
};

use once_cell::sync::OnceCell;

use feature_gate_multisig_tool::commands::create::create_command_with_deployments;
use feature_gate_multisig_tool::commands::transaction_generation::{
    approve_common_feature_gate_proposal, create_feature_gate_proposal,
    execute_common_feature_gate_proposal, reject_common_feature_gate_proposal,
    rekey_multisig_feature_gate, TransactionKind,
};
use feature_gate_multisig_tool::feature_gate_program::{
    FEATURE_ACCOUNT_SIZE, FEATURE_GATE_PROGRAM_ID,
};
use feature_gate_multisig_tool::provision::create_multisig;
use feature_gate_multisig_tool::squads::{
    get_proposal_pda, get_vault_pda, Member, Permission, Permissions, Proposal, ProposalStatus,
    SQUADS_MULTISIG_PROGRAM_ID,
};
use feature_gate_multisig_tool::utils::Config;

fn rpc_url() -> String {
    env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string())
}

fn full_permissions() -> Permissions {
    Permissions {
        mask: (Permission::Initiate as u8) | (Permission::Vote as u8) | (Permission::Execute as u8),
    }
}

struct Fixture {
    parent_multisigs: Vec<Pubkey>,
    parent_key_paths: Vec<String>,
    parent_vaults: Vec<Pubkey>,
    eoa_member: Pubkey,
    eoa_key_path: String,
    // Note: arrays below include EOA at index 1 for unified loops
    child_multisig: Pubkey,
    child_vault: Pubkey,
    executor_path: String,
    config: Config,
}

static FIXTURE: OnceCell<Fixture> = OnceCell::new();

async fn build_fixture() -> Fixture {
    // Enable non-interactive mode for E2E tests
    std::env::set_var("E2E_TEST_MODE", "1");
    std::env::set_var("RUST_LOG", "info");

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    // Step 1: Create three parent multisigs
    let mut parent_multisigs = Vec::new();
    let mut parent_vaults = Vec::new();
    let mut parent_key_paths = Vec::new();

    let temp_dir: PathBuf = std::env::temp_dir();

    for i in 0..3 {
        let creator = Keypair::new();
        let sig = client
            .request_airdrop(&creator.pubkey(), 10_000_000_000)
            .expect("request airdrop");
        client.confirm_transaction(&sig).expect("confirm airdrop");

        let members = vec![Member {
            key: creator.pubkey(),
            permissions: full_permissions(),
        }];

        let create_key = Keypair::new();
        let (multisig_pda, _signature) =
            create_multisig(rpc_url(), None, &creator, &create_key, members, 1, None)
                .await
                .expect("create parent multisig");

        let vault_pda = get_vault_pda(&multisig_pda, 0, None).0;

        // Fund the parent vault with SOL so it can pay rent when creating config transactions
        let fund_vault_ix = solana_system_interface::instruction::transfer(
            &creator.pubkey(),
            &vault_pda,
            1_000_000_000, // 1 SOL
        );
        let recent_blockhash = client.get_latest_blockhash().expect("get blockhash");
        let fund_tx = solana_transaction::Transaction::new_signed_with_payer(
            &[fund_vault_ix],
            Some(&creator.pubkey()),
            &[&creator],
            recent_blockhash,
        );
        client
            .send_and_confirm_transaction(&fund_tx)
            .expect("fund parent vault");

        parent_multisigs.push(multisig_pda);
        parent_vaults.push(vault_pda);

        let keypair_path = temp_dir.join(format!("parent_{}.json", i));
        let keypair_bytes: Vec<u8> = creator.to_bytes().to_vec();
        std::fs::write(
            &keypair_path,
            serde_json::to_string(&keypair_bytes).unwrap(),
        )
        .expect("write keypair");
        parent_key_paths.push(keypair_path.to_string_lossy().to_string());
    }

    // Create one additional EOA (non-multisig) member
    let eoa = Keypair::new();
    let sig = client
        .request_airdrop(&eoa.pubkey(), 10_000_000_000)
        .expect("request airdrop for eoa");
    client
        .confirm_transaction(&sig)
        .expect("confirm airdrop for eoa");
    let eoa_keypair_path = temp_dir.join("parent_3_eoa.json");
    let eoa_keypair_bytes: Vec<u8> = eoa.to_bytes().to_vec();
    std::fs::write(
        &eoa_keypair_path,
        serde_json::to_string(&eoa_keypair_bytes).unwrap(),
    )
    .expect("write eoa keypair");

    // Step 2: Use create_command to build the child feature gate multisig with parent vault PDAs and the EOA as members
    let fee_payer_path = PathBuf::from(&parent_key_paths[0]);

    // Ensure EOA is at index 1 among child members
    let mut members: Vec<String> = parent_vaults.iter().map(|v| v.to_string()).collect();
    // Ensure EOA is at index 1 among child members
    members.insert(1, eoa.pubkey().to_string());

    let mut config = Config {
        networks: vec![rpc_url()],
        threshold: 3,
        members,
        fee_payer_path: Some(fee_payer_path.to_string_lossy().to_string()),
    };

    let deployments = create_command_with_deployments(
        &mut config,
        Some(3),
        vec![],
        Some(fee_payer_path.to_string_lossy().to_string()),
    )
    .await
    .expect("create feature gate via create_command");

    let deployment = deployments.get(0).expect("deployment result should exist");
    let child_multisig_pda = deployment.multisig_address;
    let child_vault_pda = deployment.vault_address;

    let executor_path = parent_key_paths[0].clone();

    // Insert EOA into unified parent arrays at index 1
    parent_multisigs.insert(1, eoa.pubkey());
    parent_key_paths.insert(1, eoa_keypair_path.to_string_lossy().to_string());
    parent_vaults.insert(1, eoa.pubkey());

    Fixture {
        parent_multisigs,
        parent_key_paths,
        parent_vaults,
        eoa_member: eoa.pubkey(),
        eoa_key_path: eoa_keypair_path.to_string_lossy().to_string(),
        child_multisig: child_multisig_pda,
        child_vault: child_vault_pda,
        executor_path,
        config,
    }
}

async fn get_fixture() -> &'static Fixture {
    if let Some(f) = FIXTURE.get() {
        return f;
    }
    let fixture = build_fixture().await;
    let _ = FIXTURE.set(fixture);
    FIXTURE.get().expect("fixture should be set")
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_1_activate_feature_gate() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig: {}",
        fixture.child_multisig
    );
    println!("   Feature gate ID (vault): {}", fixture.child_vault);

    // Step 3: Approve the proposal using parent arrays (EOA at index 1)
    let proposal_index = 1u64; // Activation proposal created by create_command
    for i in 0..3 {
        let voter = fixture.parent_multisigs[i];
        let keypair_path = &fixture.parent_key_paths[i];

        approve_common_feature_gate_proposal(
            &fixture.config,
            fixture.child_multisig,
            voter,
            keypair_path.clone(),
            None,
            proposal_index,
            TransactionKind::Activate,
        )
        .await
        .expect("approve proposal");

        println!("✅ Approver {} approved proposal", i + 1);
    }

    // Step 5: Execute the proposal
    let executor_multisig = fixture.parent_multisigs[0];

    execute_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        executor_multisig,
        fixture.executor_path.clone(),
        None,
        proposal_index,
        TransactionKind::Activate,
    )
    .await
    .expect("execute proposal");

    println!("✅ Feature gate activated");

    // Step 6: Verify the feature gate account was properly activated
    let feature_gate_account = client
        .get_account(&fixture.child_vault)
        .expect("feature gate account should exist");

    // Verify the account is owned by the feature gate program
    assert_eq!(
        feature_gate_account.owner, FEATURE_GATE_PROGRAM_ID,
        "feature gate should be owned by Feature Gate program"
    );

    // Verify the account has the correct size for a feature gate account
    assert_eq!(
        feature_gate_account.data.len(),
        FEATURE_ACCOUNT_SIZE,
        "feature gate account should have correct size"
    );

    println!("✅ Feature gate activation E2E test completed successfully!");

    // Debug: Check threshold
    let child_ms_account_final = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig");
    let child_ms_final: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account_final.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms_final.threshold, 1,
        "threshold should be 1 after activation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_2_revoke_feature_gate() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for revoke: {}",
        fixture.child_multisig
    );
    println!("   Feature gate ID (vault): {}", fixture.child_vault);

    // Step 1: Verify Index 2 already executed by test 1 (threshold should be 1)
    println!("\nStep 1: Verify threshold is 1 (Index 2 was executed by test 1)");
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");

    assert_eq!(
        child_ms.threshold, 1,
        "threshold should be 1 after test 1 executed Index 2"
    );
    println!("✅ Verified: Threshold is 1");

    // Step 2: Create revocation proposal dynamically (after threshold is 1)
    println!("\nStep 2: Create revocation proposal after threshold is lowered");

    // Fetch current transaction index before creation
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for index");
    let child_ms_before: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    let revocation_index = child_ms_before.transaction_index + 1;

    // Create revocation proposal via parent multisig (creates both vault and config proposals)
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        None,
        TransactionKind::Revoke,
    )
    .await
    .expect("create revoke proposal dynamically");

    println!(
        "✅ Revocation proposals created at indices {} (vault) and {} (config)",
        revocation_index,
        revocation_index + 1
    );

    // Debug: Verify both proposals exist and check transaction_index
    println!("\n🐛 Debug: Verifying both proposals exist after creation");

    // Check transaction_index
    let child_ms_after = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig after creation");
    let child_ms_data: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_after.data[8..])
            .expect("deserialize child multisig after creation");
    println!(
        "Transaction index after creation: {}",
        child_ms_data.transaction_index
    );

    let (vault_prop_pda, _) = get_proposal_pda(&fixture.child_multisig, revocation_index, None);
    let (config_prop_pda, _) =
        get_proposal_pda(&fixture.child_multisig, revocation_index + 1, None);

    if client.get_account(&vault_prop_pda).is_ok() {
        println!("✅ Vault proposal (Index {}) exists", revocation_index);
    } else {
        println!(
            "❌ Vault proposal (Index {}) does NOT exist!",
            revocation_index
        );
    }

    if client.get_account(&config_prop_pda).is_ok() {
        println!("✅ Config proposal (Index {}) exists", revocation_index + 1);
    } else {
        println!(
            "❌ Config proposal (Index {}) does NOT exist!",
            revocation_index + 1
        );
    }

    // Step 3: Approve revocation with only 1 approval (threshold is now 1)
    println!("\nStep 3: Approve revocation with only 1 approval");

    approve_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        None,
        revocation_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("approve revoke proposal with 1 approval");

    println!("✅ Revocation approved with only 1 approval!");

    // Verify the proposal is approved with just 1 approval
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, revocation_index, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    assert_eq!(
        proposal.approved.len(),
        1,
        "revocation proposal should have 1 approval"
    );
    match proposal.status {
        ProposalStatus::Approved { timestamp: _ } => {
            println!("✅ Proposal status: Approved with 1 approval (threshold is 1)");
        }
        _ => panic!("Expected proposal to be Approved"),
    }

    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, revocation_index + 1, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    assert_eq!(
        proposal.approved.len(),
        1,
        "config change proposal should have 1 approval"
    );
    match proposal.status {
        ProposalStatus::Approved { timestamp: _ } => {
            println!("✅ Proposal status: Approved with 1 approval (threshold is 1)");
        }
        _ => panic!("Expected proposal to be Approved"),
    }

    // Step 4: Execute the revocation (this should also execute the threshold restoration)
    println!("\nStep 4: Execute revocation (should also restore threshold to 3)");

    execute_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        None,
        revocation_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("execute revoke proposal");

    println!("✅ Revocation executed!");

    // Verify threshold was restored to 3
    let child_ms_final = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig");
    let child_ms_data: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_final.data[8..])
            .expect("deserialize child multisig");

    assert_eq!(
        child_ms_data.threshold, 3,
        "threshold should be restored to 3 after revocation execution"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_3_reject_activation() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for reject test: {}",
        fixture.child_multisig
    );

    // Determine the next transaction index for a new activation proposal
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for reject test");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig for reject test");
    let vault_proposal_index = child_ms.transaction_index + 1;
    let config_proposal_index = vault_proposal_index + 1;

    // Create a new activation proposal via parent[0]
    // NOTE: This now creates PAIRED proposals (vault + config) at indices N and N+1
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        None,
        TransactionKind::Activate,
    )
    .await
    .expect("create activation proposal for rejection");

    println!(
        "✅ Activation proposals created at indices {} (vault) and {} (config) for rejection test",
        vault_proposal_index, config_proposal_index
    );

    // We only need to reject the vault proposal (the main activation)
    let proposal_index = vault_proposal_index;

    // Reject from one parent multisig and the EOA (2 rejections needed for 4 members, threshold 3)
    let parent_multisig_pda = fixture.parent_multisigs[0];
    let keypair_path = &fixture.parent_key_paths[0];
    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        parent_multisig_pda,
        keypair_path.clone(),
        None,
        proposal_index,
        TransactionKind::Activate,
    )
    .await
    .expect("reject activation proposal by parent");
    println!("✅ Parent 1 rejected proposal");

    // EOA rejection
    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        None,
        proposal_index,
        TransactionKind::Activate,
    )
    .await
    .expect("reject activation proposal by eoa");
    println!("✅ EOA member rejected proposal");

    // Fetch the proposal account and verify it's in Rejected status
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");

    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    // Verify proposal status is Rejected
    match proposal.status {
        ProposalStatus::Rejected { .. } => {
            println!("✅ Proposal status confirmed as Rejected");
        }
        _ => panic!("Expected proposal status to be Rejected"),
    }

    // Verify the parent vault PDA and EOA are in the rejected list
    assert_eq!(
        proposal.rejected.len(),
        2,
        "two members should have rejected"
    );
    assert!(
        proposal.rejected.contains(&fixture.parent_vaults[0]),
        "parent vault 0 should be in rejected list"
    );
    assert!(
        proposal.rejected.contains(&fixture.eoa_member),
        "EOA should be in rejected list"
    );

    println!("✅ Feature gate rejection E2E test completed successfully!");
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_4_reject_revocation() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for revoke rejection test: {}",
        fixture.child_multisig
    );

    // Determine the next transaction index for a new revocation proposal
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for revoke rejection test");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig for revoke rejection test");
    let vault_proposal_index = child_ms.transaction_index + 1;
    let config_proposal_index = vault_proposal_index + 1;

    // Create a new revocation proposal via parent[2] (skip EOA at index 1)
    // NOTE: This now creates PAIRED proposals (vault + config) at indices N and N+1
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[2],
        fixture.parent_key_paths[2].clone(),
        None,
        TransactionKind::Revoke,
    )
    .await
    .expect("create revocation proposal for rejection");

    println!(
        "✅ Revocation proposals created at indices {} (vault) and {} (config) for rejection test (via parent 3)",
        vault_proposal_index, config_proposal_index
    );

    // We only need to reject the vault proposal (the main revocation)
    let proposal_index = vault_proposal_index;

    // Reject from one parent multisig and the EOA (2 rejections needed for 4 members, threshold 3)
    let parent_multisig_pda = fixture.parent_multisigs[0];
    let keypair_path = &fixture.parent_key_paths[0];

    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        parent_multisig_pda,
        keypair_path.clone(),
        None,
        proposal_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("reject revocation proposal by parent");
    println!("✅ Parent 1 rejected revocation proposal");

    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        None,
        proposal_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("reject revocation proposal by eoa");
    println!("✅ EOA member rejected revocation proposal");

    // Fetch the proposal account and verify it's in Rejected status
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");

    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    // Verify proposal status is Rejected
    match proposal.status {
        ProposalStatus::Rejected { .. } => {
            println!("✅ Proposal status confirmed as Rejected");
        }
        _ => panic!("Expected proposal status to be Rejected"),
    }

    // Verify parent vault and EOA are in the rejected list
    assert_eq!(
        proposal.rejected.len(),
        2,
        "two members should have rejected"
    );
    assert!(
        proposal.rejected.contains(&fixture.parent_vaults[0]),
        "parent vault 0 should be in rejected list"
    );
    assert!(
        proposal.rejected.contains(&fixture.eoa_member),
        "EOA should be in rejected list"
    );

    println!("✅ Feature gate revocation rejection E2E test completed successfully!");
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_5_reject_rekey() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for rekey rejection: {}",
        fixture.child_multisig
    );

    // Determine the next transaction index for a new rekey proposal
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for rekey rejection");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig for rekey rejection");
    let proposal_index = child_ms.transaction_index + 1;

    // Ensure the rekey proposal exists. Create via parent[0] if missing.
    let (child_proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index, None);
    if client.get_account(&child_proposal_pda).is_err() {
        rekey_multisig_feature_gate(
            &fixture.config,
            fixture.child_multisig,
            fixture.parent_multisigs[0],
            fixture.parent_key_paths[0].clone(),
            None,
        )
        .await
        .expect("create rekey proposal for rejection");

        println!(
            "✅ Rekey proposal created at index {} for rejection test (via parent 1)",
            proposal_index
        );
    }

    // With 4 members and threshold 3, rejection threshold is 2
    let rejecting_parent_ms = fixture.parent_multisigs[2];
    let rejecting_parent_path = &fixture.parent_key_paths[2];

    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        rejecting_parent_ms,
        rejecting_parent_path.clone(),
        None,
        proposal_index,
        TransactionKind::Rekey,
    )
    .await
    .expect("reject rekey proposal by parent");
    println!("✅ Parent 2 rejected rekey proposal");

    // EOA rejection
    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        None,
        proposal_index,
        TransactionKind::Rekey,
    )
    .await
    .expect("reject rekey proposal by eoa");
    println!("✅ EOA member rejected rekey proposal");

    // Verify proposal is Rejected on-chain
    let proposal_account = client
        .get_account(&child_proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    match proposal.status {
        ProposalStatus::Rejected { .. } => {
            println!("✅ Rekey proposal status confirmed as Rejected")
        }
        _ => panic!("Expected rekey proposal to be Rejected"),
    }

    assert_eq!(
        proposal.rejected.len(),
        2,
        "two members should have rejected rekey"
    );
    assert!(
        proposal.rejected.contains(&fixture.parent_vaults[2]),
        "parent vault 2 should be in rejected list"
    );
    assert!(
        proposal.rejected.contains(&fixture.eoa_member),
        "EOA should be in rejected list"
    );

    println!("✅ Rekey rejection E2E test completed successfully!");
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_6_rekey_feature_gate_multisig() {
    let fixture = get_fixture().await;

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for rekey: {}",
        fixture.child_multisig
    );

    // Determine the next transaction index for the rekey proposal
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for rekey");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig for rekey");
    let proposal_index = child_ms.transaction_index + 1;

    // Ensure the rekey proposal exists. The CLI does not auto-schedule rekey, so we create it.
    let (child_proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index, None);
    if client.get_account(&child_proposal_pda).is_err() {
        // Use rekey_multisig_feature_gate to create the rekey proposal via parent[3] (skip EOA at index 1)
        rekey_multisig_feature_gate(
            &fixture.config,
            fixture.child_multisig,
            fixture.parent_multisigs[3],
            fixture.parent_key_paths[3].clone(),
            None,
        )
        .await
        .expect("create rekey proposal via parent multisig");

        println!(
            "✅ Rekey proposal created via parent multisig at index {} (via parent 4)",
            proposal_index
        );
    }

    // Approve using parent arrays (EOA at index 1)
    for i in 0..3 {
        let voter = fixture.parent_multisigs[i];
        let keypair_path = &fixture.parent_key_paths[i];

        approve_common_feature_gate_proposal(
            &fixture.config,
            fixture.child_multisig,
            voter,
            keypair_path.clone(),
            None,
            proposal_index,
            TransactionKind::Rekey,
        )
        .await
        .expect("approve rekey proposal");

        println!("✅ Approver {} approved rekey proposal", i + 1);
    }

    // Execute via parent 2 (skip EOA at index 1 and differ from proposer)
    let executor_multisig = fixture.parent_multisigs[2];

    execute_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        executor_multisig,
        fixture.parent_key_paths[2].clone(),
        None,
        proposal_index,
        TransactionKind::Rekey,
    )
    .await
    .expect("execute rekey proposal");

    println!("✅ Rekey executed");

    // After rekey, the child multisig should be bricked (config change). We assert the multisig PDA exists and is owned by Squads.
    let config_account = client
        .get_account(&fixture.child_multisig)
        .expect("multisig account should still exist");
    assert_eq!(
        config_account.owner, SQUADS_MULTISIG_PROGRAM_ID,
        "multisig should remain owned by Squads after rekey"
    );

    // The rekey config transaction should leave a single dummy member so the multisig is unusable.
    let mut account_data = &config_account.data[8..];
    let multisig: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut account_data).expect("deserialize multisig after rekey");
    assert_eq!(
        multisig.members.len(),
        1,
        "rekey should leave exactly one member"
    );
    assert_eq!(
        multisig.members[0].key,
        Pubkey::default(),
        "remaining member should be the default pubkey (dummy owner)"
    );

    println!("✅ Feature gate rekey E2E test completed successfully!");
}

/// Test 7: EOA approves and executes an activation proposal
/// This test creates a new child multisig with EOA-only members using the real CLI flow,
/// then EOAs approve and execute the pre-created activation proposal.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_7_eoa_activation_flow() {
    // Enable non-interactive mode
    std::env::set_var("E2E_TEST_MODE", "1");

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let temp_dir: PathBuf = std::env::temp_dir();

    // Create 3 EOA members for a new child multisig
    let mut eoa_keypaths = Vec::new();
    let mut eoa_pubkeys = Vec::new();

    for i in 0..3 {
        let eoa = Keypair::new();
        let sig = client
            .request_airdrop(&eoa.pubkey(), 10_000_000_000)
            .expect("request airdrop for eoa");
        client
            .confirm_transaction(&sig)
            .expect("confirm airdrop for eoa");

        let keypair_path = temp_dir.join(format!("eoa_test7_{}.json", i));
        let keypair_bytes: Vec<u8> = eoa.to_bytes().to_vec();
        std::fs::write(
            &keypair_path,
            serde_json::to_string(&keypair_bytes).unwrap(),
        )
        .expect("write eoa keypair");

        eoa_pubkeys.push(eoa.pubkey());
        eoa_keypaths.push(keypair_path.to_string_lossy().to_string());
    }

    // Use create_command_with_deployments like the real CLI - this creates multisig + initial activation proposal
    let mut config = Config {
        networks: vec![rpc_url()],
        threshold: 2,
        members: eoa_pubkeys.iter().map(|p| p.to_string()).collect(),
        fee_payer_path: Some(eoa_keypaths[0].clone()),
    };

    let deployments = create_command_with_deployments(
        &mut config,
        Some(2), // threshold
        vec![],
        Some(eoa_keypaths[0].clone()),
    )
    .await
    .expect("create feature gate via CLI");

    let deployment = deployments.get(0).expect("deployment should exist");
    let child_multisig = deployment.multisig_address;
    let child_vault = deployment.vault_address;

    println!("✅ Created EOA-only child multisig via CLI: {}", child_multisig);
    println!("   Vault (feature gate ID): {}", child_vault);
    println!("   Activation proposal pre-created at index 1");

    // Note: The setup keypair only has Initiate permission (not Vote), so no approvals yet.
    // We need 2 EOA approvals to meet threshold 2.

    // EOA[0] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[0],
        eoa_keypaths[0].clone(),
        None,
        1, // proposal index
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[0] approves activation");

    println!("✅ EOA[0] approved activation proposal (1/2)");

    // EOA[1] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        None,
        1, // proposal index
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[1] approves activation");

    println!("✅ EOA[1] approved activation proposal (2/2)");

    // Verify proposal is approved (2 approvals, threshold 2)
    let (proposal_pda, _) = get_proposal_pda(&child_multisig, 1, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    match proposal.status {
        ProposalStatus::Approved { .. } => {
            println!("✅ Proposal status: Approved");
        }
        _ => panic!("Expected proposal to be Approved"),
    }

    // EOA[1] executes the proposal
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        None,
        1,
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[1] executes activation");

    println!("✅ EOA[1] executed activation proposal");

    // Verify feature gate is activated
    let feature_account = client
        .get_account(&child_vault)
        .expect("feature gate account should exist");
    assert_eq!(
        feature_account.owner, FEATURE_GATE_PROGRAM_ID,
        "feature gate should be owned by Feature Gate program"
    );
    assert_eq!(
        feature_account.data.len(),
        FEATURE_ACCOUNT_SIZE,
        "feature gate account should have correct size"
    );

    // Verify threshold was lowered to 1
    let child_ms_account = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms.threshold, 1,
        "threshold should be lowered to 1 after activation"
    );

    println!("✅ EOA activation flow E2E test completed successfully!");
    println!("   Demonstrated: EOAs approve and execute activation (created via CLI)");
}

/// Test 8: EOA creates and executes a revocation proposal
/// Uses the same CLI flow as test 7 - creates multisig via create_command_with_deployments,
/// then activates, then creates and executes revocation.
#[tokio::test(flavor = "multi_thread")]
async fn rpc_e2e_8_eoa_revocation_flow() {
    // Enable non-interactive mode
    std::env::set_var("E2E_TEST_MODE", "1");

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let temp_dir: PathBuf = std::env::temp_dir();

    // Create 3 EOA members
    let mut eoa_keypaths = Vec::new();
    let mut eoa_pubkeys = Vec::new();

    for i in 0..3 {
        let eoa = Keypair::new();
        let sig = client
            .request_airdrop(&eoa.pubkey(), 10_000_000_000)
            .expect("request airdrop for eoa");
        client
            .confirm_transaction(&sig)
            .expect("confirm airdrop for eoa");

        let keypair_path = temp_dir.join(format!("eoa_test8_{}.json", i));
        let keypair_bytes: Vec<u8> = eoa.to_bytes().to_vec();
        std::fs::write(
            &keypair_path,
            serde_json::to_string(&keypair_bytes).unwrap(),
        )
        .expect("write eoa keypair");

        eoa_pubkeys.push(eoa.pubkey());
        eoa_keypaths.push(keypair_path.to_string_lossy().to_string());
    }

    // Use create_command_with_deployments like the real CLI - this creates multisig + initial activation proposal
    let mut config = Config {
        networks: vec![rpc_url()],
        threshold: 2,
        members: eoa_pubkeys.iter().map(|p| p.to_string()).collect(),
        fee_payer_path: Some(eoa_keypaths[0].clone()),
    };

    let deployments = create_command_with_deployments(
        &mut config,
        Some(2), // threshold
        vec![],
        Some(eoa_keypaths[0].clone()),
    )
    .await
    .expect("create feature gate via CLI");

    let deployment = deployments.get(0).expect("deployment should exist");
    let child_multisig = deployment.multisig_address;
    let child_vault = deployment.vault_address;

    println!("✅ Created EOA-only child multisig via CLI: {}", child_multisig);
    println!("   Vault (feature gate ID): {}", child_vault);

    // First, activate the feature gate (prerequisite for revocation)
    // Note: The setup keypair only has Initiate permission (not Vote), so no approvals yet.
    // We need 2 EOA approvals to meet threshold 2.

    // EOA[0] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[0],
        eoa_keypaths[0].clone(),
        None,
        1,
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[0] approves activation");

    // EOA[1] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        None,
        1,
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[1] approves activation");

    // EOA[1] executes the activation
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        None,
        1,
        TransactionKind::Activate,
    )
    .await
    .expect("EOA[1] executes activation");

    println!("✅ Feature gate activated (prerequisite for revocation)");

    // Verify threshold is now 1
    let child_ms_account = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(child_ms.threshold, 1, "threshold should be 1 after activation");

    let revocation_index = child_ms.transaction_index + 1;

    // EOA[2] creates revocation proposal (different from activation creator)
    create_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        None,
        TransactionKind::Revoke,
    )
    .await
    .expect("EOA[2] creates revocation proposal");

    println!("✅ EOA[2] created revocation proposal at index {}", revocation_index);

    // With threshold 1, a single approval should make the proposal approved
    // Note: Creating a proposal does NOT auto-approve it - we need to explicitly approve
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        None,
        revocation_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("EOA[2] approves revocation");

    println!("✅ EOA[2] approved revocation proposal (threshold is 1, so now approved)");

    // Verify the proposal is now approved
    let (proposal_pda, _) = get_proposal_pda(&child_multisig, revocation_index, None);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    match proposal.status {
        ProposalStatus::Approved { .. } => {
            println!("✅ Revocation proposal is Approved (1/1 approvals met threshold)");
        }
        _ => panic!("Expected proposal to be Approved after 1 approval with threshold 1"),
    }

    // EOA[2] executes the revocation
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        None,
        revocation_index,
        TransactionKind::Revoke,
    )
    .await
    .expect("EOA[2] executes revocation");

    println!("✅ EOA[2] executed revocation proposal");

    // Verify threshold was restored to 2
    let child_ms_final = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms_data: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_final.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms_data.threshold, 2,
        "threshold should be restored to 2 after revocation"
    );

    println!("✅ EOA revocation flow E2E test completed successfully!");
    println!("   Demonstrated: EOA creates, and executes revocation with threshold=1");
}
