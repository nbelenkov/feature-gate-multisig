//! RPC-based E2E tests against a running surfpool instance.
//! Run `surfpool start` first, which will load Squads BPF and start a local validator.

// unwrap/expect/panic are idiomatic in tests; the panic-prevention lints apply
// to production code only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn
)]

use std::env;
use std::path::PathBuf;

use borsh::BorshDeserialize;

use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;

use once_cell::sync::OnceCell;

use feature_gate_multisig_tool::commands::create::create_command_with_deployments;
use feature_gate_multisig_tool::commands::proposal::{
    proposal_command, ProposalCommand, ProposalCommandArgs,
};
use feature_gate_multisig_tool::commands::transaction_generation::{
    approve_common_feature_gate_proposal, create_feature_gate_proposal,
    execute_common_feature_gate_proposal, reject_common_feature_gate_proposal,
    rekey_multisig_feature_gate, TransactionKind,
};
use feature_gate_multisig_tool::commands::verify::verify_command;
use feature_gate_multisig_tool::feature_gate_program::{
    FEATURE_ACCOUNT_SIZE, FEATURE_GATE_PROGRAM_ID,
};
use feature_gate_multisig_tool::provision::{
    build_squads_transaction_message, create_execute_transaction_message, create_multisig,
    create_transaction_and_proposal_message, fetch_proposal, fetch_squads_multisig,
    fetch_vault_transaction, get_squads_account_data_with_retry, send_and_confirm_transaction,
};
use feature_gate_multisig_tool::squads::{
    get_proposal_pda, get_transaction_pda, get_vault_pda, ConfigAction, Member, Permissions,
    Proposal, ProposalStatus, PERMISSION_VOTE, SQUADS_MULTISIG_PROGRAM_ID,
};
use feature_gate_multisig_tool::utils::{load_signer, Config, ASSUME_YES_ENV};
use feature_gate_multisig_tool::verification::{
    is_autonomous, is_mainnet_cluster, is_rekeyed, verify_feature_gate, verify_squads_program,
    FeatureGateStatus,
};
use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;

fn rpc_url() -> String {
    env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string())
}

/// Non-interactive mode plus an isolated config dir, so test runs never read
/// or overwrite the real per-user config. Tests run with --test-threads=1, so
/// setting process-global env here is safe.
fn init_test_env() {
    std::env::set_var("E2E_TEST_MODE", "1");
    std::env::set_var(
        feature_gate_multisig_tool::utils::CONFIG_DIR_ENV,
        std::env::temp_dir().join("feature-gate-multisig-e2e-config"),
    );
}

fn full_permissions() -> Permissions {
    Permissions::all()
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

fn build_fixture() -> Fixture {
    init_test_env();
    std::env::set_var("RUST_LOG", "info");

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    // surfpool clones the Squads program from mainnet on startup; wait for it
    // before transacting, otherwise the first creations race the clone and fail.
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

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
            create_multisig(rpc_url(), &creator, &create_key, members, 1, None)
                .expect("create parent multisig");

        let vault_pda = get_vault_pda(&multisig_pda, 0).0;

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
        voting_key: None,
    };

    let deployments = create_command_with_deployments(
        &mut config,
        Some(3),
        Some(fee_payer_path.to_string_lossy().to_string()),
    )
    .expect("create feature gate via create_command");

    let deployment = deployments.first().expect("deployment result should exist");
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

fn get_fixture() -> &'static Fixture {
    FIXTURE.get_or_init(build_fixture)
}

/// Poll until `address` is readable, giving surfpool time to clone mainnet
/// accounts/programs on startup. Panics if it never appears.
fn wait_for_account(client: &RpcClient, address: &Pubkey) {
    for _ in 0..60 {
        if client.get_account(address).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("surfpool did not load account {address} within 30s");
}

/// Create three funded EOA members (keypair files under the temp dir with a
/// unique `prefix`) and deploy a fresh feature gate multisig with them via the
/// real CLI create flow, which pre-creates the activation proposal at index 1.
/// Returns (config, multisig, vault, eoa pubkeys, eoa keypair paths).
fn setup_eoa_multisig(
    client: &RpcClient,
    prefix: &str,
    threshold: u16,
) -> (Config, Pubkey, Pubkey, Vec<Pubkey>, Vec<String>) {
    let temp_dir: PathBuf = std::env::temp_dir();
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

        let keypair_path = temp_dir.join(format!("{}_{}.json", prefix, i));
        std::fs::write(
            &keypair_path,
            serde_json::to_string(&eoa.to_bytes().to_vec()).unwrap(),
        )
        .expect("write eoa keypair");

        eoa_pubkeys.push(eoa.pubkey());
        eoa_keypaths.push(keypair_path.to_string_lossy().to_string());
    }

    let mut config = Config {
        networks: vec![rpc_url()],
        threshold,
        members: eoa_pubkeys.iter().map(|p| p.to_string()).collect(),
        fee_payer_path: Some(eoa_keypaths[0].clone()),
        voting_key: None,
    };

    let deployments = create_command_with_deployments(
        &mut config,
        Some(threshold),
        Some(eoa_keypaths[0].clone()),
    )
    .expect("create feature gate via CLI");
    let deployment = deployments.first().expect("deployment should exist");
    (
        config,
        deployment.multisig_address,
        deployment.vault_address,
        eoa_pubkeys,
        eoa_keypaths,
    )
}

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_1_activate_feature_gate() {
    let fixture = get_fixture();

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
            proposal_index,
            TransactionKind::Activate,
        )
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
        proposal_index,
        TransactionKind::Activate,
    )
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
        child_ms_final.threshold, 3,
        "threshold should remain 3 after activation"
    );
}

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_2_revoke_feature_gate() {
    let fixture = get_fixture();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());

    println!(
        "✅ Using shared fixture child multisig for revoke: {}",
        fixture.child_multisig
    );
    println!("   Feature gate ID (vault): {}", fixture.child_vault);

    // Step 1: Verify activation did not change the threshold.
    println!("\nStep 1: Verify threshold remains 3 after activation");
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");

    assert_eq!(
        child_ms.threshold, 3,
        "threshold should remain 3 after activation"
    );
    println!("✅ Verified: Threshold remains 3");

    // Step 2: Create revocation proposal dynamically.
    println!("\nStep 2: Create revocation proposal");

    // Fetch current transaction index before creation
    let child_ms_account = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig for index");
    let child_ms_before: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    let revocation_index = child_ms_before.transaction_index + 1;

    // Create revocation proposal via parent multisig.
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        TransactionKind::Revoke,
    )
    .expect("create revoke proposal dynamically");

    println!(
        "✅ Revocation proposal created at index {}",
        revocation_index
    );

    // Debug: Verify proposal exists and check transaction_index
    println!("\n🐛 Debug: Verifying proposal exists after creation");

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

    let (vault_prop_pda, _) = get_proposal_pda(&fixture.child_multisig, revocation_index);

    if client.get_account(&vault_prop_pda).is_ok() {
        println!("✅ Vault proposal (Index {}) exists", revocation_index);
    } else {
        println!(
            "❌ Vault proposal (Index {}) does NOT exist!",
            revocation_index
        );
    }

    // Step 3: Approve revocation with enough approvals to meet the original threshold.
    println!("\nStep 3: Approve revocation with 3 approvals");

    approve_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("parent[0] approves revoke proposal");

    approve_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[1],
        fixture.parent_key_paths[1].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("EOA approves revoke proposal");

    approve_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[2],
        fixture.parent_key_paths[2].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("parent[2] approves revoke proposal");

    println!("✅ Revocation approved with 3 approvals!");

    // Verify the proposal is approved with the original threshold.
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, revocation_index);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    assert_eq!(
        proposal.approved.len(),
        3,
        "revocation proposal should have 3 approvals"
    );
    match proposal.status {
        ProposalStatus::Approved { timestamp: _ } => {
            println!("✅ Proposal status: Approved with 3 approvals");
        }
        _ => panic!("Expected proposal to be Approved"),
    }

    // Step 4: Execute the revocation.
    println!("\nStep 4: Execute revocation");

    execute_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("execute revoke proposal");

    println!("✅ Revocation executed!");

    // Verify threshold remains 3.
    let child_ms_final = client
        .get_account(&fixture.child_multisig)
        .expect("fetch child multisig");
    let child_ms_data: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_final.data[8..])
            .expect("deserialize child multisig");

    assert_eq!(
        child_ms_data.threshold, 3,
        "threshold should remain 3 after revocation execution"
    );
}

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_3_reject_activation() {
    let fixture = get_fixture();

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

    // Create a new activation proposal via parent[0]
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[0],
        fixture.parent_key_paths[0].clone(),
        TransactionKind::Activate,
    )
    .expect("create activation proposal for rejection");

    println!(
        "✅ Activation proposal created at index {} for rejection test",
        vault_proposal_index
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
        proposal_index,
        TransactionKind::Activate,
    )
    .expect("reject activation proposal by parent");
    println!("✅ Parent 1 rejected proposal");

    // EOA rejection
    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        proposal_index,
        TransactionKind::Activate,
    )
    .expect("reject activation proposal by eoa");
    println!("✅ EOA member rejected proposal");

    // Fetch the proposal account and verify it's in Rejected status
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index);
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

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_4_reject_revocation() {
    let fixture = get_fixture();

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

    // Create a new revocation proposal via parent[2] (skip EOA at index 1)
    create_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.parent_multisigs[2],
        fixture.parent_key_paths[2].clone(),
        TransactionKind::Revoke,
    )
    .expect("create revocation proposal for rejection");

    println!(
        "✅ Revocation proposal created at index {} for rejection test (via parent 3)",
        vault_proposal_index
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
        proposal_index,
        TransactionKind::Revoke,
    )
    .expect("reject revocation proposal by parent");
    println!("✅ Parent 1 rejected revocation proposal");

    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        proposal_index,
        TransactionKind::Revoke,
    )
    .expect("reject revocation proposal by eoa");
    println!("✅ EOA member rejected revocation proposal");

    // Fetch the proposal account and verify it's in Rejected status
    let (proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index);
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

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_5_reject_rekey() {
    let fixture = get_fixture();

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
    let (child_proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index);
    if client.get_account(&child_proposal_pda).is_err() {
        rekey_multisig_feature_gate(
            &fixture.config,
            fixture.child_multisig,
            fixture.parent_multisigs[0],
            fixture.parent_key_paths[0].clone(),
        )
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
        proposal_index,
        TransactionKind::Rekey,
    )
    .expect("reject rekey proposal by parent");
    println!("✅ Parent 2 rejected rekey proposal");

    // EOA rejection
    reject_common_feature_gate_proposal(
        &fixture.config,
        fixture.child_multisig,
        fixture.eoa_member,
        fixture.eoa_key_path.clone(),
        proposal_index,
        TransactionKind::Rekey,
    )
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

#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_6_rekey_feature_gate_multisig() {
    let fixture = get_fixture();

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
    let (child_proposal_pda, _) = get_proposal_pda(&fixture.child_multisig, proposal_index);
    if client.get_account(&child_proposal_pda).is_err() {
        // Use rekey_multisig_feature_gate to create the rekey proposal via parent[3] (skip EOA at index 1)
        rekey_multisig_feature_gate(
            &fixture.config,
            fixture.child_multisig,
            fixture.parent_multisigs[3],
            fixture.parent_key_paths[3].clone(),
        )
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
            proposal_index,
            TransactionKind::Rekey,
        )
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
        proposal_index,
        TransactionKind::Rekey,
    )
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
    assert!(
        is_rekeyed(&multisig),
        "rekey detection should flag the post-rekey state"
    );

    println!("✅ Feature gate rekey E2E test completed successfully!");
}

/// Test 7: EOA approves and executes an activation proposal
/// This test creates a new child multisig with EOA-only members using the real CLI flow,
/// then EOAs approve and execute the pre-created activation proposal.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_7_eoa_activation_flow() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let (config, child_multisig, child_vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test7", 2);

    println!(
        "✅ Created EOA-only child multisig via CLI: {}",
        child_multisig
    );
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
        1, // proposal index
        TransactionKind::Activate,
    )
    .expect("EOA[0] approves activation");

    println!("✅ EOA[0] approved activation proposal (1/2)");

    // EOA[1] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        1, // proposal index
        TransactionKind::Activate,
    )
    .expect("EOA[1] approves activation");

    println!("✅ EOA[1] approved activation proposal (2/2)");

    // Verify proposal is approved (2 approvals, threshold 2)
    let (proposal_pda, _) = get_proposal_pda(&child_multisig, 1);
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
        1,
        TransactionKind::Activate,
    )
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

    // Verify threshold stayed at its original value.
    let child_ms_account = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms.threshold, 2,
        "threshold should remain 2 after activation"
    );

    println!("✅ EOA activation flow E2E test completed successfully!");
    println!("   Demonstrated: EOAs approve and execute activation (created via CLI)");
}

/// Test 8: EOA creates and executes a revocation proposal
/// Uses the same CLI flow as test 7 - creates multisig via create_command_with_deployments,
/// then activates, then creates and executes revocation.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_8_eoa_revocation_flow() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let (config, child_multisig, child_vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test8", 2);

    println!(
        "✅ Created EOA-only child multisig via CLI: {}",
        child_multisig
    );
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
        1,
        TransactionKind::Activate,
    )
    .expect("EOA[0] approves activation");

    // EOA[1] approves the activation proposal
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        1,
        TransactionKind::Activate,
    )
    .expect("EOA[1] approves activation");

    // EOA[1] executes the activation
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        1,
        TransactionKind::Activate,
    )
    .expect("EOA[1] executes activation");

    println!("✅ Feature gate activated (prerequisite for revocation)");

    // Verify threshold stayed at its original value.
    let child_ms_account = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_account.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms.threshold, 2,
        "threshold should remain 2 after activation"
    );

    let revocation_index = child_ms.transaction_index + 1;

    // EOA[2] creates revocation proposal (different from activation creator)
    create_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        TransactionKind::Revoke,
    )
    .expect("EOA[2] creates revocation proposal");

    println!(
        "✅ EOA[2] created revocation proposal at index {}",
        revocation_index
    );

    // With threshold 2, two approvals are required.
    // Note: Creating a proposal does NOT auto-approve it - we need to explicitly approve
    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("EOA[2] approves revocation");

    approve_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[0],
        eoa_keypaths[0].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("EOA[0] approves revocation");

    println!("✅ Revocation proposal approved with 2 approvals");

    // Verify the proposal is now approved
    let (proposal_pda, _) = get_proposal_pda(&child_multisig, revocation_index);
    let proposal_account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    let proposal: Proposal = BorshDeserialize::deserialize(&mut &proposal_account.data[8..])
        .expect("deserialize proposal");

    match proposal.status {
        ProposalStatus::Approved { .. } => {
            println!("✅ Revocation proposal is Approved (2/2 approvals met threshold)");
        }
        _ => panic!("Expected proposal to be Approved after 2 approvals with threshold 2"),
    }

    // EOA[2] executes the revocation
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[2],
        eoa_keypaths[2].clone(),
        revocation_index,
        TransactionKind::Revoke,
    )
    .expect("EOA[2] executes revocation");

    println!("✅ EOA[2] executed revocation proposal");

    // Verify threshold remains 2.
    let child_ms_final = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let child_ms_data: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &child_ms_final.data[8..])
            .expect("deserialize child multisig");
    assert_eq!(
        child_ms_data.threshold, 2,
        "threshold should remain 2 after revocation"
    );

    println!("✅ EOA revocation flow E2E test completed successfully!");
    println!("   Demonstrated: EOA creates and executes revocation with the original threshold");
}

/// Test 9: Exercise the verification helpers against real on-chain state.
/// Covers the plumbing that unit tests can't: hashing the real cloned Squads
/// ELF, and classifying a feature account across a Fresh -> Pending transition.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_9_verify_checks() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    // Program authenticity: surfpool clones the frozen mainnet Squads program,
    // so the on-chain bytecode must match the vendored verified-build hash.
    let program = verify_squads_program(&client).expect("verify squads program");
    assert!(program.executable, "Squads program should be executable");
    assert!(
        program.loader_owner_ok,
        "Squads program should be owned by the upgradeable loader"
    );
    assert!(
        program.immutable,
        "cloned mainnet Squads program should be frozen"
    );
    assert!(
        program.hash_matches,
        "cloned Squads bytecode hash {} should match the vendored Squads v4 hash",
        program.on_chain_hash
    );
    println!("✅ Squads program authenticity verified against cloned mainnet bytecode");

    // Cluster detection: surfpool forks mainnet and reports mainnet's genesis
    // hash, so it classifies as mainnet. That is the intended semantic: the
    // genesis hash identifies the chain (mainnet forks carry mainnet state and
    // the real frozen Squads program), unlike the URL heuristic, which would
    // misread 127.0.0.1 as non-mainnet.
    let mainnet = is_mainnet_cluster(&client).expect("fetch genesis hash");
    assert!(
        mainnet,
        "surfpool forks mainnet, so it classifies as mainnet"
    );
    println!("✅ Genesis-hash cluster detection classifies the mainnet fork as mainnet");

    // Build an isolated EOA multisig so the feature-state transition is
    // deterministic and independent of the other tests.
    let (config, child_multisig, child_vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test9", 2);

    // Before execution the feature account (vault 0) is unallocated -> Fresh.
    let before = verify_feature_gate(&client, &child_multisig).expect("verify feature (fresh)");
    assert_eq!(
        before.status,
        FeatureGateStatus::Fresh,
        "feature should be Fresh before activation executes"
    );
    println!("✅ Feature gate classified Fresh before activation");

    // Owners/config: the tool always provisions autonomous, no-time-lock multisigs.
    let ms_account = client
        .get_account(&child_multisig)
        .expect("fetch child multisig");
    let ms: feature_gate_multisig_tool::squads::Multisig =
        BorshDeserialize::deserialize(&mut &ms_account.data[8..])
            .expect("deserialize child multisig");
    assert!(
        is_autonomous(&ms),
        "provisioned multisig should be autonomous"
    );
    assert_eq!(
        ms.time_lock, 0,
        "provisioned multisig should have no time lock"
    );
    assert_eq!(ms.threshold, 2);
    // The CLI adds an Initiate-only contributor at index 0 alongside the 3 EOA owners.
    assert_eq!(ms.members.len(), 4, "3 EOA owners + 1 contributor");
    let voting = ms
        .members
        .iter()
        .filter(|m| m.permissions.mask & PERMISSION_VOTE != 0)
        .count();
    assert_eq!(voting, 3, "the 3 EOA owners are the voting members");

    // Activate: two EOAs approve, one executes.
    for i in 0..2 {
        approve_common_feature_gate_proposal(
            &config,
            child_multisig,
            eoa_pubkeys[i],
            eoa_keypaths[i].clone(),
            1,
            TransactionKind::Activate,
        )
        .expect("EOA approves activation");
    }
    execute_common_feature_gate_proposal(
        &config,
        child_multisig,
        eoa_pubkeys[1],
        eoa_keypaths[1].clone(),
        1,
        TransactionKind::Activate,
    )
    .expect("EOA executes activation");

    // After execution the account is Feature-owned and queued -> Pending.
    let after = verify_feature_gate(&client, &child_multisig).expect("verify feature (pending)");
    assert_eq!(
        after.status,
        FeatureGateStatus::Pending,
        "feature should be Pending after activation executes"
    );
    assert!(
        after.rent_exempt,
        "activated feature account should be rent-exempt"
    );
    println!("✅ Feature gate classified Pending after activation; verify checks complete");

    // Pasting the feature gate account instead of the multisig must fail with
    // a hint that names the actual multisig (reverse lookup via the activation
    // transaction's account keys).
    let mut err = String::new();
    for _ in 0..30 {
        err = match fetch_squads_multisig(&client, &child_vault, "multisig") {
            Ok(_) => panic!("vault address must not pass as a multisig"),
            Err(e) => e.to_string(),
        };
        // The reverse lookup only sees rooted transactions; poll rather than
        // race the validator's rooting cadence.
        if err.contains(&child_multisig.to_string()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(
        err.contains("feature gate account"),
        "error should explain the mix-up: {err}"
    );
    assert!(
        err.contains(&child_multisig.to_string()),
        "error should name the multisig: {err}"
    );
    println!("✅ Wrong-address error names the multisig via reverse lookup");

    // Smoke test the full verify command end to end: the network loop, all three
    // display sections, and (skipped, single network) cross-network consistency.
    // The assertions above cover the logic; this catches wiring/display panics.
    verify_command(&config, Some(child_multisig))
        .expect("verify command should run cleanly against the activated multisig");
    println!("✅ verify command ran end to end");

    // The checks warn and continue so every problem shows at once; that must
    // not leave the command exiting 0 as though the multisig were verified.
    let unreachable = Config {
        networks: vec!["http://127.0.0.1:1".to_string()],
        ..config.clone()
    };
    let error = verify_command(&unreachable, Some(child_multisig))
        .expect_err("verify must fail when its checks cannot be completed");
    println!("✅ Refused with: {error}");
    assert!(
        error
            .to_string()
            .contains("has not been shown to be correct"),
        "error should say verification did not complete, got: {error}"
    );
}

/// Test 10: the non-interactive proposal subcommands drive a full feature gate
/// lifecycle end to end: approve + execute the pre-created activation, then
/// propose, approve, and execute a revocation.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_10_proposal_subcommands() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test10", 2);

    let args = |voter: usize, kind: TransactionKind, index: Option<u64>| ProposalCommandArgs {
        multisig,
        kind,
        voting_key: Some(eoa_pubkeys[voter]),
        keypair: Some(eoa_keypaths[voter].clone()),
        index,
    };

    // The create flow pre-creates the activation proposal at index 1.
    for voter in 0..2 {
        proposal_command(
            &config,
            ProposalCommand::Approve,
            args(voter, TransactionKind::Activate, Some(1)),
        )
        .expect("approve activation via subcommand");
    }
    proposal_command(
        &config,
        ProposalCommand::Execute,
        args(1, TransactionKind::Activate, Some(1)),
    )
    .expect("execute activation via subcommand");

    let activated = verify_feature_gate(&client, &multisig).expect("verify feature (pending)");
    assert_eq!(
        activated.status,
        FeatureGateStatus::Pending,
        "feature should be Pending after subcommand-driven activation"
    );

    // Revoke: propose (lands at index 2), approve to threshold, execute.
    proposal_command(
        &config,
        ProposalCommand::Propose,
        args(0, TransactionKind::Revoke, None),
    )
    .expect("propose revoke via subcommand");
    for voter in 0..2 {
        proposal_command(
            &config,
            ProposalCommand::Approve,
            args(voter, TransactionKind::Revoke, Some(2)),
        )
        .expect("approve revoke via subcommand");
    }
    proposal_command(
        &config,
        ProposalCommand::Execute,
        args(1, TransactionKind::Revoke, Some(2)),
    )
    .expect("execute revoke via subcommand");

    let reverted = verify_feature_gate(&client, &multisig).expect("verify feature (fresh)");
    assert_eq!(
        reverted.status,
        FeatureGateStatus::Fresh,
        "feature should be Fresh again after the subcommand-driven revoke"
    );
    println!("✅ proposal subcommands drove the full lifecycle end to end");
}

/// Test 11: Squads governance reads reject accounts the Squads program does not
/// own, so a discriminator alone cannot pass bytes off as governance data. The
/// feature gate account (vault 0) is a real account at a real address that is
/// never Squads-owned, which makes it the natural negative case.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_11_non_squads_accounts_are_rejected() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (_config, multisig, vault, _eoa_pubkeys, _eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test11", 2);

    // Fund the vault so it exists as a plain System-owned account.
    let airdrop = client
        .request_airdrop(&vault, 10_000_000)
        .expect("airdrop to vault");
    client
        .confirm_transaction(&airdrop)
        .expect("confirm vault airdrop");

    let error = get_squads_account_data_with_retry(&client, &vault)
        .expect_err("a non-Squads account must not be readable as governance data");
    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("not owned by the Squads program"),
        "error should name the ownership failure, got: {message}"
    );

    // And the multisig itself still reads fine, so the check is not blanket.
    let state = fetch_squads_multisig(&client, &multisig, "multisig")
        .expect("the real multisig must still be readable");
    assert!(
        !state.members.is_empty(),
        "the multisig should have members"
    );
    println!("✅ Ownership check rejects foreign accounts and admits the real multisig");
}

/// Create a real Squads vault proposal at the multisig's next index carrying
/// `instructions`, signed by the member at `keypair_path`. Used to plant
/// transactions this tool would never build, so the classifier and the guards
/// around it can be tested against genuine on-chain accounts.
fn propose_raw_vault_transaction(
    client: &RpcClient,
    multisig: &Pubkey,
    vault: &Pubkey,
    keypair_path: &str,
    instructions: &[solana_instruction::Instruction],
) -> u64 {
    let signer = load_signer(keypair_path, "proposer").expect("load proposer keypair");
    let state = fetch_squads_multisig(client, multisig, "multisig").expect("fetch multisig");
    let index = state.transaction_index + 1;

    let inner = build_squads_transaction_message(vault, instructions, &[])
        .expect("compile inner vault message");
    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let (message, _tx_pda, _proposal_pda) = create_transaction_and_proposal_message(
        &signer.pubkey(),
        &signer.pubkey(),
        multisig,
        index,
        0,
        inner,
        None,
        None,
        blockhash,
    )
    .expect("build create-transaction-and-proposal message");
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&*signer]).expect("sign");
    send_and_confirm_transaction(&transaction, client).expect("create raw vault proposal");
    index
}

/// Run `body` with the confirmation layer behaving as it does under `--yes`
/// rather than under E2E auto-confirm, then restore E2E mode.
///
/// `confirm_action` short-circuits to `true` when `E2E_TEST_MODE` is set, which
/// is what lets the other tests drive prompts unattended - but it also bypasses
/// the safety gates entirely. Exercising a gate therefore means standing in the
/// shoes of a real `--yes` operator. Tests run with `--test-threads=1`, so
/// swapping process-global env here is safe.
fn with_assume_yes<T>(body: impl FnOnce() -> T) -> T {
    std::env::remove_var("E2E_TEST_MODE");
    std::env::set_var(ASSUME_YES_ENV, "1");
    let result = body();
    std::env::remove_var(ASSUME_YES_ENV);
    std::env::set_var("E2E_TEST_MODE", "1");
    result
}

fn proposal_at(client: &RpcClient, multisig: &Pubkey, index: u64) -> Proposal {
    let (proposal_pda, _) = get_proposal_pda(multisig, index);
    let account = client
        .get_account(&proposal_pda)
        .expect("proposal account should exist");
    BorshDeserialize::deserialize(&mut &account.data[8..]).expect("deserialize proposal")
}

/// Test 12: a genuine Squads vault proposal this tool did not build - a plain
/// System transfer draining the feature gate vault - must not be actionable as
/// an activation.
///
/// This is the look-alike the byte-exact classifier exists for: every program id
/// in the message is the System program, which a program-id-only classifier
/// labelled `Activate`. It must classify as an unrecognized vault transaction,
/// and `--yes` must refuse to stand in for the operator's decision about it.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_12_system_lookalike_is_not_actionable_as_activate() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test12", 2);

    // Fund the vault so the proposed transfer is actually payable; the point is
    // that the tool refuses to act on it, not that it would fail on-chain.
    let airdrop = client
        .request_airdrop(&vault, 100_000_000)
        .expect("airdrop to vault");
    client
        .confirm_transaction(&airdrop)
        .expect("confirm vault airdrop");

    let destination = Keypair::new().pubkey();
    let index = propose_raw_vault_transaction(
        &client,
        &multisig,
        &vault,
        &eoa_keypaths[0],
        &[solana_system_interface::instruction::transfer(
            &vault,
            &destination,
            1_000_000,
        )],
    );
    println!("✅ Planted an all-System vault proposal at index {index}");

    let approve_as_activate = |voter: usize| {
        proposal_command(
            &config,
            ProposalCommand::Approve,
            ProposalCommandArgs {
                multisig,
                kind: TransactionKind::Activate,
                voting_key: Some(eoa_pubkeys[voter]),
                keypair: Some(eoa_keypaths[voter].clone()),
                index: Some(index),
            },
        )
    };

    // Under `--yes`, the unverified-proposal gate resolves to its `false`
    // default and the action aborts instead of being force-approved.
    let error = with_assume_yes(|| approve_as_activate(0).expect_err("approve must be refused"));
    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("not verified") || message.contains("could not be verified"),
        "error should say the proposal was not verified, got: {message}"
    );
    // Had it been mistaken for a recognized kind, the refusal would have been the
    // kind-mismatch error instead - or there would have been no refusal at all.
    assert!(
        !message.contains("Refusing to act on a different transaction"),
        "the look-alike should be unrecognized, not classified as another kind, got: {message}"
    );

    // Nothing was signed: the proposal carries no approvals.
    let proposal = proposal_at(&client, &multisig, index);
    assert!(
        proposal.approved.is_empty(),
        "no approval should have landed, got {:?}",
        proposal.approved
    );
    assert!(
        matches!(proposal.status, ProposalStatus::Active { .. }),
        "proposal should still be Active"
    );
    println!("✅ All-System look-alike was refused and left unapproved");
}

/// Test 13: a proposal whose transaction account cannot be read establishes
/// nothing, so it is refused outright rather than warned about. Unlike the
/// unrecognized case this is not a decision the operator can be offered - there
/// is no information to decide from - so E2E auto-confirm does not bypass it.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_13_unreadable_proposal_is_refused() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test13", 2);

    // No transaction account exists at this index.
    let missing_index = 9_999;
    let error = proposal_command(
        &config,
        ProposalCommand::Approve,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Activate,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: Some(missing_index),
        },
    )
    .expect_err("an unreadable proposal must be refused");

    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("could not be verified"),
        "error should name the verification failure, got: {message}"
    );
    println!("✅ Unreadable proposal was refused without prompting");
}

/// Test 14: the pre-created activation at index 1 must not be actionable as a
/// revocation. A recognized kind that differs from the requested one is a hard
/// error, and no signature may land.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_14_kind_mismatch_is_refused() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test14", 2);

    // The create flow pre-creates the activation proposal at index 1.
    let error = proposal_command(
        &config,
        ProposalCommand::Approve,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Revoke,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: Some(1),
        },
    )
    .expect_err("approving an activation as a revocation must be refused");

    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("Refusing to act on a different transaction"),
        "error should be the kind-mismatch refusal, got: {message}"
    );
    assert!(
        message.contains("Activate") && message.contains("Revoke"),
        "error should name both the on-chain and requested kinds, got: {message}"
    );

    let proposal = proposal_at(&client, &multisig, 1);
    assert!(
        proposal.approved.is_empty(),
        "no approval should have landed on the mismatched proposal, got {:?}",
        proposal.approved
    );

    // The same proposal approves fine as what it actually is.
    proposal_command(
        &config,
        ProposalCommand::Approve,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Activate,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: Some(1),
        },
    )
    .expect("approving it as an activation should succeed");
    let proposal = proposal_at(&client, &multisig, 1);
    assert_eq!(
        proposal.approved,
        vec![eoa_pubkeys[0]],
        "the correctly-labelled approval should have landed"
    );
    println!("✅ Mismatched kind refused; correct kind accepted");
}

// --- Substituting RPC proxy -------------------------------------------------
//
// The account-identity checks only fire when an endpoint returns data that is
// genuine but belongs to a different account, so they cannot be reached by any
// test that talks to an honest validator. These tests put a proxy in front of
// surfpool that answers `getAccountInfo(<from>)` with the chain's own data for
// `<to>`.
//
// The substitution rewrites the *request* rather than the response: the
// validator still encodes the bytes, so the forged reply is real, correctly
// owned, correctly discriminated Squads data that simply belongs to another
// account. That is precisely the threat being modelled, and it keeps base64 and
// hand-built account bodies out of the test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

struct SubstitutingRpcProxy {
    url: String,
    shutdown: Arc<AtomicBool>,
    substitutions: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SubstitutingRpcProxy {
    fn start(from: Pubkey, to: Pubkey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        listener
            .set_nonblocking(true)
            .expect("set proxy non-blocking");

        let shutdown = Arc::new(AtomicBool::new(false));
        let substitutions = Arc::new(AtomicUsize::new(0));
        let backend = rpc_url()
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();

        let stop = Arc::clone(&shutdown);
        let count = Arc::clone(&substitutions);
        let thread = std::thread::spawn(move || {
            let from = from.to_string();
            let to = to.to_string();
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (backend, from, to, count) = (
                            backend.clone(),
                            from.clone(),
                            to.clone(),
                            Arc::clone(&count),
                        );
                        std::thread::spawn(move || {
                            proxy_one_request(stream, &backend, &from, &to, &count);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            url: format!("http://127.0.0.1:{port}"),
            shutdown,
            substitutions,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn substitutions(&self) -> usize {
        self.substitutions.load(Ordering::Relaxed)
    }
}

impl Drop for SubstitutingRpcProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read one HTTP request, returning its body. Handles a body split across reads.
fn read_http_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let length: usize = String::from_utf8_lossy(&buf[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < header_end + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Some(buf[header_end..].to_vec())
}

/// Swap the queried pubkey when the request is `getAccountInfo(<from>)`.
fn substitute_account_query(body: &[u8], from: &str, to: &str, count: &AtomicUsize) -> Vec<u8> {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    if json.get("method").and_then(|m| m.as_str()) != Some("getAccountInfo") {
        return body.to_vec();
    }
    let Some(target) = json
        .get_mut("params")
        .and_then(|p| p.get_mut(0))
        .filter(|t| t.as_str() == Some(from))
    else {
        return body.to_vec();
    };
    *target = serde_json::Value::String(to.to_string());
    count.fetch_add(1, Ordering::Relaxed);
    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

fn proxy_one_request(
    mut client: TcpStream,
    backend: &str,
    from: &str,
    to: &str,
    count: &AtomicUsize,
) {
    let Some(body) = read_http_body(&mut client) else {
        return;
    };
    let body = substitute_account_query(&body, from, to, count);

    let Ok(mut upstream) = TcpStream::connect(backend) else {
        return;
    };
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {backend}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if upstream.write_all(request.as_bytes()).is_err() || upstream.write_all(&body).is_err() {
        return;
    }
    let mut response = Vec::new();
    if upstream.read_to_end(&mut response).is_ok() {
        let _ = client.write_all(&response);
    }
}

/// Test 15: a multisig account body is only trustworthy at the address it
/// derives to. An endpoint that answers with a real, correctly owned, correctly
/// discriminated multisig belonging to a *different* create_key must be
/// rejected, because its member set and threshold are what the rekey classifier,
/// the permission checks, and the quorum math all read as ground truth.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_15_multisig_body_from_another_address_is_rejected() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test15", 2);

    // A second, unrelated multisig whose account is served in place of the first.
    let impostor_creator = Keypair::new();
    let sig = client
        .request_airdrop(&impostor_creator.pubkey(), 10_000_000_000)
        .expect("airdrop impostor creator");
    client.confirm_transaction(&sig).expect("confirm airdrop");
    let (impostor, _) = create_multisig(
        rpc_url(),
        &impostor_creator,
        &Keypair::new(),
        vec![Member {
            key: impostor_creator.pubkey(),
            permissions: full_permissions(),
        }],
        1,
        None,
    )
    .expect("create impostor multisig");
    assert_ne!(multisig, impostor);

    let proxy = SubstitutingRpcProxy::start(multisig, impostor);
    let proxied = RpcClient::new_with_commitment(proxy.url(), CommitmentConfig::confirmed());

    // The forged reply is genuine Squads data - it simply belongs elsewhere.
    let message = match fetch_squads_multisig(&proxied, &multisig, "multisig") {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a body that does not derive to this address must be rejected"),
    };
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("does not match the account it was read from"),
        "error should name the derivation mismatch, got: {message}"
    );
    assert!(
        proxy.substitutions() > 0,
        "the proxy never substituted, so the check was not actually exercised"
    );

    // And the whole action path refuses rather than acting on the wrong members.
    let proxied_config = Config {
        networks: vec![proxy.url()],
        ..config.clone()
    };
    let action = proposal_command(
        &proxied_config,
        ProposalCommand::Approve,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Activate,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: Some(1),
        },
    );
    assert!(
        action.is_err(),
        "the action path must refuse a substituted multisig"
    );

    let proposal = proposal_at(&client, &multisig, 1);
    assert!(
        proposal.approved.is_empty(),
        "no approval should have landed, got {:?}",
        proposal.approved
    );
    println!("✅ Substituted multisig body rejected end to end");
}

/// Test 16: a transaction account must record the multisig and index it was
/// read for. Serving proposal 2's transaction when proposal 1 is requested
/// would otherwise let a signer approve the activation at index 1 while the
/// tool describes it as the revocation at index 2 - the label and the vote
/// pointing at different transactions.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_16_transaction_from_another_index_is_rejected() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test16", 2);

    // Index 1 is the pre-created activation; add a revocation at index 2.
    proposal_command(
        &config,
        ProposalCommand::Propose,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Revoke,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: None,
        },
    )
    .expect("propose revoke at index 2");

    let (activation_tx, _) = get_transaction_pda(&multisig, 1);
    let (revocation_tx, _) = get_transaction_pda(&multisig, 2);
    let proxy = SubstitutingRpcProxy::start(activation_tx, revocation_tx);

    // Asking to approve index 1 as a revocation: without the identity binding
    // the substituted body classifies as Revoke, matches the requested kind, and
    // the vote lands on the *activation* proposal.
    let proxied_config = Config {
        networks: vec![proxy.url()],
        ..config.clone()
    };
    let error = proposal_command(
        &proxied_config,
        ProposalCommand::Approve,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Revoke,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: Some(1),
        },
    )
    .expect_err("a transaction recorded at another index must be refused");

    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("could not be verified"),
        "error should be the unverifiable refusal, got: {message}"
    );
    assert!(
        proxy.substitutions() > 0,
        "the proxy never substituted, so the check was not actually exercised"
    );

    let proposal = proposal_at(&client, &multisig, 1);
    assert!(
        proposal.approved.is_empty(),
        "no approval should have landed on the activation, got {:?}",
        proposal.approved
    );
    println!("✅ Substituted transaction body rejected end to end");
}

/// Test 17: a canonical rekey adds an unsignable member, drops the threshold to
/// 1, and removes everyone who can sign. Authorizing that is irreversible, so
/// `--yes` must not stand in for the decision - and must not exit 0 having
/// silently done nothing, which would read as success to a script.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_17_rekey_is_not_authorized_by_assume_yes() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test17", 2);

    // Index 1 is the pre-created activation; the rekey lands at index 2.
    proposal_command(
        &config,
        ProposalCommand::Propose,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Rekey,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: None,
        },
    )
    .expect("propose rekey at index 2");

    let approve_rekey = || {
        proposal_command(
            &config,
            ProposalCommand::Approve,
            ProposalCommandArgs {
                multisig,
                kind: TransactionKind::Rekey,
                voting_key: Some(eoa_pubkeys[0]),
                keypair: Some(eoa_keypaths[0].clone()),
                index: Some(2),
            },
        )
    };

    let error = with_assume_yes(|| approve_rekey().expect_err("--yes must not authorize a rekey"));
    let message = error.to_string();
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("--yes"),
        "the error should explain that --yes cannot authorize this, got: {message}"
    );

    let proposal = proposal_at(&client, &multisig, 2);
    assert!(
        proposal.approved.is_empty(),
        "no rekey approval should have landed, got {:?}",
        proposal.approved
    );

    // An operator who does decide is still able to approve it.
    approve_rekey().expect("an explicit approval should still work");
    let proposal = proposal_at(&client, &multisig, 2);
    assert_eq!(
        proposal.approved,
        vec![eoa_pubkeys[0]],
        "the explicit approval should have landed"
    );
    println!("✅ Rekey refused under --yes, accepted on an explicit decision");
}

/// Plant a real Squads ConfigTransaction (plus its proposal) at the multisig's
/// next index, signed by the member at `keypair_path`. Models a member using an
/// out-of-band Squads client to propose a membership change.
fn propose_raw_config_transaction(
    client: &RpcClient,
    multisig: &Pubkey,
    keypair_path: &str,
    actions: Vec<ConfigAction>,
) -> u64 {
    use feature_gate_multisig_tool::squads::{
        ConfigTransactionCreateArgs, ConfigTransactionCreateData, InstructionData,
        MultisigCreateProposalAccounts, MultisigCreateProposalArgs, MultisigCreateProposalData,
    };

    let signer = load_signer(keypair_path, "proposer").expect("load proposer keypair");
    let state = fetch_squads_multisig(client, multisig, "multisig").expect("fetch multisig");
    let index = state.transaction_index + 1;
    let (transaction_pda, _) = get_transaction_pda(multisig, index);
    let (proposal_pda, _) = get_proposal_pda(multisig, index);

    let create = solana_instruction::Instruction::new_with_bytes(
        SQUADS_MULTISIG_PROGRAM_ID,
        &ConfigTransactionCreateData {
            args: ConfigTransactionCreateArgs {
                actions,
                memo: None,
            },
        }
        .data()
        .expect("serialize config create"),
        vec![
            solana_instruction::AccountMeta::new(*multisig, false),
            solana_instruction::AccountMeta::new(transaction_pda, false),
            solana_instruction::AccountMeta::new_readonly(signer.pubkey(), true),
            solana_instruction::AccountMeta::new(signer.pubkey(), true),
            solana_instruction::AccountMeta::new_readonly(
                solana_system_interface::program::ID,
                false,
            ),
        ],
    );
    let propose = solana_instruction::Instruction::new_with_bytes(
        SQUADS_MULTISIG_PROGRAM_ID,
        &MultisigCreateProposalData {
            args: MultisigCreateProposalArgs {
                transaction_index: index,
                is_draft: false,
            },
        }
        .data()
        .expect("serialize proposal create"),
        MultisigCreateProposalAccounts {
            multisig: *multisig,
            proposal: proposal_pda,
            creator: signer.pubkey(),
            rent_payer: signer.pubkey(),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(),
    );

    let message = solana_message::v0::Message::try_compile(
        &signer.pubkey(),
        &[create, propose],
        &[],
        client.get_latest_blockhash().expect("blockhash"),
    )
    .expect("compile config create");
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&*signer]).expect("sign");
    send_and_confirm_transaction(&transaction, client).expect("create config proposal");
    index
}

/// Test 18: a config transaction can rewrite membership; a vault transaction
/// cannot touch governance. Naming a config transaction `--kind activate` must
/// not let it be approved as a routine vault send with its actions unseen.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_18_config_change_is_not_approvable_as_a_vault_transaction() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test18", 2);

    // A member proposes adding an attacker key with full permissions - a
    // governance rewrite, not the canonical rekey.
    let attacker = Keypair::new().pubkey();
    let index = propose_raw_config_transaction(
        &client,
        &multisig,
        &eoa_keypaths[0],
        vec![ConfigAction::AddMember {
            new_member: Member {
                key: attacker,
                permissions: Permissions::all(),
            },
        }],
    );
    println!("✅ Planted an AddMember config proposal at index {index}");

    // Under `--yes`, approving it as an activation must not go through: the
    // unverified-proposal gate resolves to its false default and aborts.
    let error = with_assume_yes(|| {
        proposal_command(
            &config,
            ProposalCommand::Approve,
            ProposalCommandArgs {
                multisig,
                kind: TransactionKind::Activate,
                voting_key: Some(eoa_pubkeys[0]),
                keypair: Some(eoa_keypaths[0].clone()),
                index: Some(index),
            },
        )
        .expect_err("a config change must not be approvable as an activation under --yes")
    });
    let message = error.to_string();
    println!("✅ Refused with: {message}");

    // The refusal has to name it as a config change. "Vault transaction" was the
    // old label and implies it cannot alter governance at all.
    assert!(
        message.contains("Config change"),
        "the refusal must name it as a config change, got: {message}"
    );
    assert!(
        !message.contains("Vault transaction"),
        "a config change must not be labelled a vault transaction, got: {message}"
    );

    let proposal = proposal_at(&client, &multisig, index);
    assert!(
        proposal.approved.is_empty(),
        "no approval should have landed on the config change, got {:?}",
        proposal.approved
    );

    // The attacker is not a member.
    let state = fetch_squads_multisig(&client, &multisig, "multisig").expect("refetch multisig");
    assert!(
        !state.members.iter().any(|m| m.key == attacker),
        "attacker must not have been added"
    );
    println!("✅ Config change refused and left unapproved");
}

/// Test 19: the reads that shape a signed execute instruction, and the ones that
/// decide what a signer is shown, must reject a record belonging to a different
/// index. Both are reachable only through an endpoint that answers with genuine
/// data for the wrong account, so both go through the substituting proxy.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_19_execute_and_listing_reads_reject_substituted_records() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let (config, multisig, _vault, eoa_pubkeys, eoa_keypaths) =
        setup_eoa_multisig(&client, "eoa_test19", 2);

    // Index 1 is the pre-created activation; add a revocation at index 2 so
    // there are two genuine records to swap between.
    proposal_command(
        &config,
        ProposalCommand::Propose,
        ProposalCommandArgs {
            multisig,
            kind: TransactionKind::Revoke,
            voting_key: Some(eoa_pubkeys[0]),
            keypair: Some(eoa_keypaths[0].clone()),
            index: None,
        },
    )
    .expect("propose revoke at index 2");

    // --- the execute path's transaction read ---
    let (tx_one, _) = get_transaction_pda(&multisig, 1);
    let (tx_two, _) = get_transaction_pda(&multisig, 2);
    {
        let proxy = SubstitutingRpcProxy::start(tx_one, tx_two);
        let proxied = RpcClient::new_with_commitment(proxy.url(), CommitmentConfig::confirmed());

        let message = match fetch_vault_transaction(&proxied, &multisig, 1) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a vault transaction from another index must be rejected"),
        };
        println!("✅ Refused with: {message}");
        assert!(
            message.contains("Refusing to build an instruction from it"),
            "error should name the binding failure, got: {message}"
        );
        assert!(
            proxy.substitutions() > 0,
            "the proxy never substituted, so the check was not exercised"
        );

        // And the instruction builder that consumes it refuses too, rather than
        // signing an account list the endpoint chose.
        let blockhash = client.get_latest_blockhash().expect("blockhash");
        assert!(
            create_execute_transaction_message(
                &multisig,
                &eoa_pubkeys[0],
                &eoa_pubkeys[0],
                1,
                &proxied,
                blockhash,
            )
            .is_err(),
            "the execute message builder must refuse a substituted transaction"
        );
    }

    // --- the listing/status read ---
    let (proposal_one, _) = get_proposal_pda(&multisig, 1);
    let (proposal_two, _) = get_proposal_pda(&multisig, 2);
    let proxy = SubstitutingRpcProxy::start(proposal_one, proposal_two);
    let proxied = RpcClient::new_with_commitment(proxy.url(), CommitmentConfig::confirmed());

    let message = match fetch_proposal(&proxied, &multisig, 1) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a proposal record from another index must be rejected"),
    };
    println!("✅ Refused with: {message}");
    assert!(
        message.contains("Refusing to trust its status or vote counts"),
        "error should name the binding failure, got: {message}"
    );
    assert!(
        proxy.substitutions() > 0,
        "the proxy never substituted, so the check was not exercised"
    );

    // The genuine records still read fine, so the check is not blanket.
    assert_eq!(
        fetch_proposal(&client, &multisig, 1)
            .expect("real proposal 1 must read")
            .transaction_index,
        1
    );
    assert_eq!(
        fetch_vault_transaction(&client, &multisig, 1)
            .expect("real transaction 1 must read")
            .index,
        1
    );
    println!("✅ Substituted execute and listing records rejected");
}

/// Create a Squads multisig with a non-default `config_authority`, which the CLI
/// itself never does (`create_multisig` hardcodes `None`). That authority can
/// rewrite members and threshold unilaterally, so the owner list is not binding.
fn create_multisig_with_config_authority(
    client: &RpcClient,
    creator: &Keypair,
    authority: Pubkey,
) -> Pubkey {
    use feature_gate_multisig_tool::squads::{
        deserialize_squads_account, get_multisig_pda, get_program_config_pda, InstructionData,
        MultisigCreateArgsV2, MultisigCreateV2Accounts, MultisigCreateV2Data, ProgramConfig,
        PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR,
    };

    let create_key = Keypair::new();
    let (multisig, _) = get_multisig_pda(&create_key.pubkey());
    let (program_config, _) = get_program_config_pda();
    let config_account = client
        .get_account(&program_config)
        .expect("read Squads program config");
    let parsed: ProgramConfig = deserialize_squads_account(
        &config_account.data,
        PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR,
        "program config",
    )
    .expect("decode program config");

    let instruction = solana_instruction::Instruction {
        program_id: SQUADS_MULTISIG_PROGRAM_ID,
        accounts: MultisigCreateV2Accounts {
            create_key: create_key.pubkey(),
            creator: creator.pubkey(),
            multisig,
            system_program: solana_system_interface::program::ID,
            program_config,
            treasury: parsed.treasury,
        }
        .to_account_metas(),
        data: MultisigCreateV2Data {
            args: MultisigCreateArgsV2 {
                config_authority: Some(authority),
                threshold: 1,
                members: vec![Member {
                    key: creator.pubkey(),
                    permissions: Permissions::all(),
                }],
                time_lock: 0,
                rent_collector: None,
                memo: None,
            },
        }
        .data()
        .expect("serialize create args"),
    };

    let message = solana_message::v0::Message::try_compile(
        &creator.pubkey(),
        &[instruction],
        &[],
        client.get_latest_blockhash().expect("blockhash"),
    )
    .expect("compile create");
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[creator, &create_key])
            .expect("sign create");
    send_and_confirm_transaction(&transaction, client).expect("create multisig with authority");
    multisig
}

/// Test 20: `verify` must fail when a check runs and reports a problem, not only
/// when a check cannot run. A multisig whose config authority can rewrite members
/// and threshold at will is the case a runbook gate would otherwise wave through.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_20_verify_fails_on_a_non_autonomous_multisig() {
    init_test_env();

    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    wait_for_account(&client, &SQUADS_MULTISIG_PROGRAM_ID);

    let creator = Keypair::new();
    let airdrop = client
        .request_airdrop(&creator.pubkey(), 10_000_000_000)
        .expect("airdrop creator");
    client.confirm_transaction(&airdrop).expect("confirm");

    let attacker_authority = Keypair::new().pubkey();
    let multisig = create_multisig_with_config_authority(&client, &creator, attacker_authority);
    println!("✅ Created a multisig with config authority {attacker_authority}");

    let config = Config {
        networks: vec![rpc_url()],
        threshold: 1,
        members: vec![creator.pubkey().to_string()],
        fee_payer_path: None,
        voting_key: None,
    };

    // Every read succeeds here - the program is authentic, the feature account is
    // Fresh, the multisig is readable. The only negative is the autonomy check,
    // which previously printed a warning and exited 0.
    let error = verify_command(&config, Some(multisig))
        .expect_err("verify must fail when a check reports a problem");
    println!("✅ Refused with: {error}");
    assert!(
        error
            .to_string()
            .contains("has not been shown to be correct"),
        "error should be the verification failure, got: {error}"
    );

    // An autonomous multisig on the same cluster still verifies cleanly, so the
    // failure is the authority and not something incidental.
    let (autonomous_config, autonomous, _vault, _pubkeys, _paths) =
        setup_eoa_multisig(&client, "eoa_test20", 2);
    verify_command(&autonomous_config, Some(autonomous))
        .expect("an autonomous multisig must still verify cleanly");
    println!("✅ Non-autonomous multisig fails verification; autonomous one passes");
}

/// Test 21: `verify` must fail when the on-chain voting members differ from
/// the expected set (the configured member list when nothing is vendored),
/// and when there is no expected set at all.
#[test]
#[ignore = "requires a running surfpool validator; run via make test-surfpool"]
fn rpc_e2e_21_verify_fails_when_members_differ_from_expectation() {
    init_test_env();
    let client = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let (config, multisig, _vault, _pubkeys, _paths) = setup_eoa_multisig(&client, "eoa_test21", 2);

    verify_command(&config, Some(multisig))
        .expect("verify should pass when the configured members match the chain");
    println!("✅ Matching member set verifies cleanly");

    // Swap one expected signer for a stranger: verify must fail.
    let mut tampered = config.clone();
    tampered.members[0] = Pubkey::new_unique().to_string();
    let error = verify_command(&tampered, Some(multisig))
        .expect_err("verify must fail when the on-chain owners are not the expected ones");
    assert!(
        error
            .to_string()
            .contains("has not been shown to be correct"),
        "error should be the verification failure, got: {error}"
    );
    println!("✅ Refused a member set that differs from the expectation: {error}");

    // No expectation at all is not a pass either: nothing was checked.
    let no_expectation = Config {
        members: Vec::new(),
        ..config.clone()
    };
    let unchecked = verify_command(&no_expectation, Some(multisig))
        .expect_err("verify must refuse when there is no expected signer set on mainnet");
    assert!(
        unchecked
            .to_string()
            .contains("has not been shown to be correct"),
        "error should be the verification failure, got: {unchecked}"
    );
    println!("✅ Refused when there was no expected signer set to check against");
}
