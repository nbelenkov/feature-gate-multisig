use super::*;
use crate::squads::{CompiledInstruction, InstructionData, SmallVec, TransactionMessage};
use borsh::BorshDeserialize;

fn create_test_transaction_message() -> TransactionMessage {
    use crate::feature_gate_program::create_feature_activation;

    // Create feature activation instructions for a test feature
    let feature_id = Pubkey::new_unique();
    let funding_address = Pubkey::new_unique();
    let instructions = create_feature_activation(&feature_id, &funding_address);

    // Build account keys list for the message
    let mut account_keys = vec![
        funding_address,                      // 0: Funding address (signer, writable)
        feature_id,                           // 1: Feature account (writable)
        solana_system_interface::program::ID, // 2: System program
        crate::feature_gate_program::FEATURE_GATE_PROGRAM_ID, // 3: Feature gate program
    ];

    // Compile instructions into MultisigCompiledInstructions
    let mut compiled_instructions = Vec::new();

    for instruction in instructions {
        // Find program_id index in account_keys
        let program_id_index = account_keys
            .iter()
            .position(|key| *key == instruction.program_id)
            .unwrap_or_else(|| {
                account_keys.push(instruction.program_id);
                account_keys.len() - 1
            }) as u8;

        // Map account pubkeys to indices
        let account_indexes: Vec<u8> = instruction
            .accounts
            .iter()
            .map(|account_meta| {
                account_keys
                    .iter()
                    .position(|key| *key == account_meta.pubkey)
                    .unwrap_or_else(|| {
                        account_keys.push(account_meta.pubkey);
                        account_keys.len() - 1
                    }) as u8
            })
            .collect();

        compiled_instructions.push(CompiledInstruction {
            program_id_index,
            account_indexes: SmallVec::from(account_indexes),
            data: SmallVec::from(instruction.data),
        });
    }

    TransactionMessage {
        num_signers: 1,              // funding_address is the signer
        num_writable_signers: 1,     // funding_address is writable signer
        num_writable_non_signers: 1, // feature_id is writable non-signer
        account_keys: SmallVec::from(account_keys),
        instructions: SmallVec::from(compiled_instructions),
        address_table_lookups: SmallVec::from(vec![]),
    }
}

#[test]
fn test_create_transaction_data_serialization() {
    let transaction_message = create_test_transaction_message();

    let transaction_message_bytes = borsh::to_vec(&transaction_message).unwrap();
    let create_transaction_data = VaultTransactionCreateArgsData {
        args: VaultTransactionCreateArgs {
            vault_index: 0,
            ephemeral_signers: 0,
            transaction_message: transaction_message_bytes,
            memo: None,
        },
    };

    // Serialize the data
    let serialized_data = create_transaction_data.data().unwrap();

    // Check that it starts with the correct discriminator
    assert_eq!(
        &serialized_data[0..8],
        crate::squads::CREATE_TRANSACTION_DISCRIMINATOR
    );

    // Test deserialization of the args portion
    let args_data = &serialized_data[8..];
    let deserialized_args = VaultTransactionCreateArgs::try_from_slice(args_data).unwrap();

    assert_eq!(deserialized_args.vault_index, 0);
    assert_eq!(deserialized_args.ephemeral_signers, 0);
    assert_eq!(deserialized_args.memo, None);

    // Deserialize the transaction message bytes and verify
    let deserialized_transaction_message =
        TransactionMessage::try_from_slice(&deserialized_args.transaction_message).unwrap();
    assert_eq!(
        deserialized_transaction_message.num_signers,
        transaction_message.num_signers
    );
    assert_eq!(
        deserialized_transaction_message.account_keys.len(),
        transaction_message.account_keys.len()
    );
}

#[test]
fn test_create_proposal_data_serialization() {
    let create_proposal_data = MultisigCreateProposalData {
        args: MultisigCreateProposalArgs {
            transaction_index: 1,
            is_draft: false,
        },
    };

    // Serialize the data
    let serialized_data = create_proposal_data.data().unwrap();

    // Check that it starts with the correct discriminator
    assert_eq!(
        &serialized_data[0..8],
        crate::squads::CREATE_PROPOSAL_DISCRIMINATOR
    );

    // Test deserialization of the args portion
    let args_data = &serialized_data[8..];
    let deserialized_args = MultisigCreateProposalArgs::try_from_slice(args_data).unwrap();

    assert_eq!(deserialized_args.transaction_index, 1);
    assert_eq!(deserialized_args.is_draft, false);
}

#[test]
fn test_vault_transaction_message_serialization() {
    let transaction_message = create_test_transaction_message();

    // Test serialization and deserialization
    let serialized = borsh::to_vec(&transaction_message).unwrap();
    let deserialized = TransactionMessage::try_from_slice(&serialized).unwrap();

    assert_eq!(deserialized.num_signers, transaction_message.num_signers);
    assert_eq!(
        deserialized.num_writable_signers,
        transaction_message.num_writable_signers
    );
    assert_eq!(
        deserialized.num_writable_non_signers,
        transaction_message.num_writable_non_signers
    );
    assert_eq!(deserialized.account_keys, transaction_message.account_keys);
    assert_eq!(
        deserialized.instructions.len(),
        transaction_message.instructions.len()
    );
    assert_eq!(
        deserialized.instructions[0].program_id_index,
        transaction_message.instructions[0].program_id_index
    );
    assert_eq!(
        deserialized.instructions[0].account_indexes,
        transaction_message.instructions[0].account_indexes
    );
    assert_eq!(
        deserialized.instructions[0].data,
        transaction_message.instructions[0].data
    );
}

#[test]
fn test_pda_derivation() {
    let multisig_address = Pubkey::new_unique(); // Generate random key
    let transaction_index = 1u64;

    // Test transaction PDA derivation
    let (transaction_pda, transaction_bump) =
        get_transaction_pda(&multisig_address, transaction_index, None);
    assert!(transaction_bump <= 255); // Valid bump seed

    // Test proposal PDA derivation
    let (proposal_pda, proposal_bump) =
        get_proposal_pda(&multisig_address, transaction_index, None);
    assert!(proposal_bump <= 255); // Valid bump seed

    // PDAs should be different
    assert_ne!(transaction_pda, proposal_pda);

    // Same inputs should produce same PDAs
    let (transaction_pda2, _) = get_transaction_pda(&multisig_address, transaction_index, None);
    let (proposal_pda2, _) = get_proposal_pda(&multisig_address, transaction_index, None);
    assert_eq!(transaction_pda, transaction_pda2);
    assert_eq!(proposal_pda, proposal_pda2);
}

#[test]
fn test_account_metas_generation() {
    let multisig = Pubkey::new_unique();
    let transaction = Pubkey::new_unique();
    let proposal = Pubkey::new_unique();
    let creator = Pubkey::new_unique();
    let rent_payer = Pubkey::new_unique();

    // Test MultisigCreateTransaction account metas
    let create_transaction_accounts = MultisigCreateTransaction {
        multisig,
        transaction,
        creator,
        rent_payer,
        system_program: solana_system_interface::program::ID,
    };

    let tx_metas = create_transaction_accounts.to_account_metas();
    assert_eq!(tx_metas.len(), 5);
    assert_eq!(tx_metas[0].pubkey, multisig);
    assert_eq!(tx_metas[1].pubkey, transaction);
    assert_eq!(tx_metas[2].pubkey, creator);
    assert_eq!(tx_metas[3].pubkey, rent_payer);
    assert_eq!(tx_metas[4].pubkey, solana_system_interface::program::ID);

    // Test MultisigCreateProposal account metas
    let create_proposal_accounts = MultisigCreateProposalAccounts {
        multisig,
        proposal,
        creator,
        rent_payer,
        system_program: solana_system_interface::program::ID,
    };

    let proposal_metas = create_proposal_accounts.to_account_metas();
    assert_eq!(proposal_metas.len(), 5);
    assert_eq!(proposal_metas[0].pubkey, multisig);
    assert_eq!(proposal_metas[1].pubkey, proposal);
    assert_eq!(proposal_metas[2].pubkey, creator);
    assert_eq!(proposal_metas[3].pubkey, rent_payer);
    assert_eq!(
        proposal_metas[4].pubkey,
        solana_system_interface::program::ID
    );
}

#[test]
fn test_create_transaction_and_proposal_message() {
    let multisig_address = Pubkey::new_unique();
    let fee_payer_pubkey = Pubkey::new_unique();
    let contributor_pubkey = Pubkey::new_unique();
    let recent_blockhash = Hash::default(); // Use default hash for testing

    let transaction_message = create_test_transaction_message();
    let transaction_index = 1u64;
    let vault_index = 0u8;
    let priority_fee = Some(5000u32);

    // Test message creation
    let result = create_transaction_and_proposal_message(
        None, // Use default program ID
        &fee_payer_pubkey,
        &contributor_pubkey,
        &multisig_address,
        transaction_index,
        vault_index,
        transaction_message,
        priority_fee,
        Some(200000u32), // compute_unit_limit
        recent_blockhash,
    );

    assert!(result.is_ok());
    let (message, transaction_pda, proposal_pda) = result.unwrap();

    // Verify PDAs are derived correctly
    let expected_transaction_pda =
        get_transaction_pda(&multisig_address, transaction_index, None).0;
    let expected_proposal_pda = get_proposal_pda(&multisig_address, transaction_index, None).0;
    assert_eq!(transaction_pda, expected_transaction_pda);
    assert_eq!(proposal_pda, expected_proposal_pda);

    // Verify message has the right number of instructions
    // Should have 4: priority fee + compute unit limit + create transaction + create proposal
    assert_eq!(message.instructions.len(), 4);

    // Verify the fee payer is set correctly
    assert_eq!(message.account_keys[0], fee_payer_pubkey);

    // Verify PDAs are not the same
    assert_ne!(transaction_pda, proposal_pda);
}

#[test]
fn test_create_transaction_and_proposal_message_no_priority_fee() {
    let multisig_address = Pubkey::new_unique();
    let fee_payer_pubkey = Pubkey::new_unique();
    let contributor_pubkey = Pubkey::new_unique();
    let recent_blockhash = Hash::default(); // Use default hash for testing

    let transaction_message = create_test_transaction_message();
    let transaction_index = 1u64;
    let vault_index = 0u8;

    // Test message creation without priority fee
    let result = create_transaction_and_proposal_message(
        None, // Use default program ID
        &fee_payer_pubkey,
        &contributor_pubkey,
        &multisig_address,
        transaction_index,
        vault_index,
        transaction_message,
        None, // No priority fee
        None, // No compute unit limit
        recent_blockhash,
    );

    assert!(result.is_ok());
    let (message, _transaction_pda, _proposal_pda) = result.unwrap();

    // Should have 2 instructions: create transaction + create proposal (no priority fee)
    assert_eq!(message.instructions.len(), 2);
}

#[test]
fn test_feature_activation_instructions_compilation() {
    let transaction_message = create_test_transaction_message();

    // Verify we have 3 compiled instructions (transfer, allocate, assign)
    assert_eq!(transaction_message.instructions.len(), 3);

    // Verify account structure
    assert!(transaction_message.account_keys.len() >= 4); // At least: funding, feature, system, feature_gate_program

    // Verify signer counts
    assert_eq!(transaction_message.num_signers, 1);
    assert_eq!(transaction_message.num_writable_signers, 1);
    assert_eq!(transaction_message.num_writable_non_signers, 1);

    // First account should be the funding address (signer)
    // Second account should be the feature account (writable non-signer)
    // System program and Feature Gate program should be in the account list
    let has_system_program = transaction_message
        .account_keys
        .contains(&solana_system_interface::program::ID);
    let has_feature_gate_program = transaction_message
        .account_keys
        .contains(&crate::feature_gate_program::FEATURE_GATE_PROGRAM_ID);

    assert!(
        has_system_program,
        "Transaction should include system program"
    );
    assert!(
        has_feature_gate_program,
        "Transaction should include feature gate program"
    );

    // Verify all instructions have valid program_id_index and account_indexes
    for (i, instruction) in transaction_message.instructions.iter().enumerate() {
        assert!(
            (instruction.program_id_index as usize) < transaction_message.account_keys.len(),
            "Instruction {} has invalid program_id_index",
            i
        );

        for (j, &account_index) in instruction.account_indexes.iter().enumerate() {
            assert!(
                (account_index as usize) < transaction_message.account_keys.len(),
                "Instruction {} account {} has invalid index",
                i,
                j
            );
        }

        // Each instruction should have some data
        assert!(
            !instruction.data.is_empty(),
            "Instruction {} should have data",
            i
        );
    }
}