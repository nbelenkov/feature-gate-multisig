use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_system_interface::instruction::{allocate, assign, transfer};

/// The Feature Gate program ID
pub const FEATURE_GATE_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Feature111111111111111111111111111111111111");

/// The incinerator program ID (used for burning lamports in revoke)
pub const INCINERATOR_ID: Pubkey =
    Pubkey::from_str_const("1nc1nerator11111111111111111111111111111111");

/// Size of a Feature account in bytes
pub const FEATURE_ACCOUNT_SIZE: usize = 9;

/// Feature account state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feature {
    /// Slot at which the feature was activated, None if still pending
    pub activated_at: Option<u64>,
}

impl Feature {
    /// Size of the Feature account data
    pub const fn size_of() -> usize {
        FEATURE_ACCOUNT_SIZE
    }

    /// Default Feature state (pending activation)
    pub fn default() -> Self {
        Self { activated_at: None }
    }
}

/// Creates instructions to activate a feature gate
///
/// This function creates the necessary instructions to queue a feature for activation:
/// 1. Transfer lamports to the feature account
/// 2. Allocate space for the feature account
/// 3. Assign the feature account to the Feature Gate program
///
/// # Arguments
/// * `feature_id` - The public key of the feature to activate
/// * `funding_address` - The public key of the account funding the feature activation
/// * `rent` - Rent sysvar for calculating minimum balance
///
/// # Returns
/// A vector of instructions to execute the feature activation
pub fn activate_feature(
    feature_id: &Pubkey,
    funding_address: &Pubkey,
    rent: &Rent,
) -> Vec<Instruction> {
    let lamports = rent.minimum_balance(Feature::size_of());
    activate_feature_with_lamports(feature_id, funding_address, lamports)
}

/// Creates instructions to activate a feature gate with specific lamport amount
///
/// This function creates the necessary instructions to queue a feature for activation:
/// 1. Transfer the specified lamports to the feature account
/// 2. Allocate space for the feature account
/// 3. Assign the feature account to the Feature Gate program
///
/// # Arguments
/// * `feature_id` - The public key of the feature to activate
/// * `funding_address` - The public key of the account funding the feature activation
/// * `lamports` - The amount of lamports to transfer for rent exemption
///
/// # Returns
/// A vector of instructions to execute the feature activation
pub fn activate_feature_with_lamports(
    feature_id: &Pubkey,
    funding_address: &Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    vec![
        // Transfer lamports to feature account for rent exemption
        transfer(funding_address, feature_id, lamports),
        // Allocate space for the feature account
        allocate(feature_id, Feature::size_of() as u64),
        // Assign the account to the Feature Gate program
        assign(feature_id, &FEATURE_GATE_PROGRAM_ID),
    ]
}

/// Creates instructions to activate a feature gate where the feature account is already funded
///
/// This function creates the necessary instructions to queue a feature for activation:
/// 1. Allocate space for the feature account
/// 2. Assign the feature account to the Feature Gate program
///
/// # Arguments
/// * `feature_id` - The public key of the feature to activate
///
/// # Returns
/// A vector of instructions to execute the feature activation
pub fn activate_feature_funded(feature_id: &Pubkey) -> Vec<Instruction> {
    vec![
        // Allocate space for the feature account
        allocate(feature_id, Feature::size_of() as u64),
        // Assign the account to the Feature Gate program
        assign(feature_id, &FEATURE_GATE_PROGRAM_ID),
    ]
}

/// Creates an instruction to revoke a pending feature activation
///
/// This instruction can only be called by the feature account's keypair holder
/// and only works on features that haven't been activated yet (are still pending).
///
/// The instruction will:
/// 1. Reallocate the feature account to zero size
/// 2. Assign it back to the System Program
/// 3. Transfer its lamports to the incinerator (burning them)
///
/// # Arguments
/// * `feature_id` - The public key of the feature to revoke
///
/// # Returns
/// An instruction to revoke the pending feature activation
pub fn revoke_pending_activation(feature_id: &Pubkey) -> Instruction {
    let accounts = vec![
        // Feature account (must be signer and writable)
        AccountMeta::new(*feature_id, true),
        // Incinerator account (writable, burns the lamports)
        AccountMeta::new(INCINERATOR_ID, false),
        // System program (for reallocating and reassigning the account)
        AccountMeta::new_readonly(solana_system_interface::program::ID, false),
    ];

    Instruction {
        program_id: FEATURE_GATE_PROGRAM_ID,
        accounts,
        data: vec![0], // RevokePendingActivation instruction discriminator
    }
}

/// Creates a minimal instruction to activate a feature (convenience function)
///
/// This creates a simplified activation instruction using system rent for calculation.
/// For more control over lamports, use `activate_feature_with_lamports` instead.
///
/// # Arguments
/// * `feature_id` - The public key of the feature to activate
/// * `funding_address` - The public key of the account funding the activation
///
/// # Returns
/// A vector of instructions to execute the feature activation with default rent
pub fn create_feature_activation(
    feature_id: &Pubkey,
    funding_address: &Pubkey,
) -> Vec<Instruction> {
    // Use a reasonable default for rent calculation
    let rent = Rent::default();
    activate_feature(feature_id, funding_address, &rent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_system_interface::program as system_program;

    #[test]
    fn test_feature_size() {
        assert_eq!(Feature::size_of(), 9);
    }

    #[test]
    fn test_feature_default() {
        let feature = Feature::default();
        assert_eq!(feature.activated_at, None);
    }

    #[test]
    fn test_activate_feature_instructions() {
        let feature_id = Pubkey::new_unique();
        let funding_address = Pubkey::new_unique();
        let rent = Rent::default();

        let instructions = activate_feature(&feature_id, &funding_address, &rent);

        assert_eq!(instructions.len(), 3);

        // Check transfer instruction
        let transfer_ix = &instructions[0];
        assert_eq!(transfer_ix.program_id, system_program::id());
        assert_eq!(transfer_ix.accounts.len(), 2);
        assert_eq!(transfer_ix.accounts[0].pubkey, funding_address);
        assert_eq!(transfer_ix.accounts[1].pubkey, feature_id);

        // Check allocate instruction
        let allocate_ix = &instructions[1];
        assert_eq!(allocate_ix.program_id, system_program::id());
        assert_eq!(allocate_ix.accounts[0].pubkey, feature_id);

        // Check assign instruction
        let assign_ix = &instructions[2];
        assert_eq!(assign_ix.program_id, system_program::id());
        assert_eq!(assign_ix.accounts[0].pubkey, feature_id);
    }

    #[test]
    fn test_revoke_pending_activation() {
        let feature_id = Pubkey::new_unique();

        let instruction = revoke_pending_activation(&feature_id);

        assert_eq!(instruction.program_id, FEATURE_GATE_PROGRAM_ID);
        assert_eq!(instruction.accounts.len(), 3);
        assert_eq!(instruction.data, vec![0]);

        // Check feature account
        assert_eq!(instruction.accounts[0].pubkey, feature_id);
        assert!(instruction.accounts[0].is_signer);
        assert!(instruction.accounts[0].is_writable);

        // Check incinerator account
        assert_eq!(instruction.accounts[1].pubkey, INCINERATOR_ID);
        assert!(!instruction.accounts[1].is_signer);
        assert!(instruction.accounts[1].is_writable);

        // Check system program
        assert_eq!(instruction.accounts[2].pubkey, system_program::id());
        assert!(!instruction.accounts[2].is_signer);
        assert!(!instruction.accounts[2].is_writable);
    }
}
