use crate::constants::*;
use crate::feature_gate_program::activate_feature_funded;
use crate::provision::create_rpc_client;
use crate::squads::{CompiledInstruction, Member, Permissions, TransactionMessage};
use colored::*;
use dirs;
use eyre::Result;
use indicatif::ProgressBar;
use inquire::{Confirm, Select, Text};
use serde::{Deserialize, Serialize};
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub threshold: u16,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub fee_payer_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 1,
            members: Vec::new(),
            networks: vec![DEFAULT_DEVNET_URL.to_string()],
            fee_payer_path: None,
        }
    }
}

#[derive(Debug)]
pub struct DeploymentResult {
    #[allow(dead_code)]
    pub rpc_url: String,
    pub multisig_address: Pubkey,
    pub vault_address: Pubkey,
    #[allow(dead_code)]
    pub transaction_signature: String,
}

// Config management functions
pub fn get_config_path() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| eyre::eyre!("Could not find home directory"))?;
    Ok(home_dir
        .join(".feature-gate-multisig-tool")
        .join("config.json"))
}

pub fn load_config() -> Result<Config> {
    let config_path = get_config_path()?;

    if !config_path.exists() {
        let config = Config::default();
        save_config(&config)?;
        return Ok(config);
    }

    let config_str = fs::read_to_string(&config_path)
        .map_err(|e| eyre::eyre!("Failed to read config file: {}", e))?;

    let config: Config = serde_json::from_str(&config_str)
        .map_err(|e| eyre::eyre!("Failed to parse config file: {}", e))?;

    Ok(config)
}

pub fn save_config(config: &Config) -> Result<()> {
    let config_path = get_config_path()?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| eyre::eyre!("Failed to create config directory: {}", e))?;
    }

    let config_str = serde_json::to_string_pretty(config)
        .map_err(|e| eyre::eyre!("Failed to serialize config: {}", e))?;

    fs::write(&config_path, config_str)
        .map_err(|e| eyre::eyre!("Failed to write config file: {}", e))?;

    Ok(())
}

// Member management functions
pub fn parse_saved_members(config: &Config) -> Vec<Member> {
    let mut parsed_members = Vec::new();
    for member_str in &config.members {
        match Pubkey::from_str(member_str) {
            Ok(pubkey) => {
                parsed_members.push(Member {
                    key: pubkey,
                    permissions: Permissions { mask: 7 }, // Full permissions for saved members
                });
            }
            Err(_) => {
                println!(
                    "  {} Invalid saved member key: {}, skipping...",
                    "⚠️".bright_yellow(),
                    member_str
                );
            }
        }
    }
    parsed_members
}

pub fn collect_members_interactively() -> Result<Vec<Member>> {
    let mut interactive_members = Vec::new();

    loop {
        let add_member = Confirm::new("Add a member?").with_default(true).prompt()?;

        if !add_member {
            break;
        }

        match validate_pubkey_with_retry("Enter member public key:") {
            Ok(member_key) => {
                interactive_members.push(Member {
                    key: member_key,
                    permissions: Permissions { mask: 7 },
                });
                println!(
                    "  {} Added member: {} ({})",
                    "✓".bright_green(),
                    member_key.to_string().bright_white(),
                    "Initiate, Vote, Execute".bright_cyan()
                );
            }
            Err(e) => {
                println!(
                    "  {} Failed to add member: {}",
                    "❌".bright_red(),
                    e.to_string().bright_red()
                );
                continue;
            }
        }
    }

    Ok(interactive_members)
}

pub fn review_and_collect_configuration(
    config: &Config,
    threshold: Option<u16>,
) -> Result<(u16, Vec<Member>)> {
    let use_saved_config = review_config(config)?;

    if use_saved_config {
        let parsed_members = parse_saved_members(config);
        Ok((config.threshold, parsed_members))
    } else {
        println!(
            "{} Collecting configuration interactively",
            "🔄".bright_cyan()
        );

        // First collect members
        let interactive_members = collect_members_interactively()?;

        // Then get threshold based on member count
        let final_threshold =
            if let Some(t) = threshold {
                // Validate CLI threshold against member count
                let max_members = interactive_members.len() + 1; // +1 for contributor
                if t as usize > max_members {
                    println!(
                    "  {} CLI threshold ({}) exceeds member count ({}), prompting for new value",
                    "⚠️".bright_yellow(), t, max_members
                );
                    prompt_for_threshold_with_max(max_members)?
                } else {
                    println!("  {} Using threshold from CLI: {}", "✓".bright_green(), t);
                    t
                }
            } else {
                let max_members = interactive_members.len() + 1; // +1 for contributor
                prompt_for_threshold_with_max(max_members)?
            };

        Ok((final_threshold, interactive_members))
    }
}

// Keypair management functions
pub fn expand_tilde_path(path: &str) -> Result<String> {
    if path.starts_with("~/") {
        let home = dirs::home_dir().ok_or_else(|| eyre::eyre!("Could not find home directory"))?;
        Ok(home.join(&path[2..]).to_string_lossy().to_string())
    } else {
        Ok(path.to_string())
    }
}

pub fn prompt_for_threshold_with_max(max_members: usize) -> Result<u16> {
    loop {
        let input = Text::new(&format!(
            "Enter threshold (required signatures) [max: {}]:",
            max_members
        ))
        .prompt()
        .unwrap_or_default();

        match validate_threshold(&input, max_members, 1) {
            Ok(t) => return Ok(t),
            Err(e) => {
                println!("  {} {}", "❌".bright_red(), e.to_string().bright_red());
                continue;
            }
        }
    }
}

pub fn prompt_for_pubkey(prompt: &str) -> Result<Pubkey> {
    let input = Text::new(prompt).prompt()?;
    match Pubkey::from_str(&input) {
        Ok(pubkey) => Ok(pubkey),
        Err(_) => {
            println!(
                "  {} Invalid public key, please try again.",
                "❌".bright_red()
            );
            prompt_for_pubkey(prompt)
        }
    }
}

pub fn prompt_for_fee_payer_path(config: &Config) -> Result<String> {
    let default_feepayer = config.fee_payer_path.as_deref().unwrap_or("usb://ledger");

    let feepayer_path = Text::new("Enter fee payer keypair file path:")
        .with_default(default_feepayer)
        .prompt()?;

    expand_tilde_path(&feepayer_path)
}

pub fn prompt_for_network(config: &Config) -> Result<String> {
    let default_network = &config.networks[0]; // We guarantee networks is not empty after migration

    loop {
        let input = Text::new("Enter RPC URL for deployment:")
            .with_default(default_network)
            .prompt()?;

        match validate_rpc_url(&input) {
            Ok(url) => return Ok(url),
            Err(e) => {
                println!("  {} {}", "❌".bright_red(), e.to_string().bright_red());
                let retry = Confirm::new("Try again?").with_default(true).prompt()?;
                if !retry {
                    return Err(eyre::eyre!("User cancelled network entry"));
                }
            }
        }
    }
}

/// Build a TransactionMessage for a parent multisig to approve a child's proposal.
/// This creates a single instruction that calls Squads `ApproveProposal` on the child multisig,
/// with `member_pubkey` set to the parent multisig address. The resulting TransactionMessage can
/// be embedded into a parent multisig transaction using `create_transaction_and_proposal_message`.
pub fn create_child_vote_approve_transaction_message(
    child_multisig: Pubkey,
    child_tx_index: u64,
    parent_member_pubkey: Pubkey,
) -> TransactionMessage {
    use crate::squads::{
        get_proposal_pda, MultisigApproveProposalData, MultisigVoteOnProposalAccounts,
        MultisigVoteOnProposalArgs, SmallVec, SQUADS_MULTISIG_PROGRAM_ID,
    };
    use solana_instruction::Instruction;

    // Derive child's proposal PDA
    let (proposal_pda, _bump) = get_proposal_pda(
        &child_multisig,
        child_tx_index,
        Some(&SQUADS_MULTISIG_PROGRAM_ID),
    );

    // Construct the vote (approve) instruction for the child multisig
    let accounts = MultisigVoteOnProposalAccounts {
        multisig: child_multisig,
        member: parent_member_pubkey,
        proposal: proposal_pda,
    };
    let data = MultisigApproveProposalData {
        args: MultisigVoteOnProposalArgs { memo: None },
    };

    let ix = Instruction::new_with_bytes(
        SQUADS_MULTISIG_PROGRAM_ID,
        &data.data(),
        accounts.to_account_metas(),
    );

    // Fixed account structure for child approve:
    // Account keys array: [parent_member, proposal, child_multisig, program]
    // Instruction expects: [multisig=2, member=0, proposal=1]
    TransactionMessage {
        num_signers: 1,
        num_writable_signers: 1,
        num_writable_non_signers: 1,
        account_keys: SmallVec::from(vec![
            parent_member_pubkey,
            proposal_pda,
            child_multisig,
            SQUADS_MULTISIG_PROGRAM_ID,
        ]),
        instructions: SmallVec::from(vec![CompiledInstruction {
            program_id_index: 3,
            account_indexes: SmallVec::from(vec![2, 0, 1]), // [multisig, member, proposal]
            data: SmallVec::from(ix.data),
        }]),
        address_table_lookups: SmallVec::from(vec![]),
    }
}

/// Build a TransactionMessage for a parent multisig to reject a child's proposal.
pub fn create_child_vote_reject_transaction_message(
    child_multisig: Pubkey,
    child_tx_index: u64,
    parent_member_pubkey: Pubkey,
) -> TransactionMessage {
    use crate::squads::{
        get_proposal_pda, MultisigRejectProposalData, MultisigVoteOnProposalAccounts,
        MultisigVoteOnProposalArgs, SmallVec, SQUADS_MULTISIG_PROGRAM_ID,
    };
    use solana_instruction::Instruction;

    let (proposal_pda, _bump) = get_proposal_pda(
        &child_multisig,
        child_tx_index,
        Some(&SQUADS_MULTISIG_PROGRAM_ID),
    );

    let accounts = MultisigVoteOnProposalAccounts {
        multisig: child_multisig,
        member: parent_member_pubkey,
        proposal: proposal_pda,
    };
    let data = MultisigRejectProposalData {
        args: MultisigVoteOnProposalArgs { memo: None },
    };

    let ix = Instruction::new_with_bytes(
        SQUADS_MULTISIG_PROGRAM_ID,
        &data.data(),
        accounts.to_account_metas(),
    );

    // Fixed account structure for child reject:
    // Account keys array: [parent_member (writable signer), proposal, child_multisig, program]
    // Instruction expects: [multisig=2, member=0, proposal=1]
    TransactionMessage {
        num_signers: 1,
        num_writable_signers: 1, // member must be writable
        num_writable_non_signers: 1,
        account_keys: SmallVec::from(vec![
            parent_member_pubkey,
            proposal_pda,
            child_multisig,
            SQUADS_MULTISIG_PROGRAM_ID,
        ]),
        instructions: SmallVec::from(vec![CompiledInstruction {
            program_id_index: 3,
            account_indexes: SmallVec::from(vec![2, 0, 1]), // [multisig, member, proposal]
            data: SmallVec::from(ix.data),
        }]),
        address_table_lookups: SmallVec::from(vec![]),
    }
}

// Transaction creation functions
pub fn create_feature_activation_transaction_message(feature_id: Pubkey) -> TransactionMessage {
    use crate::squads::SmallVec;

    // Build activation flow without any funding transfer: allocate + assign only.
    let instructions = activate_feature_funded(&feature_id);

    // Account keys: feature signer first, then programs
    let mut account_keys: Vec<Pubkey> = Vec::with_capacity(3);
    account_keys.push(feature_id); // signer, writable
    account_keys.push(solana_system_interface::program::ID);
    account_keys.push(crate::feature_gate_program::FEATURE_GATE_PROGRAM_ID);

    // Compile instructions into CompiledInstructions with SmallVec
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
        num_signers: 1,
        num_writable_signers: 1,
        num_writable_non_signers: 0,
        account_keys: SmallVec::from(account_keys),
        instructions: SmallVec::from(compiled_instructions),
        address_table_lookups: SmallVec::from(vec![]),
    }
}

/// Create and send PAIRED proposals (vault + config) in a single atomic transaction.
/// This creates 4 instructions (no compute budget instructions to minimize transaction size):
/// 1. VaultTransactionCreate (for activate/revoke)
/// 2. ProposalCreate (for vault transaction)
/// 3. ConfigTransactionCreate (for threshold change)
/// 4. ProposalCreate (for config transaction)
///
/// Both proposals are created atomically - either both succeed or both fail.
/// Note: Compute budget instructions are excluded to reduce transaction size.
pub async fn create_and_send_paired_proposals(
    rpc_url: &str,
    fee_payer_signer: &Box<dyn Signer>,
    contributor_signer: &dyn Signer,
    multisig_address: &Pubkey,
    vault_tx_index: u64,
    config_tx_index: u64,
    vault_message: crate::squads::TransactionMessage,
    config_actions: Vec<crate::squads::ConfigAction>,
    config_memo: Option<String>,
) -> Result<()> {
    use crate::squads::{
        get_proposal_pda, get_transaction_pda, ConfigTransactionCreateArgs,
        ConfigTransactionCreateData, MultisigCreateProposalAccounts, MultisigCreateProposalArgs,
        MultisigCreateProposalData, MultisigCreateTransaction, VaultTransactionCreateArgs,
        VaultTransactionCreateArgsData, SQUADS_MULTISIG_PROGRAM_ID,
    };
    use solana_instruction::Instruction;
    use solana_message::v0::Message;
    use solana_message::VersionedMessage;
    use solana_transaction::versioned::VersionedTransaction;

    let rpc_client = create_rpc_client(rpc_url);
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(|e| eyre::eyre!("Failed to get recent blockhash: {}", e))?;

    let fee_payer_pubkey = fee_payer_signer.pubkey();
    let contributor_pubkey = contributor_signer.pubkey();
    let program_id = &SQUADS_MULTISIG_PROGRAM_ID;

    // Calculate PDAs for both transaction/proposal pairs
    let (vault_transaction_pda, _) =
        get_transaction_pda(multisig_address, vault_tx_index, Some(program_id));
    let (vault_proposal_pda, _) =
        get_proposal_pda(multisig_address, vault_tx_index, Some(program_id));
    let (config_transaction_pda, _) =
        get_transaction_pda(multisig_address, config_tx_index, Some(program_id));
    let (config_proposal_pda, _) =
        get_proposal_pda(multisig_address, config_tx_index, Some(program_id));

    // Build instructions list
    let mut instructions = Vec::new();

    // 1. Create vault transaction instruction
    let vault_create_transaction_accounts = MultisigCreateTransaction {
        multisig: *multisig_address,
        transaction: vault_transaction_pda,
        creator: contributor_pubkey,
        rent_payer: fee_payer_pubkey,
        system_program: solana_system_interface::program::ID,
    };

    let vault_transaction_message_bytes = borsh::to_vec(&vault_message)?;
    let vault_create_transaction_data = VaultTransactionCreateArgsData {
        args: VaultTransactionCreateArgs {
            vault_index: 0,
            ephemeral_signers: 0,
            transaction_message: vault_transaction_message_bytes,
            memo: None,
        },
    };

    let vault_create_transaction_instruction = Instruction::new_with_bytes(
        *program_id,
        &vault_create_transaction_data.data(),
        vault_create_transaction_accounts.to_account_metas(),
    );
    instructions.push(vault_create_transaction_instruction);

    // 2. Create vault proposal instruction
    let vault_create_proposal_accounts = MultisigCreateProposalAccounts {
        multisig: *multisig_address,
        proposal: vault_proposal_pda,
        creator: contributor_pubkey,
        rent_payer: fee_payer_pubkey,
        system_program: solana_system_interface::program::ID,
    };

    let vault_create_proposal_data = MultisigCreateProposalData {
        args: MultisigCreateProposalArgs {
            transaction_index: vault_tx_index,
            is_draft: false,
        },
    };

    let vault_create_proposal_instruction = Instruction::new_with_bytes(
        *program_id,
        &vault_create_proposal_data.data(),
        vault_create_proposal_accounts.to_account_metas(),
    );
    instructions.push(vault_create_proposal_instruction);

    // 3. Create config transaction instruction
    let config_create_transaction_accounts = vec![
        solana_instruction::AccountMeta::new(*multisig_address, false),
        solana_instruction::AccountMeta::new(config_transaction_pda, false),
        solana_instruction::AccountMeta::new_readonly(contributor_pubkey, true),
        solana_instruction::AccountMeta::new(fee_payer_pubkey, true),
        solana_instruction::AccountMeta::new_readonly(
            solana_system_interface::program::ID,
            false,
        ),
    ];

    let config_create_transaction_data = ConfigTransactionCreateData {
        args: ConfigTransactionCreateArgs {
            actions: config_actions,
            memo: config_memo.clone(),
        },
    };

    let config_create_transaction_instruction = Instruction::new_with_bytes(
        *program_id,
        &config_create_transaction_data.data(),
        config_create_transaction_accounts,
    );
    instructions.push(config_create_transaction_instruction);

    // 4. Create config proposal instruction
    let config_create_proposal_accounts = MultisigCreateProposalAccounts {
        multisig: *multisig_address,
        proposal: config_proposal_pda,
        creator: contributor_pubkey,
        rent_payer: fee_payer_pubkey,
        system_program: solana_system_interface::program::ID,
    };

    let config_create_proposal_data = MultisigCreateProposalData {
        args: MultisigCreateProposalArgs {
            transaction_index: config_tx_index,
            is_draft: false,
        },
    };

    let config_create_proposal_instruction = Instruction::new_with_bytes(
        *program_id,
        &config_create_proposal_data.data(),
        config_create_proposal_accounts.to_account_metas(),
    );
    instructions.push(config_create_proposal_instruction);

    // Create message with all instructions
    let message = Message::try_compile(&fee_payer_pubkey, &instructions, &[], recent_blockhash)?;

    // Sign the transaction
    let signers: &[&dyn Signer] = if fee_payer_pubkey == contributor_pubkey {
        &[contributor_signer]
    } else {
        &[fee_payer_signer.as_ref(), contributor_signer]
    };

    let transaction = VersionedTransaction::try_new(VersionedMessage::V0(message), signers)
        .map_err(|e| eyre::eyre!("Failed to create signed transaction: {}", e))?;

    // Send the transaction
    let progress = ProgressBar::new_spinner().with_message("Creating paired proposals...");
    progress.enable_steady_tick(Duration::from_millis(100));

    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send paired proposals: {}", e))?;

    let network_display = if rpc_url.contains("devnet") {
        "Devnet"
    } else if rpc_url.contains("mainnet") {
        "Mainnet"
    } else if rpc_url.contains("testnet") {
        "Testnet"
    } else {
        "Custom"
    };

    progress.finish_with_message(format!(
        "Paired Proposals Created ({}) - Vault Index: {}, Config Index: {}\nSignature ({}): {}",
        network_display,
        vault_tx_index,
        config_tx_index,
        network_display,
        signature.to_string().bright_green()
    ));
    println!("");
    Ok(())
}

/// Create and send a transaction to fund the feature gate account with rent-exempt lamports
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint to use
/// * `fee_payer_signer` - The signer that will pay for the transaction and provide funding
/// * `feature_gate_address` - The address of the feature gate account (vault PDA) to fund
///
/// # Returns
/// Result containing the transaction signature or an error
pub async fn create_and_send_funding_transaction(
    rpc_url: &str,
    fee_payer_signer: &Box<dyn Signer>,
    feature_gate_address: &Pubkey,
) -> Result<String> {
    use crate::feature_gate_program::FEATURE_ACCOUNT_SIZE;
    use solana_system_interface::instruction::transfer;

    let rpc_client = create_rpc_client(rpc_url);

    // Calculate rent-exempt minimum balance for feature account
    let rent = rpc_client.get_minimum_balance_for_rent_exemption(FEATURE_ACCOUNT_SIZE)?;

    crate::output::Output::info(&format!(
        "Funding feature gate address with {} lamports (rent-exempt minimum for {} bytes)",
        rent, FEATURE_ACCOUNT_SIZE
    ));

    // Create transfer instruction
    let transfer_ix = transfer(&fee_payer_signer.pubkey(), feature_gate_address, rent);

    // Get recent blockhash
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(|e| eyre::eyre!("Failed to get recent blockhash: {}", e))?;

    // Create and sign transaction
    let mut message =
        solana_message::Message::new(&[transfer_ix], Some(&fee_payer_signer.pubkey()));
    message.recent_blockhash = recent_blockhash;

    let transaction = VersionedTransaction::try_new(
        VersionedMessage::Legacy(message),
        &[fee_payer_signer.as_ref()],
    )
    .map_err(|e| eyre::eyre!("Failed to create funding transaction: {}", e))?;

    // Send and confirm transaction
    let progress = ProgressBar::new_spinner().with_message("Sending funding transaction...");
    progress.enable_steady_tick(Duration::from_millis(100));

    let signature = crate::provision::send_and_confirm_transaction(&transaction, &rpc_client)
        .map_err(|e| eyre::eyre!("Failed to send funding transaction: {}", e))?;

    progress.finish_with_message(format!(
        "Feature gate funded: {}",
        signature.to_string().bright_green()
    ));

    Ok(signature)
}

// Validation functions
pub fn validate_pubkey_with_retry(prompt: &str) -> Result<Pubkey> {
    loop {
        let input = Text::new(prompt).prompt()?;
        match Pubkey::from_str(&input.trim()) {
            Ok(pubkey) => {
                println!(
                    "  {} Valid public key: {}",
                    "✓".bright_green(),
                    pubkey.to_string().bright_white()
                );
                return Ok(pubkey);
            }
            Err(_) => {
                println!(
                    "  {} Invalid public key format. Please try again.",
                    "❌".bright_red()
                );
                println!(
                    "  {} Public keys should be valid base58-encoded addresses",
                    "💡".bright_blue()
                );

                let retry = Confirm::new("Try again?").with_default(true).prompt()?;
                if !retry {
                    return Err(eyre::eyre!("User cancelled public key entry"));
                }
            }
        }
    }
}

pub fn validate_threshold(input: &str, max_members: usize, default: u16) -> Result<u16> {
    if input.trim().is_empty() {
        return Ok(default);
    }

    match input.trim().parse::<u16>() {
        Ok(threshold) if threshold == 0 => Err(eyre::eyre!("Threshold must be at least 1")),
        Ok(threshold) if threshold > max_members as u16 => Err(eyre::eyre!(
            "Threshold cannot exceed number of members ({})",
            max_members
        )),
        Ok(threshold) => {
            println!(
                "  {} Valid threshold: {}",
                "✓".bright_green(),
                threshold.to_string().bright_white()
            );
            Ok(threshold)
        }
        Err(_) => Err(eyre::eyre!(
            "Invalid number format. Please enter a positive integer."
        )),
    }
}

pub fn validate_rpc_url(url: &str) -> Result<String> {
    let url = url.trim();

    if url.is_empty() {
        return Err(eyre::eyre!("URL cannot be empty"));
    }

    // Check if it's a valid URL
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(eyre::eyre!("URL must start with http:// or https://"));
    }

    // Basic URL validation - check for valid characters and structure
    if !url.contains("://") {
        return Err(eyre::eyre!("Invalid URL format"));
    }

    // Check for common Solana RPC patterns
    if url.contains("solana.com")
        || url.contains("localhost")
        || url.contains("127.0.0.1")
        || url.contains("rpc")
    {
        println!("  {} Valid RPC URL format detected", "✓".bright_green());
    } else {
        println!(
            "  {} Warning: URL doesn't match common Solana RPC patterns",
            "⚠️".bright_yellow()
        );
        let confirm = Confirm::new("Continue with this URL?")
            .with_default(false)
            .prompt()?;
        if !confirm {
            return Err(eyre::eyre!("User cancelled due to unusual URL"));
        }
    }

    Ok(url.to_string())
}


pub fn choose_network_from_config(config: &Config) -> Result<String> {
    let available_networks = if !config.networks.is_empty() {
        config.networks.clone()
    } else {
        vec![
            "https://api.devnet.solana.com".to_string(),
            "https://api.testnet.solana.com".to_string(),
            "https://api.mainnet.solana.com".to_string(),
        ]
    };

    if available_networks.is_empty() {
        return Err(eyre::eyre!("No networks available"));
    }

    // Non-interactive mode for E2E tests
    if std::env::var("E2E_TEST_MODE").is_ok() {
        return Ok(available_networks[0].to_string());
    }

    let choice = Select::new(
        "What network would you like to use for transaction generation?",
        available_networks,
    )
    .prompt()?;
    Ok(choice.to_string())
}

pub fn choose_network_mode(config: &Config, use_saved_config: bool) -> Result<(bool, Vec<String>)> {
    if !use_saved_config {
        return Ok((false, Vec::new()));
    }

    let available_networks = config.networks.clone();

    if available_networks.is_empty() {
        return Ok((false, Vec::new()));
    }

    println!("");
    println!("{}", "Saved Network Configuration".bold().bright_yellow(),);
    println!("");
    println!(
        "  {}: {}",
        "Networks".cyan(),
        available_networks.len().to_string().cyan()
    );
    for (i, network) in available_networks.iter().enumerate() {
        let network_name = if network.contains("devnet") {
            "Devnet"
        } else if network.contains("testnet") {
            "Testnet"
        } else if network.contains("mainnet") {
            "Mainnet"
        } else {
            "Custom"
        };
        println!(
            "    {}: {} ({})",
            format!("Network {}", i + 1).cyan(),
            network_name.bright_white(),
            network.bright_white()
        );
    }
    // Auto-confirm in E2E test mode
    let use_saved_networks = if std::env::var("E2E_TEST_MODE").is_ok() {
        true
    } else {
        Confirm::new("Use saved networks for deployment?")
            .with_default(true)
            .prompt()?
    };

    Ok((use_saved_networks, available_networks))
}

pub fn review_config(config: &Config) -> Result<bool> {
    if config.members.is_empty() && config.networks.is_empty() {
        return Ok(false);
    }

    println!(
        "\n{}",
        "📋 Found existing configuration:".bright_yellow().bold()
    );
    println!("");
    if !config.members.is_empty() {
        println!(
            "  {}: {}",
            "Saved members".cyan(),
            config.members.len().to_string().bright_green()
        );
        for (i, member) in config.members.iter().enumerate() {
            println!(
                "    {}: {}",
                format!("Member {}", i + 1).cyan(),
                member.bright_white()
            );
        }
    }
    println!("");
    println!(
        "  {}: {}",
        "Threshold".cyan(),
        config.threshold.to_string().bright_green()
    );

    // Show fee payer path
    println!("");
    if let Some(fee_payer_path) = &config.fee_payer_path {
        println!(
            "  {}: {}",
            "Fee payer keypair".cyan(),
            fee_payer_path.bright_green()
        );
    } else {
        println!(
            "  {}: {}",
            "Fee payer keypair".cyan(),
            "Not configured".bright_yellow()
        );
    }

    // Show networks
    let networks_to_show = &config.networks;

    println!("");
    println!(
        "  {}: {}",
        "Saved networks".cyan(),
        networks_to_show.len().to_string().bright_green()
    );
    for (i, network) in networks_to_show.iter().enumerate() {
        println!(
            "    {}: {}",
            format!("Network {}", i + 1).cyan(),
            network.bright_white()
        );
    }

    println!();
    // Auto-confirm in E2E test mode
    let use_config = if std::env::var("E2E_TEST_MODE").is_ok() {
        true
    } else {
        Confirm::new("Use these saved members and settings?")
            .with_default(true)
            .prompt()?
    };

    Ok(use_config)
}

pub fn decode_permissions(mask: u8) -> Vec<String> {
    let mut permissions = Vec::new();
    if mask & 1 != 0 {
        permissions.push("Initiate".to_string());
    }
    if mask & 2 != 0 {
        permissions.push("Vote".to_string());
    }
    if mask & 4 != 0 {
        permissions.push("Execute".to_string());
    }
    permissions
}

/// Check that the fee payer has sufficient SOL balance on all networks
/// Returns a Result indicating success or failure with network-specific errors
pub async fn check_fee_payer_balance_on_networks(
    fee_payer_pubkey: &Pubkey,
    networks: &[String],
    required_balance_sol: f64,
) -> Result<()> {
    use crate::output::Output;

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    let required_lamports = (required_balance_sol * LAMPORTS_PER_SOL as f64) as u64;

    Output::header("💰 Checking Fee Payer Balance");
    println!();

    let mut insufficient_balance_networks = Vec::new();
    let mut network_errors = Vec::new();

    for network in networks {
        let network_display = if network.contains("devnet") {
            "Devnet"
        } else if network.contains("mainnet") {
            "Mainnet"
        } else if network.contains("testnet") {
            "Testnet"
        } else {
            "Custom"
        };

        // Create RPC client for this network
        let rpc_client = crate::provision::create_rpc_client(network);

        // Check balance with retries
        match rpc_client.get_balance(fee_payer_pubkey) {
            Ok(balance_lamports) => {
                let balance_sol = balance_lamports as f64 / LAMPORTS_PER_SOL as f64;

                if balance_lamports >= required_lamports {
                    println!(
                        "  {} {}: {} SOL",
                        "✓".bright_green(),
                        network_display.bright_white(),
                        format!("{:.4}", balance_sol).bright_green()
                    );
                } else {
                    println!(
                        "  {} {}: {} SOL (insufficient - need {:.3})",
                        "❌".bright_red(),
                        network_display.bright_white(),
                        format!("{:.4}", balance_sol).bright_red(),
                        required_balance_sol.to_string().bright_yellow()
                    );
                    insufficient_balance_networks.push((network_display.to_string(), balance_sol));
                }
            }
            Err(e) => {
                println!(
                    "  {} {}: {}",
                    "⚠️".bright_yellow(),
                    network_display.bright_white(),
                    "Could not check balance".bright_red()
                );
                network_errors.push((network_display.to_string(), e.to_string()));
            }
        }
    }

    println!();

    // Report any issues
    if !insufficient_balance_networks.is_empty() {
        Output::error(&format!(
            "Fee payer has insufficient balance on {} network(s)",
            insufficient_balance_networks.len()
        ));
        for (network, balance) in &insufficient_balance_networks {
            println!(
                "  {} {}: {:.4} SOL (need {:.3} SOL)",
                "•".bright_red(),
                network.bright_white(),
                balance,
                required_balance_sol.to_string().bright_yellow()
            );
        }
        println!();
        return Err(eyre::eyre!(
            "Fee payer needs at least {:.3} SOL on all networks for deployment",
            required_balance_sol
        ));
    }

    if !network_errors.is_empty() {
        Output::warning(&format!(
            "Could not check balance on {} network(s) - proceeding anyway",
            network_errors.len()
        ));
        for (network, error) in &network_errors {
            println!(
                "  {} {}: {}",
                "•".bright_yellow(),
                network.bright_white(),
                error
            );
        }
        println!();
    }

    if insufficient_balance_networks.is_empty() && network_errors.is_empty() {
        Output::success("Fee payer has sufficient balance on all networks");
    }

    Ok(())
}
