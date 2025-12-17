use crate::constants::*;
use crate::provision::{create_rpc_client, get_account_data_with_retry};
use crate::squads::{
    get_proposal_pda, get_transaction_pda, get_vault_pda, Multisig, Proposal, ProposalStatus,
    VaultTransaction,
};
use crate::utils::*;
use colored::*;
use eyre::Result;
use inquire::Select;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use tabled::{settings::Style, Table, Tabled};

pub async fn show_command(config: &Config, address: Option<String>) -> Result<()> {
    let address = if let Some(addr) = address {
        // Validate provided address
        match Pubkey::from_str(&addr) {
            Ok(_) => addr,
            Err(_) => {
                println!(
                    "{} Invalid address format: {}",
                    "❌".bright_red(),
                    addr.bright_red()
                );
                return Err(eyre::eyre!("Invalid multisig address format"));
            }
        }
    } else {
        validate_pubkey_with_retry("Enter multisig address:")?.to_string()
    };
    show_multisig(config, &address).await
}

async fn show_multisig(config: &Config, address: &str) -> Result<()> {
    // Parse the multisig address
    let multisig_pubkey =
        Pubkey::from_str(address).map_err(|_| eyre::eyre!("Invalid multisig address format"))?;

    println!(
        "{}",
        "🔍 Fetching multisig details...".bright_yellow().bold()
    );
    println!();

    // Try all configured networks until we find the account
    let mut account_data = None;
    let mut successful_rpc_url = None;
    let mut last_error = None;

    let networks_to_try = if !config.networks.is_empty() {
        config.networks.clone()
    } else {
        vec![DEFAULT_DEVNET_URL.to_string()]
    };

    let rpc_url: String =
        Select::new("Which network would you like to query?", networks_to_try).prompt()?;

    println!("🌐 Trying network: {}", rpc_url.bright_white());

    let rpc_client = create_rpc_client(&rpc_url);
    match get_account_data_with_retry(&rpc_client, &multisig_pubkey) {
        Ok(data) => {
            println!("✅ Found account on: {}", rpc_url.bright_green());
            account_data = Some(data);
            successful_rpc_url = Some(rpc_url.clone());
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("AccountNotFound") || error_str.contains("could not find account")
            {
                println!("❌ Account not found on: {}", rpc_url.bright_red());
                last_error = Some(format!("Account not found: {}. This address may not exist on any of the configured networks or may not be a multisig account.", multisig_pubkey));
            } else {
                println!("❌ Error querying {}: {}", rpc_url.bright_red(), e);
                last_error = Some(format!("Failed to query networks: {}", e));
            }
        }
    }

    let (rpc_url, account_data) = match (successful_rpc_url, account_data) {
        (Some(url), Some(data)) => (url, data),
        _ => {
            return Err(eyre::eyre!(
                "{}",
                last_error.unwrap_or_else(
                    || "Failed to find account on any configured network".to_string()
                )
            ));
        }
    };

    println!();
    println!("📡 Using network: {}", rpc_url.bright_white());
    println!(
        "🎯 Multisig address: {}",
        multisig_pubkey.to_string().bright_white()
    );
    println!();

    if account_data.len() < 8 {
        return Err(eyre::eyre!("Account data too small to be a valid multisig"));
    }

    println!("📊 Account data length: {} bytes", account_data.len());

    // Strip the first 8 bytes (discriminator) and deserialize
    let multisig: Multisig = match borsh::BorshDeserialize::deserialize(&mut &account_data[8..]) {
        Ok(ms) => ms,
        Err(e) if e.to_string().contains("Not all bytes read") => {
            // This is expected for accounts with pre-allocated member slots (padding)
            // Try to deserialize only the data we need, ignoring trailing bytes
            use borsh::BorshDeserialize;
            let mut slice = &account_data[8..];
            Multisig::deserialize(&mut slice)
                .map_err(|e2| eyre::eyre!("Failed to deserialize multisig data even with partial read: {}. This account may not be a valid Squads multisig.", e2))?
        },
        Err(e) => return Err(eyre::eyre!("Failed to deserialize multisig data: {}. This account may not be a valid Squads multisig.", e)),
    };

    println!("✅ Multisig deserialized successfully!");

    // Display the multisig details
    display_multisig_details(&multisig, &multisig_pubkey)?;

    // Fetch and display transaction and proposal details for indices 1 and 2
    let rpc_client = create_rpc_client(&rpc_url);
    fetch_and_display_transactions_and_proposals(&rpc_client, &multisig_pubkey, &multisig).await?;

    Ok(())
}

fn display_multisig_details(multisig: &Multisig, address: &Pubkey) -> Result<()> {
    println!("{}", "📋 MULTISIG DETAILS".bright_green().bold());
    println!("{}", "═".repeat(80).bright_green());
    println!();

    // Basic info table
    #[derive(Tabled)]
    struct MultisigInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let info_data = vec![
        MultisigInfo {
            property: "Multisig Address".to_string(),
            value: address.to_string(),
        },
        MultisigInfo {
            property: "Create Key".to_string(),
            value: multisig.create_key.to_string(),
        },
        MultisigInfo {
            property: "Config Authority".to_string(),
            value: multisig.config_authority.to_string(),
        },
        MultisigInfo {
            property: "Threshold".to_string(),
            value: {
                let voting_members_count = multisig
                    .members
                    .iter()
                    .filter(|member| member.permissions.mask & 2 != 0) // Check Vote permission (bit 1)
                    .count();
                format!(
                    "{} of {} voting members",
                    multisig.threshold, voting_members_count
                )
            },
        },
        MultisigInfo {
            property: "Time Lock (seconds)".to_string(),
            value: multisig.time_lock.to_string(),
        },
        MultisigInfo {
            property: "Transaction Index".to_string(),
            value: multisig.transaction_index.to_string(),
        },
        MultisigInfo {
            property: "Stale Transaction Index".to_string(),
            value: multisig.stale_transaction_index.to_string(),
        },
        MultisigInfo {
            property: "Rent Collector".to_string(),
            value: multisig
                .rent_collector
                .map(|r| r.to_string())
                .unwrap_or_else(|| "None".to_string()),
        },
        MultisigInfo {
            property: "PDA Bump".to_string(),
            value: multisig.bump.to_string(),
        },
    ];

    let mut info_table = Table::new(info_data);
    info_table.with(Style::rounded());
    println!("{}", info_table);
    println!();

    // Members table
    #[derive(Tabled)]
    struct MemberInfo {
        #[tabled(rename = "#")]
        index: usize,
        #[tabled(rename = "Public Key")]
        pubkey: String,
        #[tabled(rename = "Permissions")]
        permissions: String,
        #[tabled(rename = "Bitmask")]
        bitmask: u8,
    }

    println!(
        "{} ({} total)",
        "👥 MEMBERS".bright_blue().bold(),
        multisig.members.len()
    );
    println!();

    let member_data: Vec<MemberInfo> = multisig
        .members
        .iter()
        .enumerate()
        .map(|(i, member)| {
            let perms = decode_permissions(member.permissions.mask);
            MemberInfo {
                index: i + 1,
                pubkey: member.key.to_string(),
                permissions: if perms.is_empty() {
                    "None".to_string()
                } else {
                    perms.join(", ")
                },
                bitmask: member.permissions.mask,
            }
        })
        .collect();

    let mut members_table = Table::new(member_data);
    members_table.with(Style::rounded());
    println!("{}", members_table);
    println!();

    // Calculate and display vault addresses for common indices
    println!("{}", "🏦 VAULT ADDRESSES".bright_cyan().bold());
    println!();

    #[derive(Tabled)]
    struct VaultInfo {
        #[tabled(rename = "Index")]
        index: u8,
        #[tabled(rename = "Vault Address")]
        address: String,
        #[tabled(rename = "Description")]
        description: String,
    }

    let vault_data = vec![
        VaultInfo {
            index: 0,
            address: get_vault_pda(address, 0, None).0.to_string(),
            description: "Default vault (commonly used for feature gates)".to_string(),
        },
        VaultInfo {
            index: 1,
            address: get_vault_pda(address, 1, None).0.to_string(),
            description: "Vault #1".to_string(),
        },
        VaultInfo {
            index: 2,
            address: get_vault_pda(address, 2, None).0.to_string(),
            description: "Vault #2".to_string(),
        },
    ];

    let mut vault_table = Table::new(vault_data);
    vault_table.with(Style::rounded());
    println!("{}", vault_table);
    println!();

    println!(
        "{}",
        "✅ Multisig details retrieved successfully!".bright_green()
    );

    Ok(())
}

async fn fetch_and_display_transactions_and_proposals(
    rpc_client: &RpcClient,
    multisig_pubkey: &Pubkey,
    multisig: &Multisig,
) -> Result<()> {
    println!("{}", "🔄 TRANSACTIONS & PROPOSALS".bright_yellow().bold());
    println!("{}", "═".repeat(80).bright_yellow());
    println!();

    // Check if there are any transactions to display
    if multisig.transaction_index == 0 {
        println!("🔍 No transactions found (transaction_index = 0)");
        println!();
        return Ok(());
    }

    println!("🔍 Fetching transaction and proposal data for indices 1 and 2...");
    println!();

    // Fetch data for indices 1 and 2
    for tx_index in 1..=2u64 {
        if tx_index > multisig.transaction_index {
            println!(
                "Transaction index {} not yet created (current max: {})",
                tx_index, multisig.transaction_index
            );
            continue;
        }

        println!(
            "{}",
            format!("📋 TRANSACTION INDEX {}", tx_index)
                .bright_cyan()
                .bold()
        );
        println!("{}", "─".repeat(50).bright_cyan());

        // Generate PDAs for transaction and proposal
        let (transaction_pda, _) = get_transaction_pda(multisig_pubkey, tx_index, None);
        let (proposal_pda, _) = get_proposal_pda(multisig_pubkey, tx_index, None);

        println!(
            "🎯 Transaction PDA: {}",
            transaction_pda.to_string().bright_white()
        );
        println!(
            "🎯 Proposal PDA: {}",
            proposal_pda.to_string().bright_white()
        );
        println!();

        // Fetch transaction account
        match fetch_and_display_transaction(rpc_client, &transaction_pda, tx_index).await {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "❌ Failed to fetch transaction {}: {}",
                    tx_index,
                    e.to_string().bright_red()
                );
            }
        }

        // Fetch proposal account
        match fetch_and_display_proposal(rpc_client, &proposal_pda, tx_index).await {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "❌ Failed to fetch proposal {}: {}",
                    tx_index,
                    e.to_string().bright_red()
                );
            }
        }

        println!();
    }

    Ok(())
}

async fn fetch_and_display_transaction(
    rpc_client: &RpcClient,
    transaction_pda: &Pubkey,
    tx_index: u64,
) -> Result<()> {
    println!("📦 Transaction Account Data:");

    // Fetch the transaction account
    let account_data = match get_account_data_with_retry(rpc_client, transaction_pda) {
        Ok(data) => data,
        Err(e) => {
            if e.to_string().contains("AccountNotFound") {
                println!("  ⚠️  Transaction account not found");
                return Ok(());
            }
            return Err(eyre::eyre!("Failed to fetch transaction account: {}", e));
        }
    };

    if account_data.len() < 8 {
        println!("  ❌ Account data too small");
        return Ok(());
    }

    // Deserialize the VaultTransaction
    let transaction: VaultTransaction =
        match borsh::BorshDeserialize::deserialize(&mut &account_data[8..]) {
            Ok(tx) => tx,
            Err(e) => {
                println!("  ❌ Failed to deserialize transaction: {}", e);
                return Ok(());
            }
        };

    // Display transaction details in a table
    #[derive(Tabled)]
    struct TransactionInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let tx_info = vec![
        TransactionInfo {
            property: "Index".to_string(),
            value: transaction.index.to_string(),
        },
        TransactionInfo {
            property: "Creator".to_string(),
            value: transaction.creator.to_string(),
        },
        TransactionInfo {
            property: "Multisig".to_string(),
            value: transaction.multisig.to_string(),
        },
        TransactionInfo {
            property: "Vault Index".to_string(),
            value: transaction.vault_index.to_string(),
        },
        TransactionInfo {
            property: "Vault Bump".to_string(),
            value: transaction.vault_bump.to_string(),
        },
        TransactionInfo {
            property: "Account Bump".to_string(),
            value: transaction.bump.to_string(),
        },
        TransactionInfo {
            property: "Ephemeral Signers".to_string(),
            value: transaction.ephemeral_signer_bumps.len().to_string(),
        },
    ];

    let mut tx_table = Table::new(tx_info);
    tx_table.with(Style::rounded());
    println!("{}", tx_table);

    // Display transaction message details
    println!();
    println!("📋 Transaction Message Details:");

    #[derive(Tabled)]
    struct MessageInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let msg_info = vec![
        MessageInfo {
            property: "Signers".to_string(),
            value: transaction.message.num_signers.to_string(),
        },
        MessageInfo {
            property: "Writable Signers".to_string(),
            value: transaction.message.num_writable_signers.to_string(),
        },
        MessageInfo {
            property: "Writable Non-Signers".to_string(),
            value: transaction.message.num_writable_non_signers.to_string(),
        },
        MessageInfo {
            property: "Account Keys".to_string(),
            value: transaction.message.account_keys.len().to_string(),
        },
        MessageInfo {
            property: "Instructions".to_string(),
            value: transaction.message.instructions.len().to_string(),
        },
        MessageInfo {
            property: "Address Table Lookups".to_string(),
            value: transaction.message.address_table_lookups.len().to_string(),
        },
    ];

    let mut msg_table = Table::new(msg_info);
    msg_table.with(Style::rounded());
    println!("{}", msg_table);

    // Display detailed instruction breakdown
    if !transaction.message.instructions.is_empty() {
        println!();
        println!("📋 Instructions Details:");

        #[derive(Tabled)]
        struct InstructionDetails {
            #[tabled(rename = "Instruction #")]
            instruction_num: String,
            #[tabled(rename = "Program ID")]
            program_id: String,
            #[tabled(rename = "Accounts")]
            accounts: String,
            #[tabled(rename = "Data (bytes)")]
            data: String,
        }

        let instruction_details: Vec<InstructionDetails> = transaction
            .message
            .instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                // Get the program ID from account_keys
                let program_id = if (instruction.program_id_index as usize)
                    < transaction.message.account_keys.len()
                {
                    transaction.message.account_keys[instruction.program_id_index as usize]
                        .to_string()
                } else {
                    format!("Invalid index ({})", instruction.program_id_index)
                };

                // Format account indexes with their corresponding pubkeys
                let accounts_info = if instruction.account_indexes.is_empty() {
                    "None".to_string()
                } else {
                    instruction
                        .account_indexes
                        .iter()
                        .map(|&account_idx| {
                            if (account_idx as usize) < transaction.message.account_keys.len() {
                                format!(
                                    "{}:{}",
                                    account_idx,
                                    &transaction.message.account_keys[account_idx as usize]
                                        .to_string()[..8]
                                )
                            } else {
                                format!("{}:Invalid", account_idx)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                // Format instruction data as hex bytes
                let data_str = if instruction.data.is_empty() {
                    "Empty".to_string()
                } else if instruction.data.len() <= 32 {
                    // Show full data for small instructions
                    instruction
                        .data
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    // Show first 16 bytes + length for large instructions
                    let preview = instruction
                        .data
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{} ... ({} bytes total)", preview, instruction.data.len())
                };

                InstructionDetails {
                    instruction_num: (i + 1).to_string(),
                    program_id,
                    accounts: accounts_info,
                    data: data_str,
                }
            })
            .collect();

        let mut instructions_table = Table::new(instruction_details);
        instructions_table.with(Style::rounded());
        println!("{}", instructions_table);

        // Display account keys reference table
        if !transaction.message.account_keys.is_empty() {
            println!();
            println!("🔑 Account Keys Reference:");

            #[derive(Tabled)]
            struct AccountKeyInfo {
                #[tabled(rename = "Index")]
                index: u8,
                #[tabled(rename = "Public Key")]
                pubkey: String,
                #[tabled(rename = "Role")]
                role: String,
            }

            let account_key_info: Vec<AccountKeyInfo> = transaction
                .message
                .account_keys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| {
                    let role = if i < transaction.message.num_signers as usize {
                        if i < transaction.message.num_writable_signers as usize {
                            "Writable Signer"
                        } else {
                            "Read-only Signer"
                        }
                    } else if i
                        < (transaction.message.num_signers
                            + transaction.message.num_writable_non_signers)
                            as usize
                    {
                        "Writable Non-signer"
                    } else {
                        "Read-only Non-signer"
                    };

                    AccountKeyInfo {
                        index: i as u8,
                        pubkey: pubkey.to_string(),
                        role: role.to_string(),
                    }
                })
                .collect();

            let mut account_keys_table = Table::new(account_key_info);
            account_keys_table.with(Style::rounded());
            println!("{}", account_keys_table);
        }
    }

    println!("  ✅ Transaction {} details retrieved", tx_index);
    println!();

    Ok(())
}

async fn fetch_and_display_proposal(
    rpc_client: &RpcClient,
    proposal_pda: &Pubkey,
    tx_index: u64,
) -> Result<()> {
    println!("🗳️  Proposal Account Data:");

    // Fetch the proposal account
    let account_data = match get_account_data_with_retry(rpc_client, proposal_pda) {
        Ok(data) => data,
        Err(e) => {
            if e.to_string().contains("AccountNotFound") {
                println!("  ⚠️  Proposal account not found");
                return Ok(());
            }
            return Err(eyre::eyre!("Failed to fetch proposal account: {}", e));
        }
    };

    if account_data.len() < 8 {
        println!("  ❌ Account data too small");
        return Ok(());
    }

    // Deserialize the Proposal
    let proposal: Proposal = match borsh::BorshDeserialize::deserialize(&mut &account_data[8..]) {
        Ok(prop) => prop,
        Err(e) => {
            println!("  ❌ Failed to deserialize proposal: {}", e);
            return Ok(());
        }
    };

    // Display proposal details in a table
    #[derive(Tabled)]
    struct ProposalInfo {
        #[tabled(rename = "Property")]
        property: String,
        #[tabled(rename = "Value")]
        value: String,
    }

    let status_str = match &proposal.status {
        ProposalStatus::Draft { timestamp } => format!("Draft ({})", timestamp),
        ProposalStatus::Active { timestamp } => format!("Active ({})", timestamp),
        ProposalStatus::Rejected { timestamp } => format!("Rejected ({})", timestamp),
        ProposalStatus::Approved { timestamp } => format!("Approved ({})", timestamp),
        ProposalStatus::Executed { timestamp } => format!("Executed ({})", timestamp),
        ProposalStatus::Cancelled { timestamp } => format!("Cancelled ({})", timestamp),
        #[allow(deprecated)]
        ProposalStatus::Executing => "Executing (deprecated)".to_string(),
    };

    let proposal_info = vec![
        ProposalInfo {
            property: "Transaction Index".to_string(),
            value: proposal.transaction_index.to_string(),
        },
        ProposalInfo {
            property: "Multisig".to_string(),
            value: proposal.multisig.to_string(),
        },
        ProposalInfo {
            property: "Status".to_string(),
            value: status_str,
        },
        ProposalInfo {
            property: "Account Bump".to_string(),
            value: proposal.bump.to_string(),
        },
        ProposalInfo {
            property: "Approved Count".to_string(),
            value: proposal.approved.len().to_string(),
        },
        ProposalInfo {
            property: "Rejected Count".to_string(),
            value: proposal.rejected.len().to_string(),
        },
        ProposalInfo {
            property: "Cancelled Count".to_string(),
            value: proposal.cancelled.len().to_string(),
        },
    ];

    let mut proposal_table = Table::new(proposal_info);
    proposal_table.with(Style::rounded());
    println!("{}", proposal_table);

    // Display voting details if there are votes
    if !proposal.approved.is_empty()
        || !proposal.rejected.is_empty()
        || !proposal.cancelled.is_empty()
    {
        println!();
        println!("🗳️  Voting Details:");

        #[derive(Tabled)]
        struct VoteInfo {
            #[tabled(rename = "Vote Type")]
            vote_type: String,
            #[tabled(rename = "Member")]
            member: String,
        }

        let mut votes = Vec::new();

        for member in &proposal.approved {
            votes.push(VoteInfo {
                vote_type: "Approved".to_string(),
                member: member.to_string(),
            });
        }

        for member in &proposal.rejected {
            votes.push(VoteInfo {
                vote_type: "Rejected".to_string(),
                member: member.to_string(),
            });
        }

        for member in &proposal.cancelled {
            votes.push(VoteInfo {
                vote_type: "Cancelled".to_string(),
                member: member.to_string(),
            });
        }

        let mut votes_table = Table::new(votes);
        votes_table.with(Style::rounded());
        println!("{}", votes_table);
    }

    println!("  ✅ Proposal {} details retrieved", tx_index);
    println!();

    Ok(())
}
