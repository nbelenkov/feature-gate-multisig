use crate::commands::{
    approve_common_config_change, approve_common_feature_gate_proposal, config_command,
    create_command, create_feature_gate_proposal, execute_common_config_change,
    execute_common_feature_gate_proposal, reject_common_feature_gate_proposal,
    rekey_multisig_feature_gate, show_command, TransactionKind,
};
use crate::squads::get_vault_pda;
use crate::utils::*;
use eyre::Result;
use inquire::{Confirm, Select, Text};

pub async fn interactive_mode() -> Result<()> {
    let mut config = load_config()?;

    loop {
        let options = vec![
            "Create new feature gate multisig",
            "Show feature gate multisig details",
            "Show configuration",
            "Proposal Actions (Approve/Reject/Execute)",
            "Exit",
        ];

        let choice: &str = Select::new("What would you like to do?", options).prompt()?;

        match choice {
            "Create new feature gate multisig" => {
                let feepayer_path = prompt_for_fee_payer_path(&config)?;
                create_command(&mut config, None, vec![], Some(feepayer_path)).await?;
            }
            "Proposal Actions (Approve/Reject/Execute)" => {
                handle_proposal_action(&config).await?;
            }
            "Show feature gate multisig details" => {
                let address = Text::new("Enter the main multisig address:").prompt()?;
                show_command(&config, Some(address)).await?;
            }
            "Show configuration" => {
                config_command(&config).await?;
            }
            "Exit" => break,
            _ => unreachable!(),
        }

        println!("\n");
    }

    Ok(())
}

async fn handle_proposal_action(config: &Config) -> Result<()> {
    println!("In the current setup, only the fee payer keypair is used for transactions, hence for EOA voting fee payer = voting account. For multisig setup, the fee payer needs to be a member of the parent multisig.\n");

    // Collect common inputs
    let feature_gate_multisig_address =
        prompt_for_pubkey("Enter the feature gate multisig address:")?;
    let feature_gate_id = get_vault_pda(&feature_gate_multisig_address, 0, None).0;
    let fee_payer_path = prompt_for_fee_payer_path(config)?;
    let voting_key =
        prompt_for_pubkey("Enter the voting key: (Can be either EOA or parent multisig)")?;

    // Select transaction type
    let type_options = vec![
        "Activate Feature Gate",
        "Revoke Feature Gate",
        "Rekey Multisig (this will brick the multisig)",
        "Cancel",
    ];
    let type_choice: &str = Select::new("Select transaction type:", type_options).prompt()?;

    if type_choice == "Cancel" {
        return Ok(());
    }

    let kind = match type_choice {
        "Activate Feature Gate" => TransactionKind::Activate,
        "Revoke Feature Gate" => TransactionKind::Revoke,
        "Rekey Multisig (this will brick the multisig)" => TransactionKind::Rekey,
        _ => unreachable!(),
    };

    // Select action - Rekey now supports Reject as well
    let action_options = vec!["Create", "Approve", "Reject", "Execute", "Cancel"];
    let action_choice: &str = Select::new("Select action:", action_options).prompt()?;

    if action_choice == "Cancel" {
        return Ok(());
    }

    if kind != TransactionKind::Rekey {
        // Feature Gate operations (Activate/Revoke)
        if action_choice == "Create" {
            // For Create, we don't need proposal index - we're creating a new one
            return create_feature_gate_proposal(
                config,
                feature_gate_multisig_address,
                voting_key,
                fee_payer_path,
                None,
                kind,
            )
            .await;
        }

        let proposal_index_str = Text::new("Enter the proposal index:").prompt()?;
        let proposal_index: u64 = proposal_index_str
            .parse()
            .map_err(|_| eyre::eyre!("Invalid proposal index"))?;

        Confirm::new(&format!(
            "You're {}ing the {} of feature gate {} at proposal index {}. Continue?",
            action_choice.to_lowercase(),
            type_choice.to_lowercase(),
            feature_gate_id,
            proposal_index
        ))
        .with_default(true)
        .prompt()?;

        match action_choice {
            "Approve" => {
                approve_common_feature_gate_proposal(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                    kind,
                )
                .await?;
            }
            "Reject" => {
                reject_common_feature_gate_proposal(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                    kind,
                )
                .await?;
            }
            "Execute" => {
                execute_common_feature_gate_proposal(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                    kind,
                )
                .await?;
            }
            _ => unreachable!(),
        }
    } else {
        // Rekey operation
        if action_choice == "Create" {
            // Create does not require a proposal index
            return rekey_multisig_feature_gate(
                config,
                feature_gate_multisig_address,
                voting_key,
                fee_payer_path,
                None,
            )
            .await;
        }

        let proposal_index_str = Text::new("Enter the proposal index:").prompt()?;
        let proposal_index: u64 = proposal_index_str
            .parse()
            .map_err(|_| eyre::eyre!("Invalid proposal index"))?;

        match action_choice {
            "Approve" => {
                Confirm::new(&format!(
                    "You're approving the rekey proposal at index {}. Continue?",
                    proposal_index
                ))
                .with_default(true)
                .prompt()?;

                approve_common_config_change(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                )
                .await?;
            }
            "Reject" => {
                Confirm::new(&format!(
                    "You're rejecting the rekey proposal at index {}. Continue?",
                    proposal_index
                ))
                .with_default(true)
                .prompt()?;

                reject_common_feature_gate_proposal(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                    TransactionKind::Rekey,
                )
                .await?;
            }
            "Execute" => {
                Confirm::new(&format!(
                    "You're executing the rekey proposal at index {}. Continue?",
                    proposal_index
                ))
                .with_default(true)
                .prompt()?;

                execute_common_config_change(
                    config,
                    feature_gate_multisig_address,
                    voting_key,
                    fee_payer_path,
                    None,
                    proposal_index,
                )
                .await?;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
