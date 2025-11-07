use crate::commands::{
    approve_feature_gate_activation_proposal, approve_feature_gate_activation_revocation_proposal,
    config_command, create_command, execute_feature_gate_activation_proposal,
    execute_feature_gate_revocation_proposal, show_command,
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
            "Approve/Execute Feature Gate Proposals (transactions are submited on-chain)",
            "Exit",
        ];

        let choice: &str = Select::new("What would you like to do?", options).prompt()?;

        println!("In the current setup, only the fee payer keypair is used for transactions, hence for EOA voting fee payer = voting account. For multisig setup, the fee payer needs to be a member of the parent multisig.\n");

        match choice {
            "Create new feature gate multisig" => {
                let feepayer_path = prompt_for_fee_payer_path(&config)?;
                create_command(&mut config, None, vec![], Some(feepayer_path)).await?;
            }
            "Approve/Execute Feature Gate Proposals" => {
                let feature_gate_multisig_address =
                    prompt_for_pubkey("Enter the feature gate multisig address:")?;
                let feature_gate_id = get_vault_pda(&feature_gate_multisig_address, 0, None).0;
                let fee_payer_path = prompt_for_fee_payer_path(&config)?;

                let options = vec![
                    "Approve feature gate activation proposal",
                    "Approve feature gate activation revocation proposal",
                    "Execute feature gate activation proposal",
                    "Execute feature gate revocation proposal",
                    "Exit",
                ];
                let choice: &str = Select::new("What would you like to do?", options).prompt()?;
                match choice {
                    "Approve feature gate activation proposal" => {
                        Confirm::new(&format!(
                            "You're approving the activation of the following feature gate: {}?",
                            feature_gate_id
                        ))
                        .with_default(true)
                        .prompt()?;
                        let voting_key = prompt_for_pubkey(
                            "Enter the voting key: (Can be either EOA or parent multisig)",
                        )?;
                        approve_feature_gate_activation_proposal(
                            &config,
                            feature_gate_multisig_address,
                            voting_key,
                            fee_payer_path,
                            None,
                        )
                        .await?;
                    }
                    "Approve feature gate activation revocation proposal" => {
                        Confirm::new(&format!(
                            "You're approving the activation revocation of the following feature gate: {}?",
                            feature_gate_id
                        ))
                        .with_default(true)
                        .prompt()?;
                        let voting_key = prompt_for_pubkey(
                            "Enter the voting key: (Can be either EOA or parent multisig)",
                        )?;
                        approve_feature_gate_activation_revocation_proposal(
                            &config,
                            feature_gate_multisig_address,
                            voting_key,
                            fee_payer_path,
                            None,
                        )
                        .await?;
                    }
                    "Execute feature gate activation proposal" => {
                        Confirm::new(&format!(
                            "You're executing the activation of the following feature gate: {}?",
                            feature_gate_id
                        ))
                        .with_default(true)
                        .prompt()?;
                        let voting_key = prompt_for_pubkey(
                            "Enter the voting key: (Can be either EOA or parent multisig)",
                        )?;
                        execute_feature_gate_activation_proposal(
                            &config,
                            feature_gate_multisig_address,
                            voting_key,
                            fee_payer_path,
                            None,
                        )
                        .await?;
                    }
                    "Execute feature gate revocation proposal" => {
                        Confirm::new(&format!(
                            "You're executing the activation of the following feature gate: {}?",
                            feature_gate_id
                        ))
                        .with_default(true)
                        .prompt()?;
                        let voting_key = prompt_for_pubkey(
                            "Enter the voting key: (Can be either EOA or parent multisig)",
                        )?;
                        execute_feature_gate_revocation_proposal(
                            &config,
                            feature_gate_multisig_address,
                            voting_key,
                            fee_payer_path,
                            None,
                        )
                        .await?;
                    }
                    "Exit" => break,
                    _ => unreachable!(),
                }
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
