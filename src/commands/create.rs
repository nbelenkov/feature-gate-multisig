use crate::output::Output;
use crate::provision::create_multisig;
use crate::squads::{get_proposal_pda, get_vault_pda, Member, Permissions};
use crate::utils::*;
use colored::*;
use eyre::Result;
use solana_clap_v3_utils::keypair::signer_from_path;
use solana_keypair::Keypair;
use solana_signer::Signer;

pub async fn create_command(
    config: &mut Config,
    threshold: Option<u16>,
    _sub_multisigs: Vec<String>,
    keypair_path: Option<String>,
) -> Result<()> {
    println!(
        "{}",
        "🚀 Creating feature gate multisig configuration"
            .bright_cyan()
            .bold()
    );

    // Collect configuration and members
    let (final_threshold, mut members) = review_and_collect_configuration(config, threshold)?;

    // Load fee payer signer from CLI arg or config (supports hardware wallets via usb://ledger)
    let fee_payer_path = keypair_path
        .or_else(|| config.fee_payer_path.clone())
        .ok_or_else(|| eyre::eyre!("Fee payer keypair path is required"))?;

    let fee_payer_signer =
        signer_from_path(&Default::default(), &fee_payer_path, "fee payer", &mut None)
            .map_err(|e| eyre::eyre!("Failed to load fee payer: {}", e))?;

    // Create setup keypair (always separate from fee payer)
    let setup_keypair = Keypair::new();
    let setup_pubkey = setup_keypair.pubkey();

    // Create a persistent create_key for all deployments
    let create_key = Keypair::new();

    // Add contributor as a member with permission 1 (bitmask for Initiate only)
    members.insert(
        0,
        Member {
            key: setup_pubkey,
            permissions: Permissions { mask: 1 },
        },
    );

    // // Display final configuration
    // display_final_configuration(
    //     &contributor_pubkey,
    //     &create_key.pubkey(),
    //     &fee_payer_keypair,
    //     final_threshold,
    //     &members,
    // );

    // Determine network deployment mode and deploy
    let (use_saved_networks, saved_networks) = choose_network_mode(config, true)?;

    // Check fee payer balance on all networks before deployment
    if use_saved_networks && !saved_networks.is_empty() {
        let fee_payer_pubkey = fee_payer_signer.pubkey();

        check_fee_payer_balance_on_networks(&fee_payer_pubkey, &saved_networks, 0.05).await?;
    }

    let deployments = if use_saved_networks && !saved_networks.is_empty() {
        deploy_to_saved_networks(
            &saved_networks,
            &create_key,
            &setup_keypair,
            &fee_payer_signer,
            &members,
            final_threshold,
        )
        .await?
    } else {
        deploy_to_manual_networks(
            config,
            &create_key,
            &setup_keypair,
            &fee_payer_signer,
            &members,
            final_threshold,
        )
        .await?
    };

    // Print summary table
    print_deployment_summary(
        &deployments,
        &members,
        final_threshold,
        &create_key.pubkey(),
    );

    // Save updated configuration (excluding contributor key)
    if !deployments.is_empty() {
        config.threshold = final_threshold;
        config.members = members
            .iter()
            .skip(1) // Skip contributor (index 0)
            .map(|member| member.key.to_string())
            .collect();

        save_config(config)?;
        println!(
            "\n{} Configuration saved for future use",
            "💾".bright_green()
        );
    }

    Ok(())
}

async fn deploy_to_single_network(
    rpc_url: &str,
    network_index: usize,
    total_networks: usize,
    create_key: &Keypair,
    setup_keypair: &Keypair,
    fee_payer_signer: &Box<dyn Signer>,
    members: &[Member],
    threshold: u16,
) -> Result<DeploymentResult> {
    // display_deployment_info(
    //     network_index,
    //     total_networks,
    //     rpc_url,
    //     &create_key.pubkey(),
    //     &contributor_keypair.pubkey(),
    //     &multisig_address,
    //     &vault_address,
    //     members,
    // );

    let signer_for_creation = fee_payer_signer.as_ref();

    let (multisig_address, signature) = create_multisig(
        rpc_url.to_string(),
        None, // Use default program ID
        signer_for_creation,
        create_key,
        members.to_vec(),
        threshold,
        Some(5000), // Priority fee
    )
    .await
    .map_err(|e| eyre::eyre!("Failed to create multisig: {}", e))?;

    let vault_address = get_vault_pda(&multisig_address, 0, None).0;

    // Create both activation and revocation transactions
    create_and_send_transaction_proposal(
        rpc_url,
        fee_payer_signer,
        setup_keypair,
        &multisig_address,
        "activation",
        1, // Transaction index 1 (activation)
    )
    .await?;

    create_and_send_transaction_proposal(
        rpc_url,
        fee_payer_signer,
        setup_keypair,
        &multisig_address,
        "revocation",
        2, // Transaction index 2 (revocation)
    )
    .await?;

    // Fund the vault address (feature gate account) with rent-exempt lamports
    create_and_send_funding_transaction(rpc_url, fee_payer_signer, &vault_address).await?;

    Ok(DeploymentResult {
        rpc_url: rpc_url.to_string(),
        multisig_address,
        vault_address,
        transaction_signature: signature,
    })
}

async fn deploy_to_saved_networks(
    networks: &[String],
    create_key: &Keypair,
    setup_keypair: &Keypair,
    fee_payer_signer: &Box<dyn Signer>,
    members: &[Member],
    threshold: u16,
) -> Result<Vec<DeploymentResult>> {
    let mut deployments = Vec::new();

    for (i, rpc_url) in networks.iter().enumerate() {
        match deploy_to_single_network(
            rpc_url,
            i,
            networks.len(),
            create_key,
            setup_keypair,
            fee_payer_signer,
            members,
            threshold,
        )
        .await
        {
            Ok(deployment) => {
                deployments.push(deployment);
            }
            Err(e) => {
                println!(
                    "{} Failed to deploy on {}: {}",
                    "❌".bright_red(),
                    rpc_url.bright_white(),
                    e.to_string().red()
                );
            }
        }

        if i < networks.len() - 1 {
            println!("\n{} Proceeding to next network...", "⏳".bright_yellow());
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(deployments)
}

async fn deploy_to_manual_networks(
    config: &Config,
    create_key: &Keypair,
    contributor_keypair: &Keypair,
    fee_payer_signer: &Box<dyn Signer>,
    members: &[Member],
    threshold: u16,
) -> Result<Vec<DeploymentResult>> {
    println!("\n{} Manual network entry mode", "🔄".bright_cyan());

    let mut deployments = Vec::new();

    loop {
        let rpc_url = prompt_for_network(config)?;

        match deploy_to_single_network(
            &rpc_url,
            0,
            1,
            create_key,
            contributor_keypair,
            fee_payer_signer,
            members,
            threshold,
        )
        .await
        {
            Ok(deployment) => {
                deployments.push(deployment);
            }
            Err(e) => {
                println!(
                    "{} Failed to deploy on {}: {}",
                    "❌".bright_red(),
                    rpc_url.bright_white(),
                    e.to_string().red()
                );
            }
        }

        let deploy_another =
            inquire::Confirm::new("Deploy to another network with the same configuration?")
                .with_default(false)
                .prompt()?;

        if !deploy_another {
            break;
        }

        println!();
    }

    Ok(deployments)
}

fn print_deployment_summary(
    deployments: &[DeploymentResult],
    members: &[Member],
    threshold: u16,
    _create_key: &solana_pubkey::Pubkey,
) {
    if deployments.is_empty() {
        Output::error("No successful deployments to summarize.");
        return;
    }

    println!("");
    Output::header("👀 Deployment Complete");

    for deployment in deployments {
        // Feature Gate ID is the vault address (index 0)
        let feature_gate_id = deployment.vault_address;

        // Calculate proposal PDAs for activation and revocation transactions
        let activation_proposal_pda = get_proposal_pda(&deployment.multisig_address, 1, None).0;
        let revocation_proposal_pda = get_proposal_pda(&deployment.multisig_address, 2, None).0;

        println!("\n{}", "⚙️ General Info".bright_white().bold());
        println!();
        Output::field(
            "Feature Gate Multisig",
            &deployment.multisig_address.to_string(),
        );
        Output::field("Feature Gate ID", &feature_gate_id.to_string());

        println!("\n{}", "⚙️ Config Parameters".bright_white().bold());
        println!();
        Output::field("Members", &members.len().to_string());

        // Display members with their permissions
        for (i, member) in members.iter().enumerate() {
            let perms = decode_permissions(member.permissions.mask);
            let role_indicator = if member.permissions.mask == 1 {
                " (Contributor)"
            } else {
                ""
            };
            let member_display = format!(
                "{}{} ({})",
                member.key.to_string(),
                role_indicator,
                perms.join(", ")
            );
            let member_label = if member.permissions.mask == 1 {
                "Temporary Setup Keypair".to_string()
            } else {
                format!("Member {}", i + 1)
            };
            println!(
                "  {} {}: {}",
                "✓".bright_green(),
                member_label,
                member_display.bright_white()
            );
        }
        println!();
        Output::field("Threshold", &threshold.to_string());

        println!("\n{}", "⚙️ Proposals".bright_white().bold());
        println!();
        Output::field(
            "Feature Gate Activation Proposal",
            &activation_proposal_pda.to_string(),
        );
        Output::field(
            "Feature Gate Revocation Proposal",
            &revocation_proposal_pda.to_string(),
        );

        if deployments.len() > 1 {
            println!("\n{}", "─".repeat(50).bright_cyan());
        }
    }
}
