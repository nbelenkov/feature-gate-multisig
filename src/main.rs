mod commands;
mod constants;
mod feature_gate_program;
mod output;
mod provision;
mod squads;
mod utils;

use crate::commands::{config_command, create_command, interactive_mode, show_command};
use crate::output::Output;
use crate::utils::load_config;
use clap::{Parser, Subcommand};
use colored::*;
use eyre::Result;

#[derive(Parser)]
#[command(name = "feature-gate-multisig-tool")]
#[command(
    about = "A command-line tool for rapidly provisioning minimal Squads multisig setups specifically designed for Solana feature gate governance"
)]
#[command(
    long_about = "This tool enables parties to create multisig wallets where the default vault address can be mapped to feature gate account addresses, allowing collective voting on whether new Solana features should be implemented.

Features:
• 🚀 Rapid provisioning of Squads multisig wallets
• 🌐 Multi-network deployment (automatic or manual)
• 👥 Interactive member management with permission assignment
• 📋 Persistent configuration with saved networks and members
• 🎨 Rich CLI experience with colored output and tables

For more information, run: feature-gate-multisig-tool help <COMMAND>"
)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Create a new multisig wallet with interactive setup")]
    #[command(
        long_about = "Creates a new multisig wallet for feature gate governance. The tool will guide you through:
• Configuration review (if saved config exists)
• Member collection (interactive or from saved config)
• Network deployment selection (automatic or manual)
• Multi-network deployment with consistent addresses
• Comprehensive deployment summary

The contributor key receives Initiate-only permissions, while additional members receive full permissions (Initiate, Vote, Execute)."
    )]
    Create {
        #[arg(
            short,
            long,
            help = "Number of required signatures (will be prompted if not provided)"
        )]
        threshold: Option<u32>,
        #[arg(
            short,
            long,
            help = "Signers (currently unused - members are collected interactively)"
        )]
        signers: Option<Vec<String>>,
        #[arg(
            short = 'k',
            long,
            help = "Keypair file path for paying transaction fees (e.g., ~/.config/solana/id.json)"
        )]
        keypair: Option<String>,
    },
    #[command(about = "Show feature multisig details for a given address")]
    #[command(
        long_about = "Display detailed information about an existing multisig wallet including member permissions, threshold settings, and network deployment status."
    )]
    Show {
        #[arg(help = "The multisig address to inspect")]
        address: Option<String>,
    },
    #[command(about = "Start interactive mode (default when no command is specified)")]
    #[command(
        long_about = "Launches the interactive mode which provides a guided experience for creating multisig wallets. This is the default mode when no command is specified."
    )]
    Interactive,
    #[command(about = "Show current configuration including networks and saved members")]
    #[command(
        long_about = "Displays the current configuration stored in ~/.feature-gate-multisig-tool/config.json including:
• Saved networks array for automatic deployment
• Saved member public keys
• Default threshold setting
• Configuration file location"
    )]
    Config,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(command) => handle_command(command).await,
        None => interactive_mode().await,
    };

    if let Err(e) = result {
        Output::error(&format!("Error: {}", e));

        // Provide helpful error messages for common issues
        let error_msg = e.to_string();
        if error_msg.contains("config") {
            Output::hint("Try running: feature-gate-multisig-tool config");
        } else if error_msg.contains("address") || error_msg.contains("pubkey") {
            Output::hint("Public keys should be valid base58-encoded addresses");
        } else if error_msg.contains("network") || error_msg.contains("URL") {
            Output::hint(
                "Network URLs should start with https:// (e.g., https://api.devnet.solana.com)",
            );
        } else if error_msg.contains("threshold") {
            Output::hint("Threshold must be a positive number not exceeding member count");
        }

        Output::separator();
        Output::hint("Run --help for usage information");
        std::process::exit(1);
    }
}

async fn handle_command(command: Commands) -> Result<()> {
    let mut config = load_config()?;

    match command {
        Commands::Create {
            threshold,
            signers: _,
            keypair,
        } => {
            let threshold_option = threshold
                .map(|t| {
                    if t == 0 {
                        println!(
                            "{} Threshold cannot be 0, will prompt later",
                            "⚠️".bright_yellow()
                        );
                        None
                    } else {
                        Some(t as u16)
                    }
                })
                .flatten();

            create_command(&mut config, threshold_option, vec![], keypair).await
        }
        Commands::Show { address } => show_command(&config, address).await,
        Commands::Interactive => interactive_mode().await,
        Commands::Config => config_command(&config).await,
    }
}
