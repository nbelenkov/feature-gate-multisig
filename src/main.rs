// unwrap/expect/panic are idiomatic in unit tests; the panic-prevention lints
// stay strict for production code only.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::panic_in_result_fn
    )
)]

mod commands;
mod constants;
mod feature_gate_program;
mod output;
mod provision;
mod squads;
mod utils;
mod verification;

use crate::commands::{
    check_signer_command, config_command, create_command, interactive_mode, proposal_command,
    show_command, verify_command, ProposalCommand, ProposalCommandArgs, TransactionKind,
};
use crate::output::Output;
use crate::utils::load_config;
use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::*;
use eyre::Result;
use solana_pubkey::Pubkey;

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
#[command(version)]
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
        // Parse at the on-chain width so clap rejects out-of-range values;
        // a wider type truncated instead, turning 65537 into 1.
        threshold: Option<u16>,
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
        #[arg(value_parser = crate::utils::parse_pubkey_arg, help = "The multisig address to inspect")]
        address: Option<Pubkey>,
        #[arg(
            long,
            value_parser = crate::utils::parse_network_arg,
            help = "Network to inspect: a configured network name (devnet/testnet/mainnet) or an RPC URL. Prompts when omitted and several networks are configured"
        )]
        network: Option<String>,
        #[arg(
            long,
            help = "Print full transaction/proposal details (the debugging view) for this proposal index"
        )]
        index: Option<u64>,
    },
    #[command(
        about = "Verify a feature gate multisig: program authenticity, feature state, owners"
    )]
    #[command(
        long_about = "Checks, across every configured network, that the Squads program is the authentic immutable v4, reports the feature gate account's status (fresh/pending/activated) and rent-exemption, and lists the multisig owners and threshold. Read-only."
    )]
    Verify {
        #[arg(value_parser = crate::utils::parse_pubkey_arg, help = "The feature gate multisig address to verify")]
        address: Option<Pubkey>,
    },
    #[command(about = "Create a proposal on a feature gate multisig")]
    #[command(
        long_about = "Creates a new proposal on the feature gate multisig: activate or revoke the feature (vault transaction), or rekey the multisig (config transaction). Runs the feature-state pre-flight check and confirms before sending."
    )]
    Propose {
        #[command(flatten)]
        args: ProposalActionArgs,
    },
    #[command(about = "Approve a proposal on a feature gate multisig")]
    Approve {
        #[command(flatten)]
        args: ProposalActionArgs,
        #[arg(
            long,
            help = "Proposal index to approve (see `show` for live proposals)"
        )]
        index: u64,
    },
    #[command(about = "Reject a proposal on a feature gate multisig")]
    Reject {
        #[command(flatten)]
        args: ProposalActionArgs,
        #[arg(
            long,
            help = "Proposal index to reject (see `show` for live proposals)"
        )]
        index: u64,
    },
    #[command(about = "Execute an approved proposal on a feature gate multisig")]
    Execute {
        #[command(flatten)]
        args: ProposalActionArgs,
        #[arg(
            long,
            help = "Proposal index to execute (see `show` for live proposals)"
        )]
        index: u64,
    },
    #[command(about = "Start interactive mode (default when no command is specified)")]
    #[command(
        long_about = "Launches the interactive mode which provides a guided experience for creating multisig wallets. This is the default mode when no command is specified."
    )]
    Interactive,
    #[command(
        about = "Check a signer is usable before an activation depends on it (signs nothing)"
    )]
    #[command(
        long_about = "Resolves a keypair path (including usb://ledger) to its public key and, when a multisig is given, reports whether that key is a member and what it may do. Signs nothing."
    )]
    CheckSigner {
        #[arg(
            short = 'k',
            long,
            help = "Keypair path to check (defaults to the saved config value)"
        )]
        keypair: Option<String>,
        #[arg(
            long,
            value_parser = crate::utils::parse_pubkey_arg,
            help = "Also check this key is a member of this multisig, and what it may do"
        )]
        multisig: Option<Pubkey>,
        #[arg(
            long,
            value_parser = crate::utils::parse_network_arg,
            help = "Network to inspect: a configured network name (devnet/testnet/mainnet) or an RPC URL. Prompts when omitted and several networks are configured"
        )]
        network: Option<String>,
    },
    #[command(about = "Show current configuration including networks and saved members")]
    #[command(
        long_about = "Displays the current configuration stored in your OS config directory (e.g. ~/.config/feature-gate-multisig-tool/config.json on Linux) including:
• Saved networks array for automatic deployment
• Saved member public keys
• Default threshold setting
• Configuration file location"
    )]
    Config,
}

/// Arguments shared by the proposal subcommands (propose/approve/reject/execute).
#[derive(Args)]
struct ProposalActionArgs {
    #[arg(long, value_parser = crate::utils::parse_pubkey_arg, help = "The feature gate multisig address")]
    multisig: Pubkey,
    #[arg(long, value_enum, help = "What the proposal does")]
    kind: KindArg,
    #[arg(
        long,
        value_parser = crate::utils::parse_pubkey_arg,
        help = "Voting key: your EOA or parent multisig (defaults to the saved config value)"
    )]
    voting_key: Option<Pubkey>,
    #[arg(
        short = 'k',
        long,
        help = "Fee payer keypair path (defaults to the saved config value)"
    )]
    keypair: Option<String>,
    #[arg(
        long,
        value_parser = crate::utils::parse_network_arg,
        help = "Network to act on: a configured network name (devnet/testnet/mainnet) or an RPC URL. Prompts when omitted and several networks are configured"
    )]
    network: Option<String>,
    #[arg(
        long,
        help = "Non-interactive: resolve each confirmation to its default answer"
    )]
    yes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    /// Activate the feature gate
    Activate,
    /// Revoke a pending feature gate activation
    Revoke,
    /// Rekey the multisig (permanently disables voting)
    Rekey,
}

impl From<KindArg> for TransactionKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Activate => TransactionKind::Activate,
            KindArg::Revoke => TransactionKind::Revoke,
            KindArg::Rekey => TransactionKind::Rekey,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // A build that can auto-confirm must say so on every run, whether or not
    // the env var is set, so a harness build cannot be mistaken for a release one.
    #[cfg(feature = "e2e-harness")]
    Output::warning(
        "This is an e2e-harness build: it can auto-confirm prompts. Never use it to sign \
         for a real cluster.",
    );
    if feature_gate_multisig_tool::utils::is_e2e_test_mode() {
        Output::warning(
            "E2E_TEST_MODE is set: every confirmation, including irreversible config \
             changes, is auto-approved.",
        );
    }

    let result = match cli.command {
        Some(command) => handle_command(command),
        None => interactive_mode(),
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

fn handle_command(command: Commands) -> Result<()> {
    let mut config = load_config()?;

    match command {
        Commands::Create { threshold, keypair } => {
            let threshold_option = threshold.and_then(|t| {
                if t == 0 {
                    println!(
                        "{} Threshold cannot be 0, will prompt later",
                        "⚠️".bright_yellow()
                    );
                    None
                } else {
                    Some(t)
                }
            });

            create_command(&mut config, threshold_option, keypair)
        }
        Commands::Show {
            address,
            network,
            index,
        } => show_command(&config, address, network, index),
        Commands::Verify { address } => verify_command(&config, address),
        Commands::Propose { args } => run_proposal(&config, ProposalCommand::Propose, args, None),
        Commands::Approve { args, index } => {
            run_proposal(&config, ProposalCommand::Approve, args, Some(index))
        }
        Commands::Reject { args, index } => {
            run_proposal(&config, ProposalCommand::Reject, args, Some(index))
        }
        Commands::Execute { args, index } => {
            run_proposal(&config, ProposalCommand::Execute, args, Some(index))
        }
        Commands::Interactive => interactive_mode(),
        Commands::CheckSigner {
            keypair,
            multisig,
            network,
        } => check_signer_command(&config, keypair, multisig, network),
        Commands::Config => config_command(&config),
    }
}

fn run_proposal(
    config: &crate::utils::Config,
    command: ProposalCommand,
    args: ProposalActionArgs,
    index: Option<u64>,
) -> Result<()> {
    if args.yes {
        std::env::set_var(crate::utils::ASSUME_YES_ENV, "1");
    }
    // --network narrows the config to one endpoint, so downstream flows use it
    // without prompting.
    let mut config = config.clone();
    if let Some(network) = &args.network {
        config.networks = vec![crate::utils::resolve_network_arg(&config, network)?];
    }
    proposal_command(
        &config,
        command,
        ProposalCommandArgs {
            multisig: args.multisig,
            kind: args.kind.into(),
            voting_key: args.voting_key,
            keypair: args.keypair,
            index,
        },
    )
}
