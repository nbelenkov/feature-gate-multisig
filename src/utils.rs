use crate::constants::*;
use crate::provision::{build_squads_transaction_message, create_rpc_client};
use crate::squads::{Member, Permissions, TransactionMessage};
use colored::*;
use eyre::Result;
use indicatif::ProgressBar;
use inquire::{Confirm, Select, Text};
use serde::{Deserialize, Serialize};
use solana_message::v0::Message;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Per-user config directory (under the OS config dir) and file name.
const CONFIG_DIR_NAME: &str = "feature-gate-multisig-tool";
const CONFIG_FILE_NAME: &str = "config.json";

/// Env var overriding the config directory. Set by the E2E tests (pointing at a
/// temp dir) so test runs never read or overwrite the real per-user config.
pub const CONFIG_DIR_ENV: &str = "FEATURE_GATE_MULTISIG_CONFIG_DIR";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub threshold: u16,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub fee_payer_path: Option<String>,
    /// Default voting key (EOA or parent multisig) for proposal actions. A signer's
    /// identity is stable across the many feature gate multisigs they act on.
    #[serde(default)]
    pub voting_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 1,
            members: Vec::new(),
            networks: vec![DEFAULT_DEVNET_URL.to_string()],
            fee_payer_path: None,
            voting_key: None,
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

/// True when an environment flag is set to something meaning "on".
/// `FLAG=0` and `FLAG=false` read as off, not as present-therefore-on.
fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| flag_value_enabled(&value))
}

/// Split from [`env_flag_enabled`] so the parsing rule is testable without
/// touching process-global env state.
fn flag_value_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off"
    )
}

/// True when running under the E2E test harness, which auto-confirms prompts
/// and picks defaults non-interactively.
///
/// Only exists in `e2e-harness` builds: a release binary must carry no env-var
/// path that can silence a confirmation. Without the feature this is a
/// constant `false`.
#[cfg(feature = "e2e-harness")]
pub fn is_e2e_test_mode() -> bool {
    env_flag_enabled("E2E_TEST_MODE")
}

#[cfg(not(feature = "e2e-harness"))]
pub fn is_e2e_test_mode() -> bool {
    false
}

/// Env var set by the `--yes` CLI flag. Confirmations resolve to their default
/// answer instead of prompting, so routine "send now?" prompts proceed while
/// safety prompts that default to "no" (e.g. pre-flight warnings) still abort.
pub const ASSUME_YES_ENV: &str = "FEATURE_GATE_MULTISIG_ASSUME_YES";

/// True when `--yes` was passed: take each confirmation's default answer.
pub fn is_assume_yes() -> bool {
    env_flag_enabled(ASSUME_YES_ENV)
}

/// Load a signer from a CLI-style path: a keypair file or `usb://ledger`.
///
/// `signer_from_path` is deprecated upstream pending Agave's unstable-API split,
/// but it remains the supported way to load hardware wallets; revisit once a
/// stable successor exists.
#[allow(deprecated)]
pub fn load_signer(path: &str, name: &str) -> Result<Box<dyn Signer>> {
    solana_clap_v3_utils::keypair::signer_from_path(&Default::default(), path, name, &mut None)
        .map_err(|e| eyre::eyre!("Failed to load {}: {}", name, e))
}

/// Returns a human-readable network name based on the RPC URL.
pub fn get_network_display(rpc_url: &str) -> &'static str {
    if rpc_url.contains("devnet") {
        "Devnet"
    } else if rpc_url.contains("mainnet") {
        "Mainnet"
    } else if rpc_url.contains("testnet") {
        "Testnet"
    } else {
        "Custom"
    }
}

/// Render a time lock for display: "none" when zero, otherwise the raw seconds
/// with the largest whole unit as a hint ("3600s (1h)"), "~"-prefixed when the
/// value does not divide evenly ("5400s (~1h)").
pub fn format_time_lock(seconds: u32) -> String {
    if seconds == 0 {
        return "none".to_string();
    }
    let seconds = u64::from(seconds);
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let (unit, label) = duration_unit(seconds);
    let approx = if seconds % unit == 0 { "" } else { "~" };
    format!("{seconds}s ({approx}{}{label})", seconds / unit)
}

fn duration_unit(seconds: u64) -> (u64, &'static str) {
    if seconds >= 86_400 {
        (86_400, "d")
    } else if seconds >= 3_600 {
        (3_600, "h")
    } else {
        (60, "m")
    }
}

/// Approximate age of a unix timestamp, truncated to the largest whole unit
/// ("3d ago"). The timestamp is on-chain data, so extreme or future values must
/// render as text rather than wrap or panic.
pub fn format_relative_age(timestamp: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    relative_age_at(timestamp, now)
}

fn relative_age_at(timestamp: i64, now: i64) -> String {
    let delta = now.saturating_sub(timestamp);
    if delta < 0 {
        return "in the future".to_string();
    }
    if delta < 60 {
        return "just now".to_string();
    }
    let delta = delta as u64;
    let (unit, label) = duration_unit(delta);
    format!("{}{} ago", delta / unit, label)
}

/// URL-based mainnet heuristic. Only a fallback: cluster detection normally uses
/// the genesis hash ([`crate::verification::is_mainnet_cluster`]), which identifies
/// the chain itself; this substring check is used when that RPC call fails.
pub fn is_mainnet(rpc_url: &str) -> bool {
    rpc_url.contains("mainnet")
}

/// Rent-exempt minimum for an account of `size` bytes, computed locally from
/// Solana's rent parameters: (account overhead + size) x lamports-per-byte-year
/// x years-of-rent-exemption. Used as a ceiling on what an endpoint may claim.
fn rent_exempt_minimum(size: usize) -> u64 {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    const LAMPORTS_PER_BYTE_YEAR: u64 = 3480;
    const EXEMPTION_THRESHOLD_YEARS: u64 = 2;
    (ACCOUNT_STORAGE_OVERHEAD + size as u64) * LAMPORTS_PER_BYTE_YEAR * EXEMPTION_THRESHOLD_YEARS
}

// Config management functions

/// Returns the path to the per-user config file:
/// `<OS config dir>/feature-gate-multisig-tool/config.json` (for example
/// `~/.config/feature-gate-multisig-tool/config.json` on Linux). Stable
/// regardless of the current working directory. [`CONFIG_DIR_ENV`] overrides
/// the directory entirely (used by tests).
pub fn get_config_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV).filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join(CONFIG_FILE_NAME));
    }
    let config_dir = dirs::config_dir()
        .ok_or_else(|| eyre::eyre!("Could not determine the user config directory"))?;
    Ok(config_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
}

pub fn load_config() -> Result<Config> {
    let config_path = get_config_path()?;

    if !config_path.exists() {
        // Return default config without saving - let user explicitly save when they want to
        return Ok(Config::default());
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

    // Restrict to the owning user: this records RPC endpoint URLs (which for
    // commercial providers carry an API key in the path) and the location of the
    // keypair used to sign governance transactions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| eyre::eyre!("Failed to restrict config file permissions: {}", e))?;
    }

    Ok(())
}

// Member management functions
pub fn parse_saved_members(config: &Config) -> Vec<Member> {
    let mut parsed_members: Vec<Member> = Vec::new();
    for member_str in &config.members {
        match Pubkey::from_str(member_str) {
            Ok(pubkey) => {
                // Squads rejects a member list with repeats, so a duplicate in
                // the saved config would only surface as a failed transaction.
                if parsed_members.iter().any(|m| m.key == pubkey) {
                    println!(
                        "  {} Duplicate saved member key: {}, skipping...",
                        "⚠️".bright_yellow(),
                        member_str
                    );
                    continue;
                }
                parsed_members.push(Member {
                    key: pubkey,
                    permissions: Permissions::all(), // Full permissions for saved members
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

/// Reject a member list with repeats. Squads fails such a create with
/// `MultisigError::DuplicateMember`, and it fails at send time - after the user
/// has reviewed and signed - so the list has to be checked before that.
pub fn ensure_unique_members(members: &[Member]) -> Result<()> {
    for (i, member) in members.iter().enumerate() {
        if members[..i].iter().any(|m| m.key == member.key) {
            return Err(eyre::eyre!(
                "Duplicate member {}: every member must be unique",
                member.key
            ));
        }
    }
    Ok(())
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
                if interactive_members
                    .iter()
                    .any(|m: &Member| m.key == member_key)
                {
                    println!(
                        "  {} {} is already a member; Squads rejects duplicates.",
                        "❌".bright_red(),
                        member_key.to_string().bright_white()
                    );
                    continue;
                }
                interactive_members.push(Member {
                    key: member_key,
                    permissions: Permissions::all(),
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
        if parsed_members.is_empty() {
            return Err(eyre::eyre!(
                "Saved config has no valid voting members; at least one is required"
            ));
        }
        // An explicit --threshold wins over the saved value, but must still be
        // reachable with the saved members.
        if let Some(requested) = threshold {
            if usize::from(requested) > parsed_members.len() {
                return Err(eyre::eyre!(
                    "Requested threshold {} exceeds the {} voting member(s) in the saved configuration",
                    requested,
                    parsed_members.len()
                ));
            }
            if requested != config.threshold {
                println!(
                    "  {} Using threshold {} from the command line instead of the saved {}",
                    "ℹ️".bright_cyan(),
                    requested,
                    config.threshold
                );
            }
            return Ok((requested, parsed_members));
        }
        if config.threshold == 0 || usize::from(config.threshold) > parsed_members.len() {
            println!(
                "  {} Saved threshold ({}) is invalid for {} voting member(s), prompting for new value",
                "⚠️".bright_yellow(),
                config.threshold,
                parsed_members.len()
            );
            let new_threshold = prompt_for_threshold_with_max(parsed_members.len())?;
            return Ok((new_threshold, parsed_members));
        }
        Ok((config.threshold, parsed_members))
    } else {
        println!(
            "{} Collecting configuration interactively",
            "🔄".bright_cyan()
        );

        // First collect members
        let interactive_members = collect_members_interactively()?;
        if interactive_members.is_empty() {
            return Err(eyre::eyre!(
                "At least one voting member is required to create a multisig"
            ));
        }

        // The setup keypair is added later with Initiate-only permissions and cannot vote,
        // so the threshold is capped by the voting members collected here.
        let max_voting_members = interactive_members.len();
        let final_threshold = if let Some(t) = threshold {
            if usize::from(t) > max_voting_members {
                println!(
                    "  {} CLI threshold ({}) exceeds voting member count ({}), prompting for new value",
                    "⚠️".bright_yellow(),
                    t,
                    max_voting_members
                );
                prompt_for_threshold_with_max(max_voting_members)?
            } else {
                println!("  {} Using threshold from CLI: {}", "✓".bright_green(), t);
                t
            }
        } else {
            prompt_for_threshold_with_max(max_voting_members)?
        };

        Ok((final_threshold, interactive_members))
    }
}

// Keypair management functions
pub fn expand_tilde_path(path: &str) -> Result<String> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or_else(|| eyre::eyre!("Could not find home directory"))?;
        Ok(home.join(rest).to_string_lossy().to_string())
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
        .prompt()?;

        match validate_threshold(&input, max_members) {
            Ok(t) => return Ok(t),
            Err(e) => {
                println!(
                    "  {} {}",
                    "❌".bright_red(),
                    crate::output::scrub(&e.to_string()).bright_red()
                );
            }
        }
    }
}

/// Prompt for the voting key with the saved config default pre-filled and
/// editable, so a saved identity is one Enter away but never silently binding.
/// Offers to persist a newly entered key as the default.
///
/// `config` must be the full user config (not a narrowed clone), since saving
/// writes it back to disk.
pub fn prompt_for_voting_key(config: &Config) -> Result<Pubkey> {
    let saved = config.voting_key.as_deref();
    let key = loop {
        let mut prompt = Text::new("Enter the voting key (EOA or parent multisig):");
        if let Some(saved) = saved {
            prompt = prompt.with_default(saved);
        }
        let input = prompt.prompt()?;
        match Pubkey::from_str(input.trim()) {
            Ok(key) => break key,
            Err(_) => println!(
                "  {} Invalid public key, please try again.",
                "❌".bright_red()
            ),
        }
    };

    let changed = saved != Some(key.to_string().as_str());
    if changed
        && !is_e2e_test_mode()
        && !is_assume_yes()
        && Confirm::new("Save as default voting key for future commands?")
            .with_default(true)
            .prompt()
            .unwrap_or(false)
    {
        let mut updated = config.clone();
        updated.voting_key = Some(key.to_string());
        save_config(&updated)?;
        println!("  {} Voting key saved to config.", "✓".bright_green());
    }
    Ok(key)
}

/// Resolve a `--network` argument to an RPC URL: an exact configured URL, a
/// configured network's display name (devnet/testnet/mainnet, case-insensitive),
/// or any explicit http(s) URL.
pub fn resolve_network_arg(config: &Config, arg: &str) -> Result<String> {
    let configured = if config.networks.is_empty() {
        vec![DEFAULT_DEVNET_URL.to_string()]
    } else {
        config.networks.clone()
    };
    if let Some(url) = configured.iter().find(|url| url.as_str() == arg) {
        return Ok(url.clone());
    }
    // Names come from substring matching, so several configured URLs can share
    // one. Picking the first silently sends a governance action to whichever was
    // listed earliest, so make the caller disambiguate by URL.
    let by_name: Vec<&String> = configured
        .iter()
        .filter(|url| get_network_display(url).eq_ignore_ascii_case(arg))
        .collect();
    if by_name.len() > 1 {
        return Err(eyre::eyre!(
            "'{}' matches {} configured networks: {}. Pass the full RPC URL instead.",
            arg,
            by_name.len(),
            by_name
                .iter()
                .map(|u| u.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(url) = by_name.first() {
        return Ok((*url).clone());
    }
    if arg.starts_with("http://") || arg.starts_with("https://") {
        return Ok(arg.to_string());
    }
    Err(eyre::eyre!(
        "Unknown network '{}'. Use a configured network name or URL: {}",
        arg,
        configured.join(", ")
    ))
}

/// Prompt for a pubkey with an optional editable default pre-filled.
pub fn prompt_for_pubkey_with_default(prompt: &str, default: Option<&str>) -> Result<Pubkey> {
    loop {
        let mut text = Text::new(prompt);
        if let Some(default) = default {
            text = text.with_default(default);
        }
        let input = text.prompt()?;
        match Pubkey::from_str(input.trim()) {
            Ok(key) => return Ok(key),
            Err(_) => println!(
                "  {} Invalid public key, please try again.",
                "❌".bright_red()
            ),
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
                println!(
                    "  {} {}",
                    "❌".bright_red(),
                    crate::output::scrub(&e.to_string()).bright_red()
                );
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
) -> Result<TransactionMessage> {
    create_child_vote_transaction_message(
        child_multisig,
        child_tx_index,
        parent_member_pubkey,
        ChildVoteAction::Approve,
    )
}

/// Build a TransactionMessage for a parent multisig to reject a child's proposal.
pub fn create_child_vote_reject_transaction_message(
    child_multisig: Pubkey,
    child_tx_index: u64,
    parent_member_pubkey: Pubkey,
) -> Result<TransactionMessage> {
    create_child_vote_transaction_message(
        child_multisig,
        child_tx_index,
        parent_member_pubkey,
        ChildVoteAction::Reject,
    )
}

enum ChildVoteAction {
    Approve,
    Reject,
}

fn create_child_vote_transaction_message(
    child_multisig: Pubkey,
    child_tx_index: u64,
    parent_member_pubkey: Pubkey,
    action: ChildVoteAction,
) -> Result<TransactionMessage> {
    use crate::squads::{
        get_proposal_pda, InstructionData, MultisigApproveProposalData, MultisigRejectProposalData,
        MultisigVoteOnProposalAccounts, MultisigVoteOnProposalArgs, SQUADS_MULTISIG_PROGRAM_ID,
    };
    use solana_instruction::Instruction;

    let (proposal_pda, _bump) = get_proposal_pda(&child_multisig, child_tx_index);

    let accounts = MultisigVoteOnProposalAccounts {
        multisig: child_multisig,
        member: parent_member_pubkey,
        proposal: proposal_pda,
    };
    let args = MultisigVoteOnProposalArgs { memo: None };
    let data = match action {
        ChildVoteAction::Approve => MultisigApproveProposalData { args }.data()?,
        ChildVoteAction::Reject => MultisigRejectProposalData { args }.data()?,
    };

    let ix = Instruction::new_with_bytes(
        SQUADS_MULTISIG_PROGRAM_ID,
        &data,
        accounts.to_account_metas(),
    );

    build_squads_transaction_message(&parent_member_pubkey, &[ix], &[])
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
pub fn create_and_send_funding_transaction(
    rpc_url: &str,
    fee_payer_signer: &dyn Signer,
    feature_gate_address: &Pubkey,
) -> Result<String> {
    use crate::feature_gate_program::FEATURE_ACCOUNT_SIZE;
    use solana_system_interface::instruction::transfer;

    let rpc_client = create_rpc_client(rpc_url);

    // This value is signed into a transfer out of the fee payer, so it cannot be
    // taken on the endpoint's word. Rent for a fixed-size account is locally
    // computable, so treat the local figure as a ceiling and only accept a
    // smaller answer.
    let rent = rpc_client.get_minimum_balance_for_rent_exemption(FEATURE_ACCOUNT_SIZE)?;
    let expected = rent_exempt_minimum(FEATURE_ACCOUNT_SIZE);
    if rent > expected {
        return Err(eyre::eyre!(
            "Endpoint reports {rent} lamports of rent for a {FEATURE_ACCOUNT_SIZE}-byte account,              more than the {expected} this size can require. Refusing to sign a transfer of that amount."
        ));
    }

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

    let message = Message::try_compile(
        &fee_payer_signer.pubkey(),
        &[transfer_ix],
        &[],
        recent_blockhash,
    )
    .map_err(|e| eyre::eyre!("Failed to compile funding transaction message: {}", e))?;

    let transaction =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[fee_payer_signer])
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
        match Pubkey::from_str(input.trim()) {
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

pub fn validate_threshold(input: &str, max_members: usize) -> Result<u16> {
    if input.trim().is_empty() {
        return Err(eyre::eyre!("Threshold is required"));
    }

    match input.trim().parse::<u16>() {
        Ok(0) => Err(eyre::eyre!("Threshold must be at least 1")),
        Ok(threshold) if usize::from(threshold) > max_members => Err(eyre::eyre!(
            "Threshold cannot exceed number of voting members ({})",
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

/// The host of an http(s) URL: the authority with any userinfo and port
/// removed. `None` when the URL has no http(s) scheme.
fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // `\` ends the authority too: for http(s) the URL parser the client uses
    // treats it as `/`, so `http://evil.example\@localhost` connects to
    // evil.example. Reading past it here would name the wrong host.
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    // `user:pass@host`: the host is what the client actually connects to, so a
    // look-alike parked in the userinfo must not be read as the destination.
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    // Strip the port, keeping bracketed IPv6 literals intact. An unclosed
    // bracket is not a host at all.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']')?.0,
        None => host.split(':').next().unwrap_or(""),
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Whether a host (as returned by [`url_host`]) addresses this machine. This
/// gates plain HTTP, so it is strict: the literal name `localhost`, or an IP
/// literal in the loopback range. A prefix match such as `127.` would accept
/// `127.0.0.1.example.net`, and `*.localhost` is not loopback on every resolver.
fn is_loopback_host(host: &str) -> bool {
    use std::net::IpAddr;
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Whether the URL looks like a Solana RPC endpoint. The check is on the parsed
/// host, not on a substring of the whole URL: `https://ssolana.com/mainnet`,
/// `https://solana.com.example.net` and `https://evil.example/?x=solana.com`
/// all contain "solana.com" without being one, and a typo like that is exactly
/// what this warning exists to catch.
fn looks_like_solana_rpc(url: &str) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    if is_loopback_host(host) {
        return true;
    }
    let host = host.to_ascii_lowercase();
    if host == "solana.com" || host.ends_with(".solana.com") {
        return true;
    }
    // Providers usually name themselves in the host: rpc.example.com,
    // mainnet.example-rpc.com. A path or query saying "rpc" proves nothing.
    host.split('.').any(|label| label.contains("rpc"))
}

/// Interactive RPC URL validation: the same structural rules as the CLI
/// ([`check_rpc_url`]), then a confirmation when the host does not look like a
/// Solana RPC provider. Both entry points refuse the same URLs; only the
/// "unusual host" step differs, because a prompt is available here.
pub fn validate_rpc_url(url: &str) -> Result<String> {
    let url = url.trim();

    if url.is_empty() {
        return Err(eyre::eyre!("URL cannot be empty"));
    }
    check_rpc_url(url).map_err(|e| eyre::eyre!(e))?;

    // Check for common Solana RPC patterns
    if !looks_like_solana_rpc(url) {
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

    // Nothing to choose: a single configured network is used as-is.
    if available_networks.len() == 1 {
        return Ok(available_networks[0].to_string());
    }

    // Non-interactive mode for E2E tests
    if is_e2e_test_mode() {
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

    println!();
    println!("{}", "Saved Network Configuration".bold().bright_yellow(),);
    println!();
    println!(
        "  {}: {}",
        "Networks".cyan(),
        available_networks.len().to_string().cyan()
    );
    for (i, network) in available_networks.iter().enumerate() {
        let network_name = get_network_display(network);
        println!(
            "    {}: {} ({})",
            format!("Network {}", i + 1).cyan(),
            network_name.bright_white(),
            network.bright_white()
        );
    }
    // Auto-confirm in E2E test mode
    let use_saved_networks = if is_e2e_test_mode() {
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
    println!();
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
    println!();
    println!(
        "  {}: {}",
        "Threshold".cyan(),
        config.threshold.to_string().bright_green()
    );

    // Show fee payer path
    println!();
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

    println!();
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
    let use_config = if is_e2e_test_mode() {
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
pub fn check_fee_payer_balance_on_networks(
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
        let network_display = get_network_display(network);

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

/// clap value parser for a public key argument. Parsing at the argument
/// boundary means a command can never receive an address it forgot to check,
/// and a typo is reported before any network call or prompt happens.
pub fn parse_pubkey_arg(input: &str) -> std::result::Result<Pubkey, String> {
    let input = input.trim();
    Pubkey::from_str(input).map_err(|_| format!("'{input}' is not a valid base58-encoded address"))
}

/// clap value parser for `--network`: either the name of a configured network
/// or an RPC URL. Names are resolved against the config later
/// (`resolve_network_arg`); URLs are checked here, so a mistyped endpoint is
/// rejected at the source rather than dialled.
pub fn parse_network_arg(input: &str) -> std::result::Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("network cannot be empty".to_string());
    }
    if input.contains("://") {
        check_rpc_url(input)?;
    } else if input.chars().any(char::is_whitespace) {
        return Err(format!(
            "'{input}' is not a network name or an RPC URL (URLs must start with https://)"
        ));
    }
    Ok(input.to_string())
}

/// Structural RPC URL check, shared by the CLI value parser and the interactive
/// validator. Plain HTTP is refused off the loopback interface: a governance
/// action must not be sent, nor its reply trusted, over a connection anything
/// on the path can rewrite. Returns a plain `String` error so clap can print it.
pub fn check_rpc_url(url: &str) -> std::result::Result<(), String> {
    if url.chars().any(char::is_whitespace) {
        return Err(format!("RPC URL '{url}' contains whitespace"));
    }
    let is_https = url.starts_with("https://");
    let is_http = url.starts_with("http://");
    if !is_https && !is_http {
        return Err(format!("RPC URL '{url}' must start with https://"));
    }
    let Some(host) = url_host(url) else {
        return Err(format!("RPC URL '{url}' has no host"));
    };
    if is_http && !is_loopback_host(host) {
        return Err(format!(
            "RPC URL '{url}' uses plain HTTP; use https:// (http:// is allowed only for localhost)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_lock_rendering() {
        assert_eq!(format_time_lock(0), "none");
        assert_eq!(format_time_lock(45), "45s");
        assert_eq!(format_time_lock(60), "60s (1m)");
        assert_eq!(format_time_lock(90), "90s (~1m)");
        assert_eq!(format_time_lock(3600), "3600s (1h)");
        assert_eq!(format_time_lock(5400), "5400s (~1h)");
        assert_eq!(format_time_lock(172_800), "172800s (2d)");
    }

    /// Status timestamps are on-chain data: extreme and future values must
    /// render as text, never wrap or panic.
    #[test]
    fn relative_age_rendering() {
        let now = 1_755_000_000;
        assert_eq!(relative_age_at(now, now), "just now");
        assert_eq!(relative_age_at(now - 59, now), "just now");
        assert_eq!(relative_age_at(now - 120, now), "2m ago");
        assert_eq!(relative_age_at(now - 7_200, now), "2h ago");
        assert_eq!(relative_age_at(now - 300_000, now), "3d ago");
        assert_eq!(relative_age_at(now + 500, now), "in the future");
        assert_eq!(
            relative_age_at(i64::MIN, now),
            format!("{}d ago", i64::MAX as u64 / 86_400)
        );
        assert_eq!(relative_age_at(i64::MAX, now), "in the future");
    }

    #[test]
    fn flag_values_that_mean_off_are_off() {
        for off in ["", " ", "0", "false", "FALSE", "no", "off", " Off "] {
            assert!(!flag_value_enabled(off), "{off:?} should read as off");
        }
        for on in ["1", "true", "yes", "on", "anything"] {
            assert!(flag_value_enabled(on), "{on:?} should read as on");
        }
    }

    /// A released build must have no environment-variable path to auto-confirm.
    #[test]
    #[cfg(not(feature = "e2e-harness"))]
    fn e2e_mode_is_compiled_out_of_release_builds() {
        std::env::set_var("E2E_TEST_MODE", "1");
        assert!(!is_e2e_test_mode());
        std::env::remove_var("E2E_TEST_MODE");
    }

    /// The ceiling has to equal what a real validator reports, or every create
    /// would fail. Verified against surfpool: 953,520 lamports for 9 bytes.
    #[test]
    fn rent_ceiling_matches_the_chain() {
        use crate::feature_gate_program::FEATURE_ACCOUNT_SIZE;
        assert_eq!(rent_exempt_minimum(FEATURE_ACCOUNT_SIZE), 953_520);
        // Larger accounts cost more, so the ceiling scales rather than being a
        // single hardcoded number.
        assert!(rent_exempt_minimum(FEATURE_ACCOUNT_SIZE + 1) > 953_520);
    }

    /// The config records RPC URLs (which for commercial providers carry an API
    /// key in the path) and the path of the signing keypair, so it must not be
    /// world-readable.
    #[cfg(unix)]
    #[test]
    fn saved_config_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("fgm-perm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        std::env::set_var(CONFIG_DIR_ENV, &dir);

        save_config(&Config::default()).expect("save config");

        let path = get_config_path().expect("config path");
        let mode = std::fs::metadata(&path)
            .expect("stat config")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "config should be owner-only, got {:o}",
            mode & 0o777
        );

        std::env::remove_var(CONFIG_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Squads rejects a create whose member list repeats a key, and it does so
    /// only at send time - after the user has reviewed and signed.
    #[test]
    fn duplicate_members_are_rejected() {
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        let member = |key| Member {
            key,
            permissions: Permissions::all(),
        };

        ensure_unique_members(&[member(a), member(b)]).unwrap();

        let err = ensure_unique_members(&[member(a), member(b), member(a)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("Duplicate member"), "got: {err}");
        assert!(err.contains(&a.to_string()), "got: {err}");
    }

    /// A hand-edited config can repeat a key; the second copy is dropped rather
    /// than carried into a transaction that cannot succeed.
    #[test]
    fn saved_members_are_deduplicated() {
        let a = Pubkey::new_unique().to_string();
        let b = Pubkey::new_unique().to_string();
        let config = Config {
            members: vec![a.clone(), b.clone(), a.clone()],
            ..Config::default()
        };

        let members = parse_saved_members(&config);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].key.to_string(), a);
        assert_eq!(members[1].key.to_string(), b);
        ensure_unique_members(&members).unwrap();
    }

    /// The old check matched "solana.com" anywhere in the URL, so a typo'd or
    /// look-alike host passed silently. Match the host itself.
    #[test]
    fn rpc_host_check_rejects_lookalike_urls() {
        for url in [
            "https://api.mainnet-beta.solana.com",
            "https://solana.com",
            "https://api.devnet.solana.com/",
            "http://localhost:8899",
            "http://127.0.0.1:8899",
            "https://mainnet.helius-rpc.com/?api-key=secret",
            "https://rpc.example.net",
        ] {
            assert!(looks_like_solana_rpc(url), "should be accepted: {url}");
        }

        for url in [
            // Typo: an extra letter in the domain.
            "https://ssolana.com/mainnet",
            "https://soolana.com/mainnet",
            // The real host is the suffix, not the "solana.com" prefix.
            "https://solana.com.example.net",
            // "solana.com" in the userinfo, the path, or the query.
            "https://solana.com@example.net",
            "https://example.net/solana.com",
            "https://example.net/?url=solana.com",
            // Not an http(s) URL at all.
            "ftp://api.solana.com",
        ] {
            assert!(!looks_like_solana_rpc(url), "should warn: {url}");
        }
    }

    #[test]
    fn url_host_strips_userinfo_port_and_path() {
        assert_eq!(
            url_host("https://api.devnet.solana.com/v1"),
            Some("api.devnet.solana.com")
        );
        assert_eq!(
            url_host("http://user:pass@127.0.0.1:8899"),
            Some("127.0.0.1")
        );
        assert_eq!(url_host("http://[::1]:8899/rpc"), Some("::1"));
        assert_eq!(
            url_host("https://api.devnet.solana.com./"),
            Some("api.devnet.solana.com")
        );
        assert_eq!(url_host("https://"), None);
        assert_eq!(url_host("api.devnet.solana.com"), None);
    }

    /// Sanitizing at the argument boundary: a mistyped address or endpoint is
    /// rejected before the command runs, not by whichever call site remembered
    /// to check.
    #[test]
    fn pubkey_args_are_parsed_at_the_boundary() {
        let key = Pubkey::new_unique();
        assert_eq!(parse_pubkey_arg(&format!("  {key} ")).unwrap(), key);

        let err = parse_pubkey_arg("not-a-key").unwrap_err();
        assert!(err.contains("base58"), "got: {err}");
    }

    #[test]
    fn network_args_accept_names_and_https_urls() {
        assert_eq!(parse_network_arg(" devnet ").unwrap(), "devnet");
        assert_eq!(
            parse_network_arg("https://api.devnet.solana.com").unwrap(),
            "https://api.devnet.solana.com"
        );
        // Loopback endpoints are how local validators are reached.
        assert_eq!(
            parse_network_arg("http://127.0.0.1:8899").unwrap(),
            "http://127.0.0.1:8899"
        );
        assert_eq!(
            parse_network_arg("http://[::1]:8899").unwrap(),
            "http://[::1]:8899"
        );

        for bad in [
            "",
            "http://soolana.com/mainnet",
            "ws://api.devnet.solana.com",
            "https://",
            "my network",
            // Only the loopback carve-out may be plain HTTP.
            "http://[2001:db8::1]:8899",
            "http://10.0.0.5:8899",
            "http://localhost.example.net",
        ] {
            assert!(parse_network_arg(bad).is_err(), "should be rejected: {bad}");
        }
    }

    /// One host parser serves both the CLI check and the interactive validator,
    /// so userinfo and ports are handled the same way in each.
    #[test]
    fn rpc_url_check_reads_the_parsed_host() {
        for ok in [
            "http://user:pw@127.0.0.1:8899/",
            "http://127.0.0.1:8899",
            "http://127.255.255.254:8899",
            "http://[::1]:8899",
            "http://LOCALHOST:8899",
            "https://api.devnet.solana.com",
        ] {
            check_rpc_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }

        // Plain HTTP to anything that is not this machine, however it is dressed.
        for bad in [
            // The loopback name is in the userinfo; the real host is not local.
            "http://localhost@example.net:8899",
            // A backslash ends the authority for the client's URL parser, so
            // this connects to evil.example, not localhost.
            "http://evil.example\\@localhost:8899",
            // Loopback as a prefix of a remote name.
            "http://127.0.0.1.example.net:8899",
            "http://127.example.net",
            // Not loopback ranges.
            "http://0.0.0.0:8899",
            "http://[::ffff:127.0.0.1]:8899",
            // A subdomain of localhost is not loopback on every resolver.
            "http://validator.localhost:8899",
        ] {
            let err = check_rpc_url(bad).unwrap_err();
            assert!(err.contains("plain HTTP"), "{bad}: {err}");
        }

        for (bad, expected) in [
            ("https://", "no host"),
            ("https://user@", "no host"),
            ("http://[::1:8899", "no host"),
            ("ws://api.devnet.solana.com", "must start with https://"),
            ("HTTPS://api.devnet.solana.com", "must start with https://"),
            ("https://api.devnet.solana.com/ rpc", "whitespace"),
        ] {
            let err = check_rpc_url(bad).unwrap_err();
            assert!(err.contains(expected), "{bad}: {err}");
        }
    }

    #[test]
    fn resolves_network_arg_by_url_name_or_passthrough() {
        let config = Config {
            networks: vec![
                "https://api.devnet.solana.com".to_string(),
                "https://api.mainnet.solana.com".to_string(),
            ],
            ..Config::default()
        };

        // Exact configured URL.
        assert_eq!(
            resolve_network_arg(&config, "https://api.devnet.solana.com").unwrap(),
            "https://api.devnet.solana.com"
        );
        // Display name, case-insensitive, resolves to the configured URL.
        assert_eq!(
            resolve_network_arg(&config, "Mainnet").unwrap(),
            "https://api.mainnet.solana.com"
        );
        // Unconfigured but explicit URLs pass through.
        assert_eq!(
            resolve_network_arg(&config, "http://127.0.0.1:8899").unwrap(),
            "http://127.0.0.1:8899"
        );
        // Anything else is an error naming the configured options.
        let err = resolve_network_arg(&config, "testnet")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unknown network"));
        assert!(err.contains("https://api.devnet.solana.com"));
    }

    /// Names come from substring matching, so two endpoints can share one. The
    /// action must not silently go to whichever was configured first.
    #[test]
    fn ambiguous_network_name_is_rejected() {
        let config = Config {
            networks: vec![
                "https://rpc.provider.example/mainnet-tenant".to_string(),
                "https://api.mainnet.solana.com".to_string(),
            ],
            ..Config::default()
        };

        let err = resolve_network_arg(&config, "mainnet")
            .unwrap_err()
            .to_string();
        assert!(err.contains("matches 2 configured networks"), "got: {err}");
        assert!(err.contains("https://api.mainnet.solana.com"), "got: {err}");

        // An exact URL is still unambiguous even when the name is not.
        assert_eq!(
            resolve_network_arg(&config, "https://api.mainnet.solana.com").unwrap(),
            "https://api.mainnet.solana.com"
        );
    }
}
