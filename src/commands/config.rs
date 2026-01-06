use crate::output::Output;
use crate::utils::*;
use eyre::Result;

pub async fn config_command(config: &Config) -> Result<()> {
    let config_path = get_config_path()?;
    let config_path_str = config_path.to_string_lossy();

    Output::header(&format!("📋 Configuration: {}", config_path_str));
    Output::field(
        "Saved members",
        &format!("{} members", config.members.len()),
    );

    if !config.members.is_empty() {
        for (i, member) in config.members.iter().enumerate() {
            Output::numbered_field(i + 1, "Member", member);
        }
    }

    Output::separator();
    Output::field("Threshold", &config.threshold.to_string());

    // Display fee payer path
    Output::separator();
    if let Some(fee_payer_path) = &config.fee_payer_path {
        Output::config_item("Fee payer keypair", fee_payer_path);
    } else {
        Output::config_item("Fee payer keypair", "");
    }

    // Display networks array if available, otherwise show legacy single network
    if !config.networks.is_empty() {
        Output::separator();
        Output::field(
            "Saved networks",
            &format!("{} networks", config.networks.len()),
        );
        for (i, network) in config.networks.iter().enumerate() {
            Output::numbered_field(i + 1, "Network", network);
        }
    }

    Ok(())
}
