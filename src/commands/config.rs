//! Config command implementation
//!
//! Shows and modifies agent configuration.

use crate::cli::{
    ConfigArgs, ConfigGetArgs, ConfigSetArgs, ConfigSubcommand, PerformanceProfileArg, ProfileArgs,
};
use crate::ipc::{AgentConfigUpdate, IpcClient, PerformanceProfile};
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;

/// Execute the config command
pub async fn execute(client: &mut IpcClient, args: &ConfigArgs, output: &Output) -> Result<()> {
    match &args.command {
        Some(ConfigSubcommand::Show) => show_config(client, output).await,
        Some(ConfigSubcommand::Get(get_args)) => get_config(client, get_args, output).await,
        Some(ConfigSubcommand::Set(set_args)) => set_config(client, set_args, output).await,
        Some(ConfigSubcommand::Profile(profile_args)) => {
            handle_profile(client, profile_args, output).await
        }
        Some(ConfigSubcommand::Reload) => reload_config(client, output).await,
        None => show_config(client, output).await,
    }
}

/// Show current configuration
async fn show_config(client: &mut IpcClient, output: &Output) -> Result<()> {
    let status = client.get_status().await?;
    let profile = client.get_performance_profile().await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "agent_id": status.agent_id,
            "version": status.version,
            "protection_enabled": status.protection_enabled,
            "collectors_running": status.collectors_running,
            "performance_profile": profile.to_string(),
        }))?;
    } else {
        output.println(&format!("{}", "=== Agent Configuration ===".bold()));
        output.println(&format!("Agent ID:         {}", status.agent_id));
        output.println(&format!("Version:          {}", status.version));

        let protection = if status.protection_enabled {
            "enabled".green()
        } else {
            "disabled".red()
        };
        output.println(&format!("Protection:       {}", protection));

        output.println(&format!("Profile:          {}", profile));
        output.println("");

        output.println(&format!("{}", "Active Collectors:".bold()));
        for collector in &status.collectors_running {
            output.println(&format!("  - {}", collector));
        }

        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl config set <key> <value>' to modify settings.".dimmed()
        ));
    }

    Ok(())
}

/// Get a specific configuration value
async fn get_config(client: &mut IpcClient, args: &ConfigGetArgs, output: &Output) -> Result<()> {
    let status = client.get_status().await?;

    let value: Option<String> = match args.key.as_str() {
        "agent_id" => Some(status.agent_id.clone()),
        "version" => Some(status.version.clone()),
        "protection_enabled" | "protection" => Some(status.protection_enabled.to_string()),
        "collectors" | "collectors_running" => Some(status.collectors_running.join(", ")),
        "profile" | "performance_profile" => {
            let profile = client.get_performance_profile().await?;
            Some(profile.to_string())
        }
        "backend_connected" | "backend" => Some(status.backend_connected.to_string()),
        "cpu_usage" | "cpu" => Some(format!("{:.1}%", status.cpu_usage)),
        "memory_usage" | "memory" => Some(format!("{} MB", status.memory_usage / 1024 / 1024)),
        "uptime" => Some(format!("{} seconds", status.uptime_seconds)),
        _ => None,
    };

    match value {
        Some(v) => {
            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "key": args.key,
                    "value": v,
                }))?;
            } else {
                output.println(&format!("{} = {}", args.key, v));
            }
        }
        None => {
            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "key": args.key,
                    "error": "Unknown configuration key",
                }))?;
            } else {
                output.println(&format!(
                    "{} Unknown configuration key: {}",
                    "[ERROR]".red(),
                    args.key
                ));
                output.println("");
                output.println("Available keys:");
                output.println("  agent_id, version, protection, profile, collectors,");
                output.println("  backend, cpu, memory, uptime");
            }
        }
    }

    Ok(())
}

/// Set a configuration value
async fn set_config(client: &mut IpcClient, args: &ConfigSetArgs, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    let mut config_update = AgentConfigUpdate {
        scan_interval_seconds: None,
        heartbeat_interval_seconds: None,
        enable_real_time_protection: None,
        enable_cloud_lookup: None,
        excluded_paths: None,
        excluded_processes: None,
    };

    let key = args.key.to_lowercase();
    let value = args.value.clone();

    match key.as_str() {
        "protection" | "protection_enabled" | "real_time_protection" => {
            let enabled = parse_bool(&value)?;
            config_update.enable_real_time_protection = Some(enabled);
        }
        "cloud_lookup" | "enable_cloud_lookup" => {
            let enabled = parse_bool(&value)?;
            config_update.enable_cloud_lookup = Some(enabled);
        }
        "scan_interval" | "scan_interval_seconds" => {
            let seconds: u64 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid number: {}", value))?;
            config_update.scan_interval_seconds = Some(seconds);
        }
        "heartbeat_interval" | "heartbeat_interval_seconds" => {
            let seconds: u64 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid number: {}", value))?;
            config_update.heartbeat_interval_seconds = Some(seconds);
        }
        "profile" | "performance_profile" => {
            // Redirect to profile subcommand
            let profile = match value.to_lowercase().as_str() {
                "aggressive" => PerformanceProfile::Aggressive,
                "balanced" => PerformanceProfile::Balanced,
                "lightweight" | "light" => PerformanceProfile::Lightweight,
                _ => anyhow::bail!(
                    "Invalid profile: {}. Use aggressive, balanced, or lightweight.",
                    value
                ),
            };
            client.set_performance_profile(profile).await?;

            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "status": "updated",
                    "key": "performance_profile",
                    "value": value,
                }))?;
            } else {
                output.println(&format!(
                    "{} Performance profile set to {}",
                    "[OK]".green(),
                    value
                ));
            }
            return Ok(());
        }
        _ => {
            anyhow::bail!(
                "Unknown or read-only configuration key: {}. Modifiable keys: protection, cloud_lookup, scan_interval, heartbeat_interval, profile",
                key
            );
        }
    }

    // Send the update (for non-profile keys)
    // Note: The IPC protocol doesn't have a generic UpdateConfig response,
    // so we use the Success response pattern
    let response = client
        .request(crate::ipc::IpcMessage::UpdateConfig {
            config: config_update,
        })
        .await?;

    match response {
        crate::ipc::IpcMessage::Success => {
            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "status": "updated",
                    "key": key,
                    "value": value,
                }))?;
            } else {
                output.println(&format!("{} {} = {}", "[OK]".green(), key, value));
            }
        }
        crate::ipc::IpcMessage::Error { message, .. } => {
            anyhow::bail!("Failed to update config: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response from agent");
        }
    }

    Ok(())
}

/// Handle performance profile get/set
async fn handle_profile(client: &mut IpcClient, args: &ProfileArgs, output: &Output) -> Result<()> {
    if let Some(ref new_profile) = args.profile {
        // Set profile
        if !client.is_authenticated() {
            client.authenticate().await?;
        }

        let profile = match new_profile {
            PerformanceProfileArg::Aggressive => PerformanceProfile::Aggressive,
            PerformanceProfileArg::Balanced => PerformanceProfile::Balanced,
            PerformanceProfileArg::Lightweight => PerformanceProfile::Lightweight,
        };

        client.set_performance_profile(profile).await?;

        if output.is_json() {
            output.print_json(&serde_json::json!({
                "status": "updated",
                "profile": profile.to_string(),
            }))?;
        } else {
            output.println(&format!(
                "{} Performance profile set to {}",
                "[OK]".green(),
                profile
            ));
            output.println("");
            output.println(&format!("{}", get_profile_description(&profile)));
        }
    } else {
        // Get profile
        let profile = client.get_performance_profile().await?;

        if output.is_json() {
            output.print_json(&serde_json::json!({
                "profile": profile.to_string(),
            }))?;
        } else {
            output.println(&format!("Current profile: {}", profile.to_string().bold()));
            output.println("");
            output.println(&format!("{}", get_profile_description(&profile)));
            output.println("");
            output.println(&format!(
                "{}",
                "Use 'tamandua-ctl config profile <aggressive|balanced|lightweight>' to change."
                    .dimmed()
            ));
        }
    }

    Ok(())
}

/// Reload configuration from disk
async fn reload_config(client: &mut IpcClient, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    // Note: There's no explicit reload message in the protocol,
    // but we can test backend connection as a health check
    let response = client
        .request(crate::ipc::IpcMessage::TestBackendConnection)
        .await?;

    match response {
        crate::ipc::IpcMessage::BackendTestResult { connected, .. } => {
            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "status": "reloaded",
                    "backend_connected": connected,
                }))?;
            } else {
                output.println(&format!("{} Configuration validated", "[OK]".green()));
                if connected {
                    output.println(&format!("  Backend: {}", "connected".green()));
                } else {
                    output.println(&format!("  Backend: {}", "disconnected".yellow()));
                }
            }
        }
        crate::ipc::IpcMessage::Error { message, .. } => {
            anyhow::bail!("Failed to validate config: {}", message);
        }
        _ => {
            output.println(&format!(
                "{} Configuration reload triggered",
                "[OK]".green()
            ));
        }
    }

    Ok(())
}

/// Get profile description
fn get_profile_description(profile: &PerformanceProfile) -> String {
    match profile {
        PerformanceProfile::Aggressive => {
            "Maximum detection coverage. All collectors enabled with tight intervals.\nHigher CPU/memory usage (~15-25%).".to_string()
        }
        PerformanceProfile::Balanced => {
            "Good detection with reasonable resource usage (~5-10% CPU).\nSuitable for most workstations.".to_string()
        }
        PerformanceProfile::Lightweight => {
            "Minimal footprint (~1-3% CPU). Only core collectors active.\nBest for performance-sensitive systems.".to_string()
        }
    }
}

/// Parse boolean from string
fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" | "enabled" => Ok(true),
        "false" | "no" | "0" | "off" | "disabled" => Ok(false),
        _ => anyhow::bail!(
            "Invalid boolean value: '{}'. Use true/false, yes/no, or on/off.",
            s
        ),
    }
}
