//! Version command implementation
//!
//! Shows version information for the CLI and agent.

use crate::ipc::IpcClient;
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;

/// CLI version
const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Execute the version command
pub async fn execute(client: &mut IpcClient, output: &Output) -> Result<()> {
    // Get agent version
    let agent_version = match client.get_version().await {
        Ok(v) => Some(v),
        Err(e) => {
            if !output.is_json() {
                output.println(&format!(
                    "{} Could not get agent version: {}",
                    "[WARN]".yellow(),
                    e
                ));
            }
            None
        }
    };

    if output.is_json() {
        let mut json = serde_json::json!({
            "cli": {
                "version": CLI_VERSION,
            }
        });

        if let Some(ref v) = agent_version {
            json["agent"] = serde_json::json!({
                "version": v.version,
                "build_date": v.build_date,
                "commit_hash": v.commit_hash,
                "rust_version": v.rust_version,
            });
        }

        output.print_json(&json)?;
    } else {
        output.println(&format!(
            "{}",
            "=== Tamandua Version Information ===".bold()
        ));
        output.println("");

        output.println(&format!("{}", "CLI:".bold()));
        output.println(&format!("  Version: {}", CLI_VERSION));
        output.println("");

        if let Some(v) = agent_version {
            output.println(&format!("{}", "Agent:".bold()));
            output.println(&format!("  Version:      {}", v.version));
            output.println(&format!("  Build Date:   {}", v.build_date));
            output.println(&format!("  Commit:       {}", v.commit_hash));
            output.println(&format!("  Rust Version: {}", v.rust_version));
        } else {
            output.println(&format!("{}", "Agent: Not available".dimmed()));
        }
    }

    Ok(())
}
