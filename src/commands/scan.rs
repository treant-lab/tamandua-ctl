//! Scan command implementation
//!
//! Starts, monitors, and manages on-demand file scans.

use crate::cli::{ScanArgs, ScanCancelArgs, ScanHistoryArgs, ScanStartArgs, ScanSubcommand};
use crate::ipc::IpcClient;
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;

/// Execute the scan command
pub async fn execute(client: &mut IpcClient, args: &ScanArgs, output: &Output) -> Result<()> {
    match &args.command {
        ScanSubcommand::Start(start_args) => start_scan(client, start_args, output).await,
        ScanSubcommand::Status => show_status(client, output).await,
        ScanSubcommand::Cancel(cancel_args) => cancel_scan(client, cancel_args, output).await,
        ScanSubcommand::History(history_args) => show_history(client, history_args, output).await,
    }
}

/// Start a new scan
async fn start_scan(client: &mut IpcClient, args: &ScanStartArgs, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    // Verify path exists
    if !args.path.exists() {
        anyhow::bail!("Path does not exist: {}", args.path.display());
    }

    let path_display = args.path.display().to_string();

    client
        .start_scan(args.path.clone(), args.recursive, args.archives)
        .await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "started",
            "path": path_display,
            "recursive": args.recursive,
            "scan_archives": args.archives,
        }))?;
    } else {
        output.println(&format!(
            "{} Scan started for: {}",
            "[OK]".green(),
            path_display
        ));
        output.println(&format!("  Recursive: {}", args.recursive));
        output.println(&format!("  Scan archives: {}", args.archives));

        if args.wait {
            output.println("");
            output.println("Waiting for scan to complete...");
            // Note: In a real implementation, we would poll for scan progress
            // For now, we just indicate the scan was started
            output.println(&format!(
                "{}",
                "Use 'tamandua-ctl scan status' to check progress.".dimmed()
            ));
        } else {
            output.println("");
            output.println(&format!(
                "{}",
                "Use 'tamandua-ctl scan status' to check progress.".dimmed()
            ));
        }
    }

    Ok(())
}

/// Show current scan status
async fn show_status(client: &mut IpcClient, output: &Output) -> Result<()> {
    let status = client.get_status().await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "scan_in_progress": status.scan_in_progress,
        }))?;
    } else if status.scan_in_progress {
        output.println(&format!("{}", "=== Scan in Progress ===".bold()));
        output.println("A scan is currently running.");
        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl scan cancel' to stop the scan.".dimmed()
        ));
    } else {
        output.println("No scan in progress.");
        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl scan start <path>' to start a new scan.".dimmed()
        ));
    }

    Ok(())
}

/// Cancel a running scan
async fn cancel_scan(client: &mut IpcClient, args: &ScanCancelArgs, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    let scan_id = args
        .scan_id
        .clone()
        .unwrap_or_else(|| "current".to_string());

    let response = client
        .request(crate::ipc::IpcMessage::CancelScan {
            scan_id: scan_id.clone(),
        })
        .await?;

    match response {
        crate::ipc::IpcMessage::Success => {
            if output.is_json() {
                output.print_json(&serde_json::json!({
                    "status": "cancelled",
                    "scan_id": scan_id,
                }))?;
            } else {
                output.println(&format!("{} Scan cancelled", "[OK]".green()));
            }
        }
        crate::ipc::IpcMessage::Error { message, .. } => {
            anyhow::bail!("Failed to cancel scan: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response from agent");
        }
    }

    Ok(())
}

/// Show scan history
async fn show_history(
    client: &mut IpcClient,
    _args: &ScanHistoryArgs,
    output: &Output,
) -> Result<()> {
    // Note: The current IPC protocol doesn't have a GetScanHistory message
    // This is a stub that indicates the feature isn't available yet

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "error": "Scan history not yet available via IPC",
            "history": [],
        }))?;
    } else {
        output.println(&format!("{}", "=== Scan History ===".bold()));
        output.println("");
        output.println(&format!(
            "{}",
            "Scan history is not yet available via the CLI.".yellow()
        ));
        output.println("Check the web dashboard for historical scan results.");
    }

    Ok(())
}
