//! Quarantine command implementation
//!
//! Lists, restores, and manages quarantined files.

use crate::cli::{
    QuarantineArgs, QuarantineDeleteArgs, QuarantineListArgs, QuarantineRestoreArgs,
    QuarantineShowArgs, QuarantineSubcommand,
};
use crate::ipc::IpcClient;
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

/// Execute the quarantine command
pub async fn execute(client: &mut IpcClient, args: &QuarantineArgs, output: &Output) -> Result<()> {
    match &args.command {
        Some(QuarantineSubcommand::List(list_args)) => list_files(client, list_args, output).await,
        Some(QuarantineSubcommand::Show(show_args)) => show_entry(client, show_args, output).await,
        Some(QuarantineSubcommand::Restore(restore_args)) => {
            restore_file(client, restore_args, output).await
        }
        Some(QuarantineSubcommand::Delete(delete_args)) => {
            delete_file(client, delete_args, output).await
        }
        None => {
            // Default: list quarantined files
            list_files(client, &QuarantineListArgs { limit: 50 }, output).await
        }
    }
}

/// List quarantined files
async fn list_files(
    client: &mut IpcClient,
    args: &QuarantineListArgs,
    output: &Output,
) -> Result<()> {
    let files = client.get_quarantined_files().await?;

    let files: Vec<_> = files.into_iter().take(args.limit).collect();

    if output.is_json() {
        output.print_json(&files)?;
    } else if files.is_empty() {
        output.println("No files in quarantine.");
    } else {
        #[derive(Tabled)]
        struct QuarantineRow {
            id: String,
            #[tabled(rename = "quarantined_at")]
            time: String,
            threat: String,
            #[tabled(rename = "original_path")]
            path: String,
            size: String,
        }

        let rows: Vec<QuarantineRow> = files
            .iter()
            .map(|f| QuarantineRow {
                id: truncate(&f.id, 8),
                time: f.quarantined_at.format("%Y-%m-%d %H:%M").to_string(),
                threat: truncate(&f.threat_name, 25),
                path: truncate(&f.original_path.display().to_string(), 40),
                size: format_size(f.file_size),
            })
            .collect();

        let table = Table::new(rows).to_string();
        output.println(&table);
        output.println(&format!("\n{} files in quarantine", files.len()));
    }

    Ok(())
}

/// Show quarantine entry details
async fn show_entry(
    client: &mut IpcClient,
    args: &QuarantineShowArgs,
    output: &Output,
) -> Result<()> {
    let files = client.get_quarantined_files().await?;

    let entry = files
        .iter()
        .find(|f| f.id.starts_with(&args.id) || f.id == args.id)
        .ok_or_else(|| anyhow::anyhow!("Quarantine entry not found: {}", args.id))?;

    if output.is_json() {
        output.print_json(entry)?;
    } else {
        output.println(&format!("{}", "=== Quarantine Entry ===".bold()));
        output.println(&format!("ID:            {}", entry.id));
        output.println(&format!(
            "Quarantined:   {}",
            entry.quarantined_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.println(&format!("Threat:        {}", entry.threat_name.red()));
        output.println(&format!("Original Path: {}", entry.original_path.display()));
        output.println(&format!("File Size:     {}", format_size(entry.file_size)));
        output.println(&format!("SHA256:        {}", entry.file_hash));
        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl quarantine restore <id>' to restore this file.".dimmed()
        ));
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl quarantine delete <id>' to permanently delete.".dimmed()
        ));
    }

    Ok(())
}

/// Restore a file from quarantine
async fn restore_file(
    client: &mut IpcClient,
    args: &QuarantineRestoreArgs,
    output: &Output,
) -> Result<()> {
    // Get file info first
    let files = client.get_quarantined_files().await?;
    let entry = files
        .iter()
        .find(|f| f.id.starts_with(&args.id) || f.id == args.id)
        .ok_or_else(|| anyhow::anyhow!("Quarantine entry not found: {}", args.id))?;

    if !args.force && !output.is_json() {
        output.println(&format!(
            "{} You are about to restore a potentially malicious file!",
            "[WARNING]".yellow().bold()
        ));
        output.println(&format!("  Threat: {}", entry.threat_name.red()));
        output.println(&format!("  Path:   {}", entry.original_path.display()));
        output.println("");
        output.println("Use --force to confirm restore.");
        return Ok(());
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.restore_quarantined_file(entry.id.clone()).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "restored",
            "id": entry.id,
            "path": entry.original_path.display().to_string(),
        }))?;
    } else {
        output.println(&format!(
            "{} File restored to: {}",
            "[OK]".green(),
            entry.original_path.display()
        ));
        output.println("");
        output.println(&format!(
            "{}",
            "Warning: This file was previously flagged as malicious.".yellow()
        ));
    }

    Ok(())
}

/// Permanently delete a quarantined file
async fn delete_file(
    client: &mut IpcClient,
    args: &QuarantineDeleteArgs,
    output: &Output,
) -> Result<()> {
    // Get file info first
    let files = client.get_quarantined_files().await?;
    let entry = files
        .iter()
        .find(|f| f.id.starts_with(&args.id) || f.id == args.id)
        .ok_or_else(|| anyhow::anyhow!("Quarantine entry not found: {}", args.id))?;

    if !args.force && !output.is_json() {
        output.println(&format!(
            "{} You are about to permanently delete this file!",
            "[WARNING]".yellow().bold()
        ));
        output.println(&format!("  Threat: {}", entry.threat_name));
        output.println(&format!("  Path:   {}", entry.original_path.display()));
        output.println("");
        output.println("This action cannot be undone. Use --force to confirm.");
        return Ok(());
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.delete_quarantined_file(entry.id.clone()).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "deleted",
            "id": entry.id,
        }))?;
    } else {
        output.println(&format!(
            "{} Quarantined file permanently deleted",
            "[OK]".green()
        ));
    }

    Ok(())
}

/// Format file size for display
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Truncate string
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
