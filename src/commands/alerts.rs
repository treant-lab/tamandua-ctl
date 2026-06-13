//! Alerts command implementation
//!
//! Lists, acknowledges, and manages security alerts.

use crate::cli::{AlertAckArgs, AlertShowArgs, AlertsArgs, AlertsListArgs, AlertsSubcommand};
use crate::ipc::{AlertSeverity, IpcClient};
use crate::output::Output;
use anyhow::Result;
use chrono::{Duration, Utc};
use colored::Colorize;
use tabled::{Table, Tabled};

/// Execute the alerts command
pub async fn execute(client: &mut IpcClient, args: &AlertsArgs, output: &Output) -> Result<()> {
    match &args.command {
        Some(AlertsSubcommand::List(list_args)) => list_alerts(client, list_args, output).await,
        Some(AlertsSubcommand::Ack(ack_args)) => ack_alert(client, ack_args, output).await,
        Some(AlertsSubcommand::Show(show_args)) => show_alert(client, show_args, output).await,
        Some(AlertsSubcommand::Stats) => show_stats(client, output).await,
        None => {
            // Default: list recent unacknowledged alerts
            list_alerts(
                client,
                &AlertsListArgs {
                    limit: 50,
                    since: None,
                    severity: None,
                    unacked: true,
                    all: false,
                },
                output,
            )
            .await
        }
    }
}

/// List alerts
async fn list_alerts(client: &mut IpcClient, args: &AlertsListArgs, output: &Output) -> Result<()> {
    // Parse since argument
    let since = if let Some(ref since_str) = args.since {
        Some(parse_since(since_str)?)
    } else {
        None
    };

    let mut alerts = client.get_alerts(since, Some(args.limit)).await?;

    // Filter by severity if provided
    if let Some(ref severity) = args.severity {
        let target_severity = match severity {
            crate::cli::Severity::Info => AlertSeverity::Info,
            crate::cli::Severity::Low => AlertSeverity::Low,
            crate::cli::Severity::Medium => AlertSeverity::Medium,
            crate::cli::Severity::High => AlertSeverity::High,
            crate::cli::Severity::Critical => AlertSeverity::Critical,
        };
        alerts.retain(|a| a.severity >= target_severity);
    }

    // Filter by acknowledged status
    if args.unacked && !args.all {
        alerts.retain(|a| !a.acknowledged);
    }

    if output.is_json() {
        output.print_json(&alerts)?;
    } else if alerts.is_empty() {
        output.println("No alerts found.");
    } else {
        #[derive(Tabled)]
        struct AlertRow {
            id: String,
            time: String,
            severity: String,
            title: String,
            acked: String,
        }

        let rows: Vec<AlertRow> = alerts
            .iter()
            .map(|alert| {
                let severity_colored = colorize_severity(&alert.severity);
                let acked = if alert.acknowledged {
                    "yes".dimmed().to_string()
                } else {
                    "no".to_string()
                };

                AlertRow {
                    id: truncate(&alert.id, 8),
                    time: alert.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                    severity: severity_colored,
                    title: truncate(&alert.title, 50),
                    acked,
                }
            })
            .collect();

        let table = Table::new(rows).to_string();
        output.println(&table);

        let unacked_count = alerts.iter().filter(|a| !a.acknowledged).count();
        output.println(&format!(
            "\nShowing {} alerts ({} unacknowledged)",
            alerts.len(),
            unacked_count
        ));
    }

    Ok(())
}

/// Acknowledge an alert
async fn ack_alert(client: &mut IpcClient, args: &AlertAckArgs, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.acknowledge_alert(args.alert_id.clone()).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "acknowledged",
            "alert_id": args.alert_id,
        }))?;
    } else {
        output.println(&format!(
            "{} Alert {} acknowledged",
            "[OK]".green(),
            args.alert_id
        ));
        if let Some(ref note) = args.note {
            output.println(&format!("Note: {}", note));
        }
    }

    Ok(())
}

/// Show detailed alert information
async fn show_alert(client: &mut IpcClient, args: &AlertShowArgs, output: &Output) -> Result<()> {
    let alerts = client.get_alerts(None, Some(100)).await?;

    let alert = alerts
        .iter()
        .find(|a| a.id.starts_with(&args.alert_id) || a.id == args.alert_id)
        .ok_or_else(|| anyhow::anyhow!("Alert not found: {}", args.alert_id))?;

    if output.is_json() {
        output.print_json(alert)?;
    } else {
        output.println(&format!("{}", "=== Alert Details ===".bold()));
        output.println(&format!("ID:          {}", alert.id));
        output.println(&format!(
            "Time:        {}",
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.println(&format!(
            "Severity:    {}",
            colorize_severity(&alert.severity)
        ));
        output.println(&format!("Title:       {}", alert.title));
        output.println(&format!("Description: {}", alert.description));

        if let Some(ref threat) = alert.threat_name {
            output.println(&format!("Threat:      {}", threat.red()));
        }

        if let Some(ref process) = alert.process_name {
            output.println(&format!("Process:     {}", process));
        }

        if let Some(pid) = alert.process_id {
            output.println(&format!("PID:         {}", pid));
        }

        if let Some(ref path) = alert.file_path {
            output.println(&format!("File:        {}", path.display()));
        }

        if !alert.mitre_tactics.is_empty() {
            output.println(&format!("MITRE:       {}", alert.mitre_tactics.join(", ")));
        }

        if let Some(ref remediation) = alert.remediation {
            output.println("");
            output.println(&format!("{}", "Recommended Action:".bold()));
            output.println(&format!("  {}", remediation));
        }

        output.println("");
        let acked_status = if alert.acknowledged {
            "Yes".green()
        } else {
            "No".yellow()
        };
        output.println(&format!("Acknowledged: {}", acked_status));
    }

    Ok(())
}

/// Show alert statistics
async fn show_stats(client: &mut IpcClient, output: &Output) -> Result<()> {
    let alerts = client.get_alerts(None, Some(1000)).await?;

    let total = alerts.len();
    let unacked = alerts.iter().filter(|a| !a.acknowledged).count();
    let critical = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    let high = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::High)
        .count();
    let medium = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Medium)
        .count();
    let low = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Low)
        .count();
    let info = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Info)
        .count();

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "total": total,
            "unacknowledged": unacked,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
            }
        }))?;
    } else {
        output.println(&format!("{}", "=== Alert Statistics ===".bold()));
        output.println(&format!("Total Alerts:     {}", total));
        output.println(&format!("Unacknowledged:   {}", unacked));
        output.println("");
        output.println(&format!("{}", "By Severity:".bold()));
        output.println(&format!("  Critical: {}", critical.to_string().red()));
        output.println(&format!("  High:     {}", high.to_string().red()));
        output.println(&format!("  Medium:   {}", medium.to_string().yellow()));
        output.println(&format!("  Low:      {}", low.to_string().blue()));
        output.println(&format!("  Info:     {}", info));
    }

    Ok(())
}

/// Colorize severity for display
fn colorize_severity(severity: &AlertSeverity) -> String {
    match severity {
        AlertSeverity::Critical => "critical".red().bold().to_string(),
        AlertSeverity::High => "high".red().to_string(),
        AlertSeverity::Medium => "medium".yellow().to_string(),
        AlertSeverity::Low => "low".blue().to_string(),
        AlertSeverity::Info => "info".to_string(),
    }
}

/// Parse "since" time specification
fn parse_since(since_str: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    // Try duration format (e.g., "1h", "30m", "2d")
    if let Some(duration) = parse_duration(since_str) {
        return Ok(Utc::now() - duration);
    }

    // Try ISO 8601 format
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(since_str) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try date format (YYYY-MM-DD)
    if let Ok(date) = chrono::NaiveDate::parse_from_str(since_str, "%Y-%m-%d") {
        let datetime = date.and_hms_opt(0, 0, 0).unwrap();
        return Ok(chrono::DateTime::from_naive_utc_and_offset(datetime, Utc));
    }

    anyhow::bail!("Invalid time format: '{}'", since_str);
}

/// Parse duration string
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str.parse().ok()?;

    match unit {
        "s" => Some(Duration::seconds(num)),
        "m" => Some(Duration::minutes(num)),
        "h" => Some(Duration::hours(num)),
        "d" => Some(Duration::days(num)),
        "w" => Some(Duration::weeks(num)),
        _ => None,
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
