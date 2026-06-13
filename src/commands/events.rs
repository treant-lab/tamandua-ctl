//! Events command implementation
//!
//! Lists, searches, and displays telemetry events.

use crate::cli::{EventsArgs, EventsListArgs, EventsSearchArgs, EventsSubcommand};
use crate::ipc::IpcClient;
use crate::output::Output;
use anyhow::Result;
use chrono::{Duration, Utc};
use colored::Colorize;
use tabled::{Table, Tabled};

/// Execute the events command
pub async fn execute(client: &mut IpcClient, args: &EventsArgs, output: &Output) -> Result<()> {
    match &args.command {
        Some(EventsSubcommand::List(list_args)) => list_events(client, list_args, output).await,
        Some(EventsSubcommand::Search(search_args)) => {
            search_events(client, search_args, output).await
        }
        Some(EventsSubcommand::Stats) => show_stats(client, output).await,
        None => {
            // Default: list recent events
            list_events(
                client,
                &EventsListArgs {
                    limit: 50,
                    since: None,
                    event_type: None,
                    severity: None,
                },
                output,
            )
            .await
        }
    }
}

/// List recent events (via logs endpoint)
async fn list_events(client: &mut IpcClient, args: &EventsListArgs, output: &Output) -> Result<()> {
    // Parse since argument
    let since = if let Some(ref since_str) = args.since {
        Some(parse_since(since_str)?)
    } else {
        None
    };

    // Map severity to log level if provided
    let level = args.severity.as_ref().map(|s| s.to_string());

    let logs = client.get_logs(since, level, Some(args.limit)).await?;

    if output.is_json() {
        output.print_json(&logs)?;
    } else if logs.is_empty() {
        output.println("No events found.");
    } else {
        #[derive(Tabled)]
        struct EventRow {
            time: String,
            level: String,
            module: String,
            message: String,
        }

        let rows: Vec<EventRow> = logs
            .iter()
            .map(|log| {
                let level_colored = match log.level.as_str() {
                    "error" | "ERROR" => log.level.clone().red().to_string(),
                    "warn" | "WARN" => log.level.clone().yellow().to_string(),
                    "info" | "INFO" => log.level.clone().green().to_string(),
                    "debug" | "DEBUG" => log.level.clone().blue().to_string(),
                    _ => log.level.clone(),
                };

                EventRow {
                    time: log.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                    level: level_colored,
                    module: log.module.clone().unwrap_or_default(),
                    message: truncate(&log.message, 60),
                }
            })
            .collect();

        let table = Table::new(rows).to_string();
        output.println(&table);
        output.println(&format!("\nShowing {} events", logs.len()));
    }

    Ok(())
}

/// Search events by query
async fn search_events(
    client: &mut IpcClient,
    args: &EventsSearchArgs,
    output: &Output,
) -> Result<()> {
    // For now, we fetch all logs and filter client-side
    // TODO: Implement server-side search
    let logs = client.get_logs(None, None, Some(args.limit * 10)).await?;

    let query_lower = args.query.to_lowercase();
    let filtered: Vec<_> = logs
        .into_iter()
        .filter(|log| {
            log.message.to_lowercase().contains(&query_lower)
                || log
                    .module
                    .as_ref()
                    .map(|m| m.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
        })
        .take(args.limit)
        .collect();

    if output.is_json() {
        output.print_json(&filtered)?;
    } else if filtered.is_empty() {
        output.println(&format!("No events matching '{}'", args.query));
    } else {
        #[derive(Tabled)]
        struct EventRow {
            time: String,
            level: String,
            module: String,
            message: String,
        }

        let rows: Vec<EventRow> = filtered
            .iter()
            .map(|log| EventRow {
                time: log.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
                level: log.level.clone(),
                module: log.module.clone().unwrap_or_default(),
                message: truncate(&log.message, 60),
            })
            .collect();

        let table = Table::new(rows).to_string();
        output.println(&table);
        output.println(&format!(
            "\nFound {} events matching '{}'",
            filtered.len(),
            args.query
        ));
    }

    Ok(())
}

/// Show event statistics
async fn show_stats(client: &mut IpcClient, output: &Output) -> Result<()> {
    let metrics = client.get_metrics().await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "events_processed": metrics.events_processed,
            "events_per_second": metrics.events_per_second,
            "collector_metrics": metrics.collector_metrics,
        }))?;
    } else {
        output.println(&format!("{}", "=== Event Statistics ===".bold()));
        output.println(&format!(
            "Total Events Processed: {}",
            metrics.events_processed
        ));
        output.println(&format!(
            "Current Rate:           {:.2} events/sec",
            metrics.events_per_second
        ));
        output.println("");

        if !metrics.collector_metrics.is_empty() {
            output.println(&format!("{}", "=== By Collector ===".bold()));

            #[derive(Tabled)]
            struct CollectorRow {
                collector: String,
                events: String,
                #[tabled(rename = "events/s")]
                rate: String,
                errors: String,
            }

            let rows: Vec<CollectorRow> = metrics
                .collector_metrics
                .iter()
                .map(|m| CollectorRow {
                    collector: m.name.clone(),
                    events: m.events_collected.to_string(),
                    rate: format!("{:.1}", m.events_per_second),
                    errors: m.errors.to_string(),
                })
                .collect();

            let table = Table::new(rows).to_string();
            output.println(&table);
        }
    }

    Ok(())
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

    anyhow::bail!(
        "Invalid time format: '{}'. Use duration (e.g., '1h', '30m') or date (e.g., '2024-01-01')",
        since_str
    );
}

/// Parse duration string (e.g., "1h", "30m", "2d")
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

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
