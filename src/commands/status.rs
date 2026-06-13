//! Status command implementation
//!
//! Shows agent status, health information, and metrics.

use crate::cli::StatusArgs;
use crate::ipc::IpcClient;
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

/// Execute the status command
pub async fn execute(client: &mut IpcClient, args: &StatusArgs, output: &Output) -> Result<()> {
    if args.watch {
        watch_status(client, args, output).await
    } else if args.detailed {
        show_detailed_status(client, output).await
    } else if args.metrics {
        show_metrics(client, output).await
    } else {
        show_basic_status(client, output).await
    }
}

/// Show basic agent status
async fn show_basic_status(client: &mut IpcClient, output: &Output) -> Result<()> {
    let status = client.get_status().await?;

    if output.is_json() {
        output.print_json(&status)?;
    } else {
        let state_colored = match status.state {
            crate::ipc::AgentState::Running => "Running".green(),
            crate::ipc::AgentState::Starting => "Starting".yellow(),
            crate::ipc::AgentState::Degraded => "Degraded".yellow(),
            crate::ipc::AgentState::Stopped => "Stopped".red(),
            crate::ipc::AgentState::Error => "Error".red(),
        };

        let backend_status = if status.backend_connected {
            "Connected".green()
        } else {
            "Disconnected".red()
        };

        let protection_status = if status.protection_enabled {
            "Enabled".green()
        } else {
            "Disabled".red()
        };

        output.println(&format!("Agent ID:       {}", status.agent_id));
        output.println(&format!("Version:        {}", status.version));
        output.println(&format!("State:          {}", state_colored));
        output.println(&format!("Backend:        {}", backend_status));
        output.println(&format!("Protection:     {}", protection_status));
        output.println(&format!("CPU Usage:      {:.1}%", status.cpu_usage));
        output.println(&format!(
            "Memory Usage:   {} MB",
            status.memory_usage / 1024 / 1024
        ));
        output.println(&format!(
            "Uptime:         {}",
            format_duration(status.uptime_seconds)
        ));

        if !status.collectors_running.is_empty() {
            output.println(&format!(
                "Collectors:     {}",
                status.collectors_running.join(", ")
            ));
        }

        if let Some(heartbeat) = status.last_heartbeat {
            output.println(&format!(
                "Last Heartbeat: {}",
                heartbeat.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
    }

    Ok(())
}

/// Show detailed component status
async fn show_detailed_status(client: &mut IpcClient, output: &Output) -> Result<()> {
    let status = client.get_status().await?;
    let component_status = client.get_component_status().await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": status,
            "components": component_status,
        }))?;
    } else {
        // Basic status
        output.println(&format!("{}", "=== Agent Status ===".bold()));
        output.println(&format!("Agent ID: {}", status.agent_id));
        output.println(&format!("Version:  {}", status.version));
        output.println(&format!(
            "Uptime:   {}",
            format_duration(status.uptime_seconds)
        ));
        output.println("");

        // Driver status
        output.println(&format!("{}", "=== Driver Status ===".bold()));
        let driver_loaded = if component_status.driver.loaded {
            "Loaded".green()
        } else {
            "Not Loaded".red()
        };
        output.println(&format!("Status:  {}", driver_loaded));
        if let Some(ref version) = component_status.driver.version {
            output.println(&format!("Version: {}", version));
        }
        output.println(&format!(
            "Events:  {}",
            component_status.driver.events_captured
        ));
        if let Some(ref error) = component_status.driver.error {
            output.println(&format!("Error:   {}", error.red()));
        }
        output.println("");

        // Backend status
        output.println(&format!("{}", "=== Backend Connection ===".bold()));
        let backend_connected = if component_status.backend.connected {
            "Connected".green()
        } else {
            "Disconnected".red()
        };
        output.println(&format!("Status:   {}", backend_connected));
        output.println(&format!("URL:      {}", component_status.backend.url));
        if let Some(latency) = component_status.backend.latency_ms {
            output.println(&format!("Latency:  {} ms", latency));
        }
        output.println(&format!(
            "Queued:   {} events",
            component_status.backend.events_queued
        ));
        output.println(&format!(
            "Sent:     {} events",
            component_status.backend.events_sent
        ));
        if let Some(ref error) = component_status.backend.error {
            output.println(&format!("Error:    {}", error.red()));
        }
        output.println("");

        // Collector status
        output.println(&format!("{}", "=== Collectors ===".bold()));
        #[derive(Tabled)]
        struct CollectorRow {
            name: String,
            status: String,
            #[tabled(rename = "events/s")]
            events_per_sec: String,
            total: String,
            errors: String,
            cpu: String,
        }

        let rows: Vec<CollectorRow> = component_status
            .collectors
            .iter()
            .map(|c| CollectorRow {
                name: c.name.clone(),
                status: if c.running {
                    "running".to_string()
                } else {
                    "stopped".to_string()
                },
                events_per_sec: format!("{:.1}", c.events_per_second),
                total: c.total_events.to_string(),
                errors: c.errors.to_string(),
                cpu: format!("{:.1}%", c.cpu_percent),
            })
            .collect();

        if !rows.is_empty() {
            let table = Table::new(rows).to_string();
            output.println(&table);
        }
        output.println("");

        // Health status
        output.println(&format!("{}", "=== Health Checks ===".bold()));
        let health_colored = match component_status.health.status {
            crate::ipc::HealthState::Healthy => "Healthy".green(),
            crate::ipc::HealthState::Degraded => "Degraded".yellow(),
            crate::ipc::HealthState::Unhealthy => "Unhealthy".red(),
        };
        output.println(&format!("Overall: {}", health_colored));
        output.println(&format!(
            "Pressure Level: {}",
            component_status.pressure_level
        ));

        for check in &component_status.health.checks {
            let status = if check.passed {
                "[PASS]".green()
            } else {
                "[FAIL]".red()
            };
            let msg = check.message.as_deref().unwrap_or("");
            output.println(&format!("  {} {} {}", status, check.name, msg));
        }
    }

    Ok(())
}

/// Show performance metrics
async fn show_metrics(client: &mut IpcClient, output: &Output) -> Result<()> {
    let metrics = client.get_metrics().await?;

    if output.is_json() {
        output.print_json(&metrics)?;
    } else {
        output.println(&format!("{}", "=== Performance Metrics ===".bold()));
        output.println(&format!(
            "Timestamp:       {}",
            metrics.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.println(&format!("Events Processed: {}", metrics.events_processed));
        output.println(&format!(
            "Events/sec:       {:.2}",
            metrics.events_per_second
        ));
        output.println(&format!("Alerts Generated: {}", metrics.alerts_generated));
        output.println(&format!("Actions Executed: {}", metrics.actions_executed));
        output.println(&format!("CPU Usage:        {:.1}%", metrics.cpu_usage));
        output.println(&format!(
            "Memory Usage:     {} MB",
            metrics.memory_usage / 1024 / 1024
        ));
        output.println(&format!(
            "Network Sent:     {} KB",
            metrics.network_bytes_sent / 1024
        ));
        output.println(&format!(
            "Network Received: {} KB",
            metrics.network_bytes_received / 1024
        ));

        if !metrics.collector_metrics.is_empty() {
            output.println("");
            output.println(&format!("{}", "=== Collector Metrics ===".bold()));

            #[derive(Tabled)]
            struct MetricRow {
                collector: String,
                events: String,
                #[tabled(rename = "events/s")]
                rate: String,
                errors: String,
                cpu: String,
            }

            let rows: Vec<MetricRow> = metrics
                .collector_metrics
                .iter()
                .map(|m| MetricRow {
                    collector: m.name.clone(),
                    events: m.events_collected.to_string(),
                    rate: format!("{:.1}", m.events_per_second),
                    errors: m.errors.to_string(),
                    cpu: format!("{:.1}%", m.cpu_percent),
                })
                .collect();

            let table = Table::new(rows).to_string();
            output.println(&table);
        }
    }

    Ok(())
}

/// Watch status continuously
async fn watch_status(client: &mut IpcClient, args: &StatusArgs, output: &Output) -> Result<()> {
    let interval = std::time::Duration::from_secs(args.interval);

    loop {
        // Clear screen (ANSI escape)
        if !output.is_json() {
            print!("\x1B[2J\x1B[1;1H");
        }

        if args.detailed {
            show_detailed_status(client, output).await?;
        } else if args.metrics {
            show_metrics(client, output).await?;
        } else {
            show_basic_status(client, output).await?;
        }

        if !output.is_json() {
            output.println("");
            output.println(&format!(
                "{}",
                format!(
                    "Refreshing every {} seconds. Press Ctrl+C to exit.",
                    args.interval
                )
                .dimmed()
            ));
        }

        tokio::time::sleep(interval).await;
    }
}

/// Format duration in human-readable format
fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}
