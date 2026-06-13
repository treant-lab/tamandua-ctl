//! Tamandua EDR Command-Line Control Tool
//!
//! A CLI for interacting with the Tamandua agent service.
//! Uses the same IPC protocol as the GUI (Named Pipes on Windows,
//! Unix domain sockets on Linux/macOS).
//!
//! # Usage
//!
//! ```bash
//! # Show agent status
//! tamandua-ctl status
//!
//! # List recent alerts
//! tamandua-ctl alerts list
//!
//! # Start a scan
//! tamandua-ctl scan start /path/to/scan
//!
//! # JSON output for scripting
//! tamandua-ctl --json status
//! ```

mod cli;
mod commands;
mod ipc;
mod output;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use tracing::Level;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use commands::{create_client, create_output};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "[ERROR]".red().bold(), e);

        // Print cause chain
        let mut cause = e.source();
        while let Some(c) = cause {
            eprintln!("  {} {}", "Caused by:".dimmed(), c);
            cause = c.source();
        }

        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose, cli.quiet);

    // Create output formatter
    let output = create_output(&cli);

    // Handle version command specially (can work without agent connection)
    if matches!(cli.command, Commands::Version) {
        // Try to connect, but don't fail if we can't
        match create_client(&cli).await {
            Ok(mut client) => {
                commands::version::execute(&mut client, &output).await?;
            }
            Err(_) => {
                // Just show CLI version if we can't connect
                if output.is_json() {
                    output.print_json(&serde_json::json!({
                        "cli": {
                            "version": env!("CARGO_PKG_VERSION"),
                        },
                        "agent": null,
                        "error": "Could not connect to agent"
                    }))?;
                } else {
                    output.println(&format!(
                        "tamandua-ctl version {}",
                        env!("CARGO_PKG_VERSION")
                    ));
                    output.println("");
                    output.println(&format!(
                        "{}",
                        "Agent not available (could not connect to IPC server)".yellow()
                    ));
                }
            }
        }
        return Ok(());
    }

    if let Commands::Remote(args) = &cli.command {
        commands::remote::execute(args, &output).await?;
        return Ok(());
    }

    // Connect to agent
    let mut client = create_client(&cli).await.map_err(|e| {
        anyhow::anyhow!(
            "Could not connect to Tamandua agent: {}. Is the agent service running?",
            e
        )
    })?;

    // Execute command
    match &cli.command {
        Commands::Status(args) => {
            commands::status::execute(&mut client, args, &output).await?;
        }
        Commands::Events(args) => {
            commands::events::execute(&mut client, args, &output).await?;
        }
        Commands::Alerts(args) => {
            commands::alerts::execute(&mut client, args, &output).await?;
        }
        Commands::Config(args) => {
            commands::config::execute(&mut client, args, &output).await?;
        }
        Commands::Scan(args) => {
            commands::scan::execute(&mut client, args, &output).await?;
        }
        Commands::Quarantine(args) => {
            commands::quarantine::execute(&mut client, args, &output).await?;
        }
        Commands::Response(args) => {
            commands::response::execute(&mut client, args, &output).await?;
        }
        Commands::Remote(_) => unreachable!("remote commands are handled before IPC connection"),
        Commands::Version => {
            // Already handled above
            unreachable!();
        }
    }

    Ok(())
}

/// Initialize logging based on verbosity level
fn init_logging(verbose: u8, quiet: bool) {
    let level = if quiet {
        Level::ERROR
    } else {
        match verbose {
            0 => Level::WARN,
            1 => Level::INFO,
            2 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        // Reduce noise from dependencies
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("mio=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}
