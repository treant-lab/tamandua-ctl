//! Command implementations
//!
//! Each subcommand has its own module with handlers for various operations.

pub mod alerts;
pub mod config;
pub mod events;
pub mod quarantine;
pub mod remote;
pub mod response;
pub mod scan;
pub mod status;
pub mod version;

use crate::cli::Cli;
use crate::ipc::IpcClient;
use crate::output::{Output, OutputFormat};
use anyhow::Result;
use std::time::Duration;

/// Create and connect an IPC client based on CLI args
pub async fn create_client(cli: &Cli) -> Result<IpcClient> {
    let timeout = Duration::from_secs(cli.timeout);
    let mut client = IpcClient::new(timeout);

    if let Some(ref path) = cli.ipc_path {
        client.connect_to(path).await?;
    } else {
        client.connect().await?;
    }

    Ok(client)
}

/// Create output formatter based on CLI args
pub fn create_output(cli: &Cli) -> Output {
    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Table
    };

    Output::new(format, cli.quiet)
}
