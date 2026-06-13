//! Response command implementation
//!
//! Executes response actions like kill process, quarantine file, isolate host.

use crate::cli::{
    BlockIpArgs, KillArgs, QuarantineFileArgs, ResponseArgs, ResponseSubcommand, UnblockIpArgs,
};
use crate::ipc::{IpcClient, ResponseAction};
use crate::output::Output;
use anyhow::Result;
use colored::Colorize;

/// Execute the response command
pub async fn execute(client: &mut IpcClient, args: &ResponseArgs, output: &Output) -> Result<()> {
    match &args.command {
        ResponseSubcommand::Kill(kill_args) => kill_process(client, kill_args, output).await,
        ResponseSubcommand::QuarantineFile(quarantine_args) => {
            quarantine_file(client, quarantine_args, output).await
        }
        ResponseSubcommand::Isolate => isolate_host(client, output).await,
        ResponseSubcommand::Restore => restore_host(client, output).await,
        ResponseSubcommand::BlockIp(block_args) => block_ip(client, block_args, output).await,
        ResponseSubcommand::UnblockIp(unblock_args) => {
            unblock_ip(client, unblock_args, output).await
        }
    }
}

/// Kill a process
async fn kill_process(client: &mut IpcClient, args: &KillArgs, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.kill_process(args.pid).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "killed",
            "pid": args.pid,
            "force": args.force,
        }))?;
    } else {
        output.println(&format!(
            "{} Process {} terminated",
            "[OK]".green(),
            args.pid
        ));
    }

    Ok(())
}

/// Quarantine a file
async fn quarantine_file(
    client: &mut IpcClient,
    args: &QuarantineFileArgs,
    output: &Output,
) -> Result<()> {
    // Verify path exists
    if !args.path.exists() {
        anyhow::bail!("File does not exist: {}", args.path.display());
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    let path_display = args.path.display().to_string();

    client
        .execute_action(ResponseAction::QuarantineFile {
            path: args.path.clone(),
        })
        .await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "quarantined",
            "path": path_display,
        }))?;
    } else {
        output.println(&format!(
            "{} File quarantined: {}",
            "[OK]".green(),
            path_display
        ));
        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl quarantine list' to see quarantined files.".dimmed()
        ));
    }

    Ok(())
}

/// Isolate the host from network
async fn isolate_host(client: &mut IpcClient, output: &Output) -> Result<()> {
    if !output.is_json() {
        output.println(&format!(
            "{} This will isolate the host from the network!",
            "[WARNING]".yellow().bold()
        ));
        output.println("Only communication with the Tamandua backend will be allowed.");
        output.println("");
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.execute_action(ResponseAction::IsolateHost).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "isolated",
            "message": "Host network isolated",
        }))?;
    } else {
        output.println(&format!("{} Host network isolated", "[OK]".green()));
        output.println("");
        output.println(&format!(
            "{}",
            "Use 'tamandua-ctl response restore' to restore network connectivity.".dimmed()
        ));
    }

    Ok(())
}

/// Restore host network connectivity
async fn restore_host(client: &mut IpcClient, output: &Output) -> Result<()> {
    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client.execute_action(ResponseAction::RestoreHost).await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "restored",
            "message": "Host network connectivity restored",
        }))?;
    } else {
        output.println(&format!(
            "{} Host network connectivity restored",
            "[OK]".green()
        ));
    }

    Ok(())
}

/// Block an IP address
async fn block_ip(client: &mut IpcClient, args: &BlockIpArgs, output: &Output) -> Result<()> {
    // Validate IP address format
    if args.ip.parse::<std::net::IpAddr>().is_err() {
        anyhow::bail!("Invalid IP address: {}", args.ip);
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client
        .execute_action(ResponseAction::BlockIp {
            ip: args.ip.clone(),
        })
        .await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "blocked",
            "ip": args.ip,
            "duration": if args.duration == 0 { "permanent".to_string() } else { format!("{} seconds", args.duration) },
        }))?;
    } else {
        let duration_str = if args.duration == 0 {
            "permanently".to_string()
        } else {
            format!("for {} seconds", args.duration)
        };
        output.println(&format!(
            "{} IP address {} blocked {}",
            "[OK]".green(),
            args.ip,
            duration_str
        ));
    }

    Ok(())
}

/// Unblock an IP address
async fn unblock_ip(client: &mut IpcClient, args: &UnblockIpArgs, output: &Output) -> Result<()> {
    // Validate IP address format
    if args.ip.parse::<std::net::IpAddr>().is_err() {
        anyhow::bail!("Invalid IP address: {}", args.ip);
    }

    // Authenticate if not already
    if !client.is_authenticated() {
        client.authenticate().await?;
    }

    client
        .execute_action(ResponseAction::UnblockIp {
            ip: args.ip.clone(),
        })
        .await?;

    if output.is_json() {
        output.print_json(&serde_json::json!({
            "status": "unblocked",
            "ip": args.ip,
        }))?;
    } else {
        output.println(&format!(
            "{} IP address {} unblocked",
            "[OK]".green(),
            args.ip
        ));
    }

    Ok(())
}
