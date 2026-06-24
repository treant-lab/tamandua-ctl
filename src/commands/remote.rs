//! Remote Tamandua server commands.

use crate::cli::{
    RemoteAgentsArgs, RemoteAgentsListArgs, RemoteAgentsSubcommand, RemoteAlertsArgs,
    RemoteAlertsListArgs, RemoteAlertsSubcommand, RemoteArgs, RemoteCommandArgs, RemoteLoginArgs,
    RemoteShellArgs, RemoteSubcommand, RemoteUploadArgs,
};
use crate::output::Output;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tabled::{Table, Tabled};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{self, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_SERVER: &str = "https://tamandua.treantlab.org";
const PHOENIX_VSN: &str = "2.0.0";

#[derive(Debug, Default, Serialize, Deserialize)]
struct RemoteConfig {
    server: Option<String>,
    token: Option<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceStartResponse {
    device_code: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    access_token: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
}

struct RemoteSession {
    server: String,
    token: String,
}

pub async fn execute(args: &RemoteArgs, output: &Output) -> Result<()> {
    match &args.command {
        RemoteSubcommand::Login(login_args) => login(login_args, output).await,
        RemoteSubcommand::Agents(agents_args) => agents(agents_args, output).await,
        RemoteSubcommand::Alerts(alerts_args) => alerts(alerts_args, output).await,
        RemoteSubcommand::Shell(shell_args) => shell(shell_args, output).await,
        RemoteSubcommand::Command(command_args) => command(command_args, output).await,
        RemoteSubcommand::Upload(upload_args) => upload(upload_args, output).await,
    }
}

async fn login(args: &RemoteLoginArgs, output: &Output) -> Result<()> {
    let server = args
        .server
        .clone()
        .unwrap_or_else(|| DEFAULT_SERVER.to_owned())
        .trim_end_matches('/')
        .to_owned();

    let (token, expires_at) = match &args.token {
        Some(token) => (token.clone(), None),
        None => {
            let token = browser_device_login(&server, args.no_browser, output).await?;
            (token.access_token, token.expires_at)
        }
    };

    let config = RemoteConfig {
        server: Some(server),
        token: Some(token),
        expires_at,
    };

    let path = remote_config_path()?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let body = serde_json::to_string_pretty(&config)?;
    tokio::fs::write(&path, body).await?;

    output.println(&format!(
        "{} {}",
        "stored remote credentials at".green(),
        path.display()
    ));
    output.println("Use: tamandua-ctl remote shell --agent-id <agent-id>");
    Ok(())
}

async fn agents(args: &RemoteAgentsArgs, output: &Output) -> Result<()> {
    match &args.command {
        RemoteAgentsSubcommand::List(list_args) => list_agents(list_args, output).await,
    }
}

async fn alerts(args: &RemoteAlertsArgs, output: &Output) -> Result<()> {
    match &args.command {
        RemoteAlertsSubcommand::List(list_args) => list_remote_alerts(list_args, output).await,
    }
}

async fn list_agents(args: &RemoteAgentsListArgs, output: &Output) -> Result<()> {
    let session = remote_session(args.server.clone(), args.token.clone()).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    let mut request = client
        .get(format!("{}/api/v1/agents", session.server))
        .bearer_auth(&session.token);

    if let Some(status) = args.status.as_deref().filter(|value| !value.is_empty()) {
        request = request.query(&[("status", status)]);
    }

    let body = send_api_request(request, "list agents").await?;

    if output.is_json() {
        output.print_json(&body)?;
        return Ok(());
    }

    let agents = body
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if agents.is_empty() {
        output.println("No agents found.");
        return Ok(());
    }

    #[derive(Tabled)]
    struct AgentRow {
        id: String,
        hostname: String,
        os: String,
        status: String,
        health: String,
        last_seen: String,
    }

    let rows: Vec<AgentRow> = agents
        .iter()
        .map(|agent| {
            let status = string_field(agent, "status", "unknown");
            AgentRow {
                id: string_field(agent, "id", ""),
                hostname: truncate(&string_field(agent, "hostname", "unknown"), 32),
                os: format!(
                    "{} {}",
                    string_field(agent, "os_type", ""),
                    string_field(agent, "os_version", "")
                )
                .trim()
                .to_owned(),
                status,
                health: string_field_nested(agent, &["health_status", "status"], "unknown"),
                last_seen: string_field(agent, "last_seen", "-"),
            }
        })
        .collect();

    output.println(&Table::new(rows).to_string());
    output.println(&format!("\nShowing {} agents", agents.len()));
    Ok(())
}

async fn list_remote_alerts(args: &RemoteAlertsListArgs, output: &Output) -> Result<()> {
    let session = remote_session(args.server.clone(), args.token.clone()).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    let mut query: Vec<(&str, String)> = vec![("per_page", args.limit.min(200).to_string())];

    if let Some(agent_id) = args.agent_id.as_deref().filter(|value| !value.is_empty()) {
        query.push(("agent_id", agent_id.to_owned()));
    }

    if let Some(severity) = &args.severity {
        query.push(("severity", severity.to_string()));
    }

    if let Some(status) = args.status.as_deref().filter(|value| !value.is_empty()) {
        query.push(("status", status.to_owned()));
    }

    let body = send_api_request(
        client
            .get(format!("{}/api/v1/alerts", session.server))
            .bearer_auth(&session.token)
            .query(&query),
        "list alerts",
    )
    .await?;

    if output.is_json() {
        output.print_json(&body)?;
        return Ok(());
    }

    let alerts = body
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if alerts.is_empty() {
        output.println("No alerts found.");
        return Ok(());
    }

    #[derive(Tabled)]
    struct AlertRow {
        id: String,
        time: String,
        severity: String,
        status: String,
        agent: String,
        title: String,
    }

    let rows: Vec<AlertRow> = alerts
        .iter()
        .map(|alert| {
            let severity = string_field(alert, "severity", "unknown");
            AlertRow {
                id: string_field(alert, "id", ""),
                time: string_field(alert, "created_at", "-"),
                severity,
                status: string_field(alert, "status", "-"),
                agent: string_field(alert, "agent_id", ""),
                title: truncate(&string_field(alert, "title", "untitled"), 64),
            }
        })
        .collect();

    output.println(&Table::new(rows).to_string());

    if let Some(meta) = body.get("meta") {
        let total = meta
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(alerts.len() as u64);
        output.println(&format!("\nShowing {} alerts of {}", alerts.len(), total));
    } else {
        output.println(&format!("\nShowing {} alerts", alerts.len()));
    }

    Ok(())
}

async fn shell(args: &RemoteShellArgs, output: &Output) -> Result<()> {
    let config = load_remote_config().await.unwrap_or_default();
    let server = args
        .server
        .clone()
        .or(config.server)
        .unwrap_or_else(|| DEFAULT_SERVER.to_owned());
    let token = args
        .token
        .clone()
        .or(config.token)
        .context("missing token; pass --token or run tamandua-ctl remote login")?;

    let ws_url = dashboard_socket_url(&server, &token)?;
    let topic = format!("live_response:{}", args.agent_id);
    let refs = RefCounter::default();

    output.println(&format!(
        "{} connecting to {}",
        "[remote-shell]".cyan().bold(),
        server
    ));
    output.println(&format!("{} {}", "agent:".dimmed(), args.agent_id));

    let (ws, _) = connect_async(&ws_url)
        .await
        .with_context(|| format!("failed to connect dashboard socket at {ws_url}"))?;
    let (mut sink, mut stream) = ws.split();

    let join_ref = refs.next();
    let join_payload = json!({
        "view_only": args.view_only,
        "supervisor_mode": args.supervisor_mode
    });
    send_phoenix(
        &mut sink,
        Some(&join_ref),
        &join_ref,
        &topic,
        "phx_join",
        join_payload,
    )
    .await?;

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut heartbeat = time::interval(Duration::from_secs(25));
    let mut joined = false;
    let mut shell_ready = false;
    let mut stdin_closed = false;
    let mut stdin_closed_at: Option<time::Instant> = None;
    let mut pending_lines: VecDeque<String> = VecDeque::new();
    let mut pending_echoes: VecDeque<String> = VecDeque::new();
    let mut session_id: Option<String> = None;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let reference = refs.next();
                send_phoenix(&mut sink, None, &reference, "phoenix", "heartbeat", json!({})).await?;
            }
            line = stdin.next_line(), if !stdin_closed => {
                match line? {
                    Some(line) if joined && shell_ready => {
                        if handle_shell_line(
                            &mut sink,
                            &refs,
                            &join_ref,
                            &topic,
                            line,
                            output,
                            &mut pending_echoes,
                        )
                        .await?
                        {
                            break;
                        }
                    }
                    Some(line) => pending_lines.push_back(line),
                    None => {
                        stdin_closed = true;
                        stdin_closed_at = Some(time::Instant::now());
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(50)), if joined && shell_ready && !pending_lines.is_empty() => {
                if let Some(line) = pending_lines.pop_front() {
                    if handle_shell_line(
                        &mut sink,
                        &refs,
                        &join_ref,
                        &topic,
                        line,
                        output,
                        &mut pending_echoes,
                    )
                    .await?
                    {
                        break;
                    }
                }
            }
            _ = time::sleep(Duration::from_secs(3)), if stdin_closed && joined && shell_ready && pending_lines.is_empty() => {
                if stdin_closed_at
                    .map(|closed_at| closed_at.elapsed() >= Duration::from_secs(3))
                    .unwrap_or(true)
                {
                    break;
                }
            }
            _ = time::sleep(Duration::from_secs(30)), if stdin_closed && !joined => {
                bail!("dashboard socket join timed out before piped input could run");
            }
            incoming = stream.next() => {
                let Some(message) = incoming else {
                    bail!("dashboard socket closed");
                };
                let message = message?;
                match message {
                    Message::Text(text) => {
                        let Some(frame) = PhoenixFrame::parse(&text)? else {
                            continue;
                        };

                        match frame.event.as_str() {
                            "phx_reply" if frame.reference.as_deref() == Some(join_ref.as_str()) => {
                                let status = frame.payload.get("status").and_then(Value::as_str).unwrap_or("error");
                                if status == "ok" {
                                    joined = true;
                                    let response = frame.payload.get("response").cloned().unwrap_or_else(|| json!({}));
                                    session_id = response.get("session_id").and_then(Value::as_str).map(ToOwned::to_owned);
                                    print_joined(output, &response);
                                    print_shell_help(output);
                                } else {
                                    let reason = frame.payload
                                        .get("response")
                                        .and_then(|v| v.get("reason"))
                                        .and_then(Value::as_str)
                                        .unwrap_or("join failed");
                                    bail!("live response join failed: {reason}");
                                }
                            }
                            "output" => {
                                if let Some(data) = frame.payload.get("data").and_then(Value::as_str) {
                                    let filtered = filter_remote_echo(data, &mut pending_echoes);
                                    print_shell_data(&filtered)?;
                                }
                            }
                            "session_started" => {
                                let shell = frame.payload.get("shell").and_then(Value::as_str).unwrap_or("shell");
                                shell_ready = true;
                                output.println(&format!("\n{} {shell}", "shell started:".green()));
                            }
                            "session_ended" | "session_timeout" => {
                                let reason = frame.payload.get("reason").and_then(Value::as_str).unwrap_or("ended");
                                output.println(&format!("\n{} {reason}", "session ended:".yellow()));
                                break;
                            }
                            "builtin_result" => {
                                if let Some(data) = frame.payload.get("output").and_then(Value::as_str) {
                                    let filtered = filter_remote_echo(data, &mut pending_echoes);
                                    print_shell_data(&filtered)?;
                                }
                            }
                            "history" => {
                                output.println(&format!("{}", "\n--- session history ---".cyan()));
                                if let Some(entries) = frame.payload.get("entries").and_then(Value::as_array) {
                                    for entry in entries.iter().rev() {
                                        let command = entry
                                            .get("command")
                                            .or_else(|| entry.get("data"))
                                            .and_then(Value::as_str)
                                            .unwrap_or("");
                                        let ts = entry.get("timestamp").and_then(Value::as_str).unwrap_or("");
                                        output.println(&format!("{ts} {command}"));
                                    }
                                }
                            }
                            "error" => {
                                let msg = frame.payload.get("message").and_then(Value::as_str).unwrap_or("unknown error");
                                output.eprintln(&format!("{} {msg}", "error:".red()));
                            }
                            "rate_limited" => {
                                let msg = frame.payload.get("message").and_then(Value::as_str).unwrap_or("rate limited");
                                output.eprintln(&format!("{} {msg}", "rate limited:".yellow()));
                            }
                            "phx_close" | "phx_error" => {
                                bail!("channel closed: {}", frame.event);
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(data) => sink.send(Message::Pong(data)).await?,
                    _ => {}
                }
            }
        }
    }

    if let Some(session_id) = session_id {
        output.println(&format!("{} {}", "closed session".dimmed(), session_id));
    }

    Ok(())
}

fn print_shell_data(data: &str) -> Result<()> {
    print!("{data}");
    io::stdout()
        .flush()
        .context("failed to flush remote shell output")?;
    Ok(())
}

async fn command(args: &RemoteCommandArgs, output: &Output) -> Result<()> {
    let command = args.command.join(" ");
    let config = load_remote_config().await.unwrap_or_default();
    let server = args
        .server
        .clone()
        .or(config.server)
        .unwrap_or_else(|| DEFAULT_SERVER.to_owned());
    let token = args
        .token
        .clone()
        .or(config.token)
        .context("missing token; pass --token or run tamandua-ctl remote login")?;

    let ws_url = dashboard_socket_url(&server, &token)?;
    let topic = format!("live_response:{}", args.agent_id);
    let refs = RefCounter::default();

    let (ws, _) = connect_async(&ws_url)
        .await
        .with_context(|| format!("failed to connect dashboard socket at {ws_url}"))?;
    let (mut sink, mut stream) = ws.split();

    let join_ref = refs.next();
    let join_payload = json!({
        "view_only": false,
        "supervisor_mode": args.supervisor_mode
    });
    send_phoenix(
        &mut sink,
        Some(&join_ref),
        &join_ref,
        &topic,
        "phx_join",
        join_payload,
    )
    .await?;

    let started_at = time::Instant::now();
    let deadline = started_at + Duration::from_secs(args.overall_timeout.max(1));
    let idle_timeout = Duration::from_secs(args.idle_timeout.max(1));
    let shell_start_timeout = Duration::from_secs(
        args.shell_start_timeout
            .max(1)
            .min(args.overall_timeout.max(1)),
    );
    let mut heartbeat = time::interval(Duration::from_secs(25));
    let mut joined = false;
    let mut shell_ready = false;
    let mut shell_ready_at: Option<time::Instant> = None;
    let mut shell_start_deadline: Option<time::Instant> = None;
    let mut sent = false;
    let mut sent_at: Option<time::Instant> = None;
    let mut command_output_seen = false;
    let mut command_confirmed = false;
    let mut command_exit_code: Option<i32> = None;
    let mut terminated = false;
    let mut last_output_at: Option<time::Instant> = None;
    let mut session_id: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut os: Option<String> = None;
    let mut captured_output = String::new();
    let mut events: Vec<Value> = Vec::new();
    let mut end_reason: Option<String> = None;
    let completion_marker = format!("__TAMANDUA_CTL_DONE_{}__", refs.next());

    loop {
        let first_output_timeout = Duration::from_secs(args.idle_timeout.max(15));
        let idle_deadline = if sent && !command_confirmed {
            deadline
        } else if sent && !command_output_seen {
            sent_at
                .map(|instant| instant + first_output_timeout)
                .unwrap_or(deadline)
        } else {
            last_output_at
                .map(|instant| instant + idle_timeout)
                .unwrap_or(deadline)
        };

        tokio::select! {
            _ = heartbeat.tick() => {
                let reference = refs.next();
                send_phoenix(&mut sink, None, &reference, "phoenix", "heartbeat", json!({})).await?;
            }
            _ = time::sleep_until(deadline) => {
                end_reason = Some("overall_timeout".to_owned());
                break;
            }
            _ = time::sleep_until(idle_deadline), if sent && command_confirmed && !terminated => {
                let reference = refs.next();
                send_phoenix(&mut sink, Some(&join_ref), &reference, &topic, "terminate", json!({})).await?;
                terminated = true;
                end_reason = Some("idle_timeout".to_owned());
            }
            _ = time::sleep(Duration::from_millis(50)), if joined && shell_ready && !sent && command_dispatch_ready(shell_ready_at, last_output_at) => {
                let command_line = wrap_one_shot_command(&args.command, os.as_deref(), &completion_marker)?;
                send_one_shot_command(
                    &mut sink,
                    &refs,
                    &join_ref,
                    &topic,
                    &command_line,
                    os.as_deref(),
                )
                .await?;
                sent = true;
                sent_at = Some(time::Instant::now());
            }
            _ = time::sleep_until(shell_start_deadline.unwrap_or(deadline)), if joined && shell_start_deadline.is_some() && !shell_ready && !sent => {
                end_reason = Some("shell_start_timeout".to_owned());
                events.push(json!({
                    "event": "shell_start_timeout",
                    "message": format!(
                        "Shell command was not dispatched because session_started was not received within {} seconds",
                        shell_start_timeout.as_secs()
                    )
                }));
                break;
            }
            incoming = stream.next() => {
                let Some(message) = incoming else {
                    break;
                };
                let message = message?;
                match message {
                    Message::Text(text) => {
                        let Some(frame) = PhoenixFrame::parse(&text)? else {
                            continue;
                        };

                        match frame.event.as_str() {
                            "phx_reply" if frame.reference.as_deref() == Some(join_ref.as_str()) => {
                                let status = frame.payload.get("status").and_then(Value::as_str).unwrap_or("error");
                                if status == "ok" {
                                    joined = true;
                                    shell_start_deadline = Some(time::Instant::now() + shell_start_timeout);
                                    let response = frame.payload.get("response").cloned().unwrap_or_else(|| json!({}));
                                    session_id = response.get("session_id").and_then(Value::as_str).map(ToOwned::to_owned);
                                    hostname = response.get("hostname").and_then(Value::as_str).map(ToOwned::to_owned);
                                    os = response.get("os").and_then(Value::as_str).map(ToOwned::to_owned);
                                } else {
                                    let reason = frame.payload
                                        .get("response")
                                        .and_then(|v| v.get("reason"))
                                        .and_then(Value::as_str)
                                        .unwrap_or("join failed");
                                    bail!("live response join failed: {reason}");
                                }
                            }
                            "session_started" => {
                                shell_ready = true;
                                shell_ready_at = Some(time::Instant::now());
                                events.push(json!({"event": "session_started", "payload": frame.payload}));
                            }
                            "output" => {
                                if let Some(data) = frame.payload.get("data").and_then(Value::as_str) {
                                    captured_output.push_str(data);
                                    if let Some(exit_code) = parse_completion_marker(&captured_output, &completion_marker) {
                                        command_confirmed = true;
                                        command_exit_code = Some(exit_code);
                                        let reference = refs.next();
                                        send_phoenix(
                                            &mut sink,
                                            Some(&join_ref),
                                            &reference,
                                            &topic,
                                            "terminate",
                                            json!({}),
                                        )
                                        .await?;
                                        terminated = true;
                                        end_reason = Some("command_confirmed".to_owned());
                                        break;
                                    }
                                    if sent {
                                        command_output_seen = true;
                                    }
                                    last_output_at = Some(time::Instant::now());
                                }
                            }
                            "builtin_result" => {
                                if let Some(data) = frame.payload.get("output").and_then(Value::as_str) {
                                    captured_output.push_str(data);
                                    if let Some(exit_code) = parse_completion_marker(&captured_output, &completion_marker) {
                                        command_confirmed = true;
                                        command_exit_code = Some(exit_code);
                                        let reference = refs.next();
                                        send_phoenix(
                                            &mut sink,
                                            Some(&join_ref),
                                            &reference,
                                            &topic,
                                            "terminate",
                                            json!({}),
                                        )
                                        .await?;
                                        terminated = true;
                                        end_reason = Some("command_confirmed".to_owned());
                                        break;
                                    }
                                    if sent {
                                        command_output_seen = true;
                                    }
                                    last_output_at = Some(time::Instant::now());
                                }
                                events.push(json!({"event": "builtin_result", "payload": frame.payload}));
                            }
                            "session_ended" | "session_timeout" => {
                                let reason = frame.payload.get("reason").and_then(Value::as_str).unwrap_or(frame.event.as_str());
                                end_reason = Some(reason.to_owned());
                                events.push(json!({"event": frame.event, "payload": frame.payload}));
                                break;
                            }
                            "error" => {
                                let msg = frame.payload.get("message").and_then(Value::as_str).unwrap_or("unknown error");
                                events.push(json!({"event": "error", "message": msg}));
                                if !sent && msg.contains("already exists") {
                                    continue;
                                }
                                if !sent {
                                    bail!("live response command failed before dispatch: {msg}");
                                }
                            }
                            "rate_limited" => {
                                let msg = frame.payload.get("message").and_then(Value::as_str).unwrap_or("rate limited");
                                bail!("live response command rate limited: {msg}");
                            }
                            "phx_close" | "phx_error" => {
                                if sent {
                                    end_reason = Some(frame.event.to_owned());
                                    break;
                                }

                                bail!("channel closed: {}", frame.event);
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(data) => sink.send(Message::Pong(data)).await?,
                    _ => {}
                }
            }
        }
    }

    if !terminated {
        let reference = refs.next();
        let _ = send_phoenix(
            &mut sink,
            Some(&join_ref),
            &reference,
            &topic,
            "terminate",
            json!({}),
        )
        .await;
    }

    let session_id_value = session_id.unwrap_or_else(|| "unknown".to_owned());
    let duration_ms = started_at.elapsed().as_millis() as u64;
    let status = if command_confirmed {
        "completed"
    } else if sent {
        "dispatched_unconfirmed"
    } else if !shell_ready {
        "shell_not_ready"
    } else {
        "not_dispatched"
    };
    let result = json!({
        "status": status,
        "shell_ready": shell_ready,
        "unconfirmed_dispatch": sent && !command_confirmed,
        "command_confirmed": command_confirmed,
        "exit_code": command_exit_code,
        "agent_id": args.agent_id,
        "hostname": hostname,
        "os": os,
        "session_id": session_id_value,
        "audit_resource_type": "live_response_session",
        "audit_resource_id": session_id_value,
        "command": command,
        "output": captured_output,
        "duration_ms": duration_ms,
        "end_reason": end_reason.unwrap_or_else(|| "socket_closed".to_owned()),
        "events": events,
    });

    if output.is_json() {
        output.print_json(&result)?;
    } else {
        print_shell_data(result.get("output").and_then(Value::as_str).unwrap_or(""))?;
        output.println(&format!(
            "\n{} {}",
            "audit session:".dimmed(),
            result
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }

    Ok(())
}

async fn upload(args: &RemoteUploadArgs, output: &Output) -> Result<()> {
    let session = remote_session(args.server.clone(), args.token.clone()).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout.max(30) + 30))
        .build()?;

    let content = tokio::fs::read(&args.local_path)
        .await
        .with_context(|| format!("failed to read {}", args.local_path.display()))?;
    let local_sha256 = hex::encode(Sha256::digest(&content));
    let content_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&content)
    };

    let created = send_api_request(
        client
            .post(format!("{}/api/v1/live-response/sessions", session.server))
            .bearer_auth(&session.token)
            .json(&json!({
                "agent_id": args.agent_id,
                "notes": "tamandua-ctl remote upload"
            })),
        "create live response session",
    )
    .await?;

    let session_id = created
        .get("data")
        .and_then(|data| data.get("session_id").or_else(|| data.get("id")))
        .and_then(Value::as_str)
        .context("live response session response did not include session_id")?
        .to_owned();

    let upload_result = send_api_request(
        client
            .post(format!(
                "{}/api/v1/live-response/session/{}/execute",
                session.server, session_id
            ))
            .bearer_auth(&session.token)
            .json(&json!({
                "command": "upload_file",
                "args": {
                    "path": args.remote_path,
                    "content": content_b64
                },
                "timeout": args.timeout.saturating_mul(1000)
            })),
        "upload file through live response",
    )
    .await?;

    let upload_error = live_response_command_error(&upload_result);
    let remote_sha256 = extract_upload_sha256(&upload_result);
    let integrity = match remote_sha256.as_deref() {
        Some(remote) if remote.eq_ignore_ascii_case(&local_sha256) => "matched",
        Some(_) => "mismatch",
        None => "not_reported",
    };
    let status = if upload_error.is_some() {
        "failed"
    } else if integrity == "mismatch" {
        "integrity_mismatch"
    } else {
        "uploaded"
    };

    let mut close_result = None;
    if args.close_session {
        let closed = send_api_request(
            client
                .delete(format!(
                    "{}/api/v1/live-response/sessions/{}",
                    session.server, session_id
                ))
                .bearer_auth(&session.token)
                .json(&json!({"reason": "tamandua_ctl_upload_complete"})),
            "close live response session",
        )
        .await
        .ok();
        close_result = closed;
    }

    let result = json!({
        "status": status,
        "agent_id": args.agent_id,
        "session_id": session_id,
        "local_path": args.local_path,
        "remote_path": args.remote_path,
        "size": content.len(),
        "local_sha256": local_sha256,
        "remote_sha256": remote_sha256,
        "integrity": integrity,
        "error": upload_error,
        "upload_response": upload_result,
        "close_response": close_result,
    });

    if output.is_json() {
        output.print_json(&result)?;
    } else {
        output.println(&format!(
            "{} {} -> {}",
            "uploaded".green(),
            args.local_path.display(),
            args.remote_path
        ));
        output.println(&format!(
            "{} {} ({})",
            "sha256:".dimmed(),
            result
                .get("local_sha256")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            integrity
        ));
    }

    if integrity == "mismatch" {
        bail!("remote upload SHA256 mismatch");
    }
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        bail!("remote upload failed: {error}");
    }

    Ok(())
}

fn live_response_command_error(value: &Value) -> Option<String> {
    let data = value.get("data")?;
    let status = data
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let exit_code = data.get("exit_code").and_then(Value::as_i64).unwrap_or(0);

    if let Some(output) = data.get("output") {
        if output
            .get("success")
            .and_then(Value::as_bool)
            .is_some_and(|success| !success)
        {
            let message = output
                .get("error_message")
                .and_then(Value::as_str)
                .unwrap_or("remote command reported success=false");
            return Some(format!("status={status} exit_code={exit_code}: {message}"));
        }
    }

    if status == "success" && exit_code == 0 {
        return None;
    }

    let output = data.get("output").map_or_else(
        || "remote command did not report output".to_owned(),
        |output| {
            output
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| output.to_string())
        },
    );

    Some(format!("status={status} exit_code={exit_code}: {output}"))
}

fn extract_upload_sha256(value: &Value) -> Option<String> {
    let output = value.get("data").and_then(|data| data.get("output"))?;

    if let Some(object_sha) = output
        .get("sha256")
        .or_else(|| output.get("sha256_hash"))
        .and_then(value_to_string)
    {
        return Some(object_sha);
    }

    let output = output.as_str()?;

    if let Ok(parsed) = serde_json::from_str::<Value>(output) {
        return parsed
            .get("sha256")
            .or_else(|| parsed.get("sha256_hash"))
            .and_then(value_to_string);
    }

    None
}

fn filter_remote_echo(data: &str, pending_echoes: &mut VecDeque<String>) -> String {
    let Some(line) = pending_echoes.front() else {
        return data.to_owned();
    };

    let candidates = [
        format!("{line}\r\n"),
        format!("{line}\n"),
        format!("{line}\r"),
        line.clone(),
    ];

    for candidate in candidates {
        if let Some(stripped) = data.strip_prefix(&candidate) {
            pending_echoes.pop_front();
            return stripped.to_owned();
        }
    }

    data.to_owned()
}

fn command_dispatch_ready(
    shell_ready_at: Option<time::Instant>,
    last_output_at: Option<time::Instant>,
) -> bool {
    let Some(shell_ready_at) = shell_ready_at else {
        return false;
    };

    match last_output_at {
        Some(last_output_at) => last_output_at.elapsed() >= Duration::from_millis(500),
        None => shell_ready_at.elapsed() >= Duration::from_secs(5),
    }
}

async fn browser_device_login(
    server: &str,
    no_browser: bool,
    output: &Output,
) -> Result<DeviceTokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let start_url = format!("{}/api/v1/cli-auth/device", server.trim_end_matches('/'));
    let response = client
        .post(&start_url)
        .json(&json!({
            "client_name": "tamandua-ctl",
            "scopes": ["live_response:shell"]
        }))
        .send()
        .await
        .with_context(|| format!("failed to start CLI auth at {start_url}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("failed to start CLI auth: HTTP {status} {body}");
    }

    let device: DeviceStartResponse = response.json().await?;

    output.println(&format!(
        "{}",
        "Open this URL to authorize tamandua-ctl:".cyan().bold()
    ));
    output.println(&device.verification_uri_complete);
    output.println(&format!("{} {}", "code:".dimmed(), device.user_code.bold()));

    if !no_browser {
        match webbrowser::open(&device.verification_uri_complete) {
            Ok(_) => output.println("Browser opened. Waiting for authorization..."),
            Err(err) => output.eprintln(&format!(
                "Could not open browser automatically: {err}. Open the URL above."
            )),
        }
    } else {
        output.println("Waiting for authorization...");
    }

    poll_device_token(&client, server, &device, output).await
}

async fn poll_device_token(
    client: &reqwest::Client,
    server: &str,
    device: &DeviceStartResponse,
    output: &Output,
) -> Result<DeviceTokenResponse> {
    let token_url = format!("{}/api/v1/cli-auth/token", server.trim_end_matches('/'));
    let deadline = time::Instant::now() + Duration::from_secs(device.expires_in);
    let interval = Duration::from_secs(device.interval.max(1));

    loop {
        if time::Instant::now() >= deadline {
            bail!("CLI authorization expired; run tamandua-ctl remote login again");
        }

        time::sleep(interval).await;

        let response = client
            .post(&token_url)
            .json(&json!({"device_code": device.device_code}))
            .send()
            .await
            .with_context(|| format!("failed to poll CLI auth at {token_url}"))?;

        if response.status().is_success() {
            let token: DeviceTokenResponse = response.json().await?;
            if let Some(expires_at) = token.expires_at.as_deref() {
                output.println(&format!(
                    "{} {}",
                    "authorized; token expires at".green(),
                    expires_at
                ));
            } else {
                output.println(&format!("{}", "authorized".green()));
            }
            return Ok(token);
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let parsed = serde_json::from_str::<ErrorResponse>(&body).ok();
        let error = parsed
            .and_then(|value| value.error)
            .unwrap_or_else(|| body.clone());

        match error.as_str() {
            "authorization_pending" => continue,
            "expired_token" => {
                bail!("CLI authorization expired; run tamandua-ctl remote login again")
            }
            "already_consumed" => bail!("CLI authorization code was already consumed"),
            "invalid_device_code" => bail!("CLI authorization code is invalid"),
            _ => bail!("CLI authorization failed: HTTP {status} {body}"),
        }
    }
}

fn dashboard_socket_url(server: &str, token: &str) -> Result<String> {
    let base = server.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{base}")
    };

    Ok(format!(
        "{ws_base}/socket/dashboard/websocket?token={token}&vsn={PHOENIX_VSN}"
    ))
}

async fn remote_session(server: Option<String>, token: Option<String>) -> Result<RemoteSession> {
    let config = load_remote_config().await.unwrap_or_default();
    let server = server
        .or(config.server)
        .unwrap_or_else(|| DEFAULT_SERVER.to_owned())
        .trim_end_matches('/')
        .to_owned();
    let token = token
        .or(config.token)
        .context("missing token; pass --token or run tamandua-ctl remote login")?;

    Ok(RemoteSession { server, token })
}

async fn send_api_request(request: reqwest::RequestBuilder, action: &str) -> Result<Value> {
    let response = request
        .send()
        .await
        .with_context(|| format!("failed to {action}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        bail!("failed to {action}: HTTP {status} {body}");
    }

    serde_json::from_str(&body).with_context(|| format!("invalid JSON while trying to {action}"))
}

fn string_field(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(value_to_string)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn string_field_nested(value: &Value, keys: &[&str], default: &str) -> String {
    let mut current = value;

    for key in keys {
        let Some(next) = current.get(*key) else {
            return default.to_owned();
        };
        current = next;
    }

    value_to_string(current)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let keep = max_chars.saturating_sub(3);
    format!("{}...", value.chars().take(keep).collect::<String>())
}

async fn load_remote_config() -> Result<RemoteConfig> {
    let path = remote_config_path()?;
    let body = tokio::fs::read_to_string(path).await?;
    Ok(serde_json::from_str(&body)?)
}

fn remote_config_path() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .context("APPDATA is not set")?;
        Ok(base
            .join("Tamandua")
            .join("tamandua-ctl")
            .join("remote.json"))
    }

    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("HOME is not set")?;
        Ok(base
            .join("tamandua")
            .join("tamandua-ctl")
            .join("remote.json"))
    }
}

async fn handle_shell_line<S>(
    sink: &mut S,
    refs: &RefCounter,
    join_ref: &str,
    topic: &str,
    line: String,
    output: &Output,
    pending_echoes: &mut VecDeque<String>,
) -> Result<bool>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match line.trim() {
        ":quit" | ":exit" => {
            let reference = refs.next();
            send_phoenix(
                sink,
                Some(join_ref),
                &reference,
                topic,
                "terminate",
                json!({}),
            )
            .await?;
            Ok(true)
        }
        ":help" => {
            print_shell_help(output);
            Ok(false)
        }
        ":history" => {
            let reference = refs.next();
            send_phoenix(
                sink,
                Some(join_ref),
                &reference,
                topic,
                "get_history",
                json!({}),
            )
            .await?;
            Ok(false)
        }
        _ if line.starts_with(":builtin ") => {
            let mut parts = line[9..].split_whitespace();
            let Some(command) = parts.next() else {
                output.eprintln("usage: :builtin <command> [args...]");
                return Ok(false);
            };
            let args: Vec<String> = parts.map(ToOwned::to_owned).collect();
            let reference = refs.next();
            send_phoenix(
                sink,
                Some(join_ref),
                &reference,
                topic,
                "builtin",
                json!({"command": command, "args": args}),
            )
            .await?;
            Ok(false)
        }
        _ if line.starts_with(":resize ") => {
            let parts: Vec<&str> = line[8..].split_whitespace().collect();
            if parts.len() != 2 {
                output.eprintln("usage: :resize <cols> <rows>");
                return Ok(false);
            }
            let cols: u16 = parts[0].parse().context("invalid cols value")?;
            let rows: u16 = parts[1].parse().context("invalid rows value")?;
            let reference = refs.next();
            send_phoenix(
                sink,
                Some(join_ref),
                &reference,
                topic,
                "resize",
                json!({"cols": cols, "rows": rows}),
            )
            .await?;
            Ok(false)
        }
        _ => {
            let reference = refs.next();
            if !line.is_empty() {
                pending_echoes.push_back(line.clone());
                while pending_echoes.len() > 16 {
                    pending_echoes.pop_front();
                }
            }
            send_phoenix(
                sink,
                Some(join_ref),
                &reference,
                topic,
                "input",
                json!({"data": format!("{line}\r\n")}),
            )
            .await?;
            Ok(false)
        }
    }
}

async fn send_one_shot_command<S>(
    sink: &mut S,
    refs: &RefCounter,
    join_ref: &str,
    topic: &str,
    line: &str,
    _os: Option<&str>,
) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    if line.trim().is_empty() {
        bail!("missing command");
    }

    let reference = refs.next();
    // Keep one-shot command input identical to the interactive shell path.
    // Windows cmd.exe running behind a PTY expects an Enter key sequence; a
    // bare CR can leave the local channel thinking the input was dispatched
    // while the remote side never emits the completion marker.
    let terminator = "\r\n";
    send_phoenix(
        sink,
        Some(join_ref),
        &reference,
        topic,
        "input",
        json!({"data": format!("{line}{terminator}")}),
    )
    .await
}

fn wrap_one_shot_command(command: &[String], os: Option<&str>, marker: &str) -> Result<String> {
    if command.is_empty() {
        bail!("missing command");
    }

    let line = command.join(" ");
    let marker = marker.replace('"', "").replace('\'', "");
    let os = os.unwrap_or("").to_ascii_lowercase();
    if os.contains("windows") {
        Ok(format!("{line}\r\necho {marker}:%ERRORLEVEL%"))
    } else {
        Ok(format!("{line}; printf '\\n{marker}:%s\\n' \"$?\""))
    }
}

fn parse_completion_marker(output: &str, marker: &str) -> Option<i32> {
    let marker_prefix = format!("{marker}:");
    if !output.contains(&marker_prefix) {
        return None;
    }
    output.rsplit(&marker_prefix).next().and_then(|tail| {
        let digits: String = tail
            .chars()
            .skip_while(|ch| ch.is_whitespace())
            .take_while(|ch| ch.is_ascii_digit() || *ch == '-')
            .collect();
        digits.parse::<i32>().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_windows_one_shot_marker_on_separate_line() {
        let wrapped = wrap_one_shot_command(
            &[
                "if".to_owned(),
                "exist".to_owned(),
                "C:\\Windows".to_owned(),
                "echo".to_owned(),
                "FOUND".to_owned(),
            ],
            Some("windows"),
            "__TAMANDUA_CTL_DONE_1__",
        )
        .expect("wrap windows command");

        assert_eq!(
            wrapped,
            "if exist C:\\Windows echo FOUND\r\necho __TAMANDUA_CTL_DONE_1__:%ERRORLEVEL%"
        );
    }

    #[test]
    fn parses_last_completion_marker() {
        let output =
            "first\r\n__TAMANDUA_CTL_DONE_1__:1\r\nsecond\r\n__TAMANDUA_CTL_DONE_1__:0\r\n";

        assert_eq!(
            parse_completion_marker(output, "__TAMANDUA_CTL_DONE_1__"),
            Some(0)
        );
    }

    #[test]
    fn live_response_command_error_detects_nested_upload_failure() {
        let value = json!({
            "data": {
                "status": "success",
                "exit_code": 0,
                "output": {
                    "success": false,
                    "error_message": "Failed to write file: access denied"
                }
            }
        });

        let error = live_response_command_error(&value).expect("nested failure should be reported");
        assert!(error.contains("access denied"));
    }

    #[test]
    fn live_response_command_error_accepts_successful_upload_object() {
        let value = json!({
            "data": {
                "status": "success",
                "exit_code": 0,
                "output": {
                    "path": "\\\\?\\D:\\Temp\\agent.exe",
                    "sha256": "abc123",
                    "size": 42
                }
            }
        });

        assert!(live_response_command_error(&value).is_none());
    }
}

async fn send_phoenix<S>(
    sink: &mut S,
    join_ref: Option<&str>,
    reference: &str,
    topic: &str,
    event: &str,
    payload: Value,
) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let frame = json!([join_ref, reference, topic, event, payload]);
    sink.send(Message::Text(frame.to_string())).await?;
    Ok(())
}

fn print_joined(output: &Output, response: &Value) {
    let hostname = response
        .get("hostname")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let session_id = response
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let os = response
        .get("os")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    output.println(&format!("{} {hostname}", "connected to".green().bold()));
    output.println(&format!("{} {session_id}", "session:".dimmed()));
    output.println(&format!("{} {os}", "os:".dimmed()));
}

fn print_shell_help(output: &Output) {
    output.println(&format!(
        "{}",
        "commands: type shell commands normally; :history, :builtin <cmd>, :resize <cols> <rows>, :quit".dimmed()
    ));
}

#[derive(Default)]
struct RefCounter(AtomicU64);

impl RefCounter {
    fn next(&self) -> String {
        self.0.fetch_add(1, Ordering::Relaxed).to_string()
    }
}

struct PhoenixFrame {
    reference: Option<String>,
    _topic: String,
    event: String,
    payload: Value,
}

impl PhoenixFrame {
    fn parse(text: &str) -> Result<Option<Self>> {
        let value: Value = serde_json::from_str(text)?;
        let Some(items) = value.as_array() else {
            return Ok(None);
        };

        if items.len() != 5 {
            return Ok(None);
        }

        Ok(Some(Self {
            reference: items[1].as_str().map(ToOwned::to_owned),
            _topic: items[2].as_str().unwrap_or_default().to_owned(),
            event: items[3].as_str().unwrap_or_default().to_owned(),
            payload: items[4].clone(),
        }))
    }
}
