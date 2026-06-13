//! IPC client for CLI-to-Agent communication
//!
//! Uses the same protocol as the GUI:
//! - Windows: Named pipes
//! - Linux/macOS: Unix domain sockets
//! - MessagePack serialization with length-prefix framing

mod protocol;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

pub use protocol::MessageFrame;

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Default IPC pipe name for Windows
#[cfg(windows)]
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\tamandua-agent";

/// Default IPC socket path for macOS
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET_PATH: &str = "/Library/Application Support/Tamandua/agent.sock";

/// Default IPC socket path for Linux
#[cfg(all(unix, not(target_os = "macos")))]
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/tamandua/agent.sock";

/// IPC client for Agent communication
pub struct IpcClient {
    #[cfg(windows)]
    stream: Option<tokio::net::windows::named_pipe::NamedPipeClient>,

    #[cfg(unix)]
    stream: Option<tokio::net::UnixStream>,

    authenticated: bool,
    timeout: Duration,
}

impl IpcClient {
    /// Create a new IPC client (does not connect yet)
    pub fn new(timeout: Duration) -> Self {
        Self {
            stream: None,
            authenticated: false,
            timeout,
        }
    }

    /// Connect to the IPC server using default path
    pub async fn connect(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            self.connect_to(DEFAULT_PIPE_NAME).await
        }

        #[cfg(unix)]
        {
            self.connect_to(DEFAULT_SOCKET_PATH).await
        }
    }

    /// Connect to the IPC server at a specific path
    pub async fn connect_to(&mut self, path: &str) -> Result<()> {
        #[cfg(windows)]
        {
            self.stream = Some(Self::connect_windows(path, self.timeout).await?);
        }

        #[cfg(unix)]
        {
            self.stream = Some(Self::connect_unix(path, self.timeout).await?);
        }

        info!("Connected to Agent IPC server");
        Ok(())
    }

    /// Connect to Windows named pipe
    #[cfg(windows)]
    async fn connect_windows(
        pipe_name: &str,
        timeout: Duration,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use tokio::net::windows::named_pipe::ClientOptions;

        debug!("Connecting to IPC server at {}", pipe_name);

        let deadline = tokio::time::Instant::now() + timeout;
        let mut retries = 0;
        let max_retries = 5;

        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("Connection timed out after {:?}", timeout);
            }

            match ClientOptions::new().open(pipe_name) {
                Ok(client) => {
                    info!("Connected to IPC server");
                    return Ok(client);
                }
                Err(e) if retries < max_retries => {
                    let delay = Duration::from_millis(100 * (1 << retries));
                    warn!(
                        "Failed to connect (attempt {}/{}): {}. Retrying in {:?}...",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    retries += 1;
                }
                Err(e) => {
                    bail!(
                        "Failed to connect to IPC server after {} attempts: {}",
                        max_retries,
                        e
                    );
                }
            }
        }
    }

    /// Connect to Unix domain socket
    #[cfg(unix)]
    async fn connect_unix(socket_path: &str, timeout: Duration) -> Result<tokio::net::UnixStream> {
        use tokio::net::UnixStream;

        debug!("Connecting to IPC server at {}", socket_path);

        let deadline = tokio::time::Instant::now() + timeout;
        let mut retries = 0;
        let max_retries = 5;

        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("Connection timed out after {:?}", timeout);
            }

            match UnixStream::connect(socket_path).await {
                Ok(stream) => {
                    info!("Connected to IPC server");
                    return Ok(stream);
                }
                Err(e) if retries < max_retries => {
                    let delay = Duration::from_millis(100 * (1 << retries));
                    warn!(
                        "Failed to connect (attempt {}/{}): {}. Retrying in {:?}...",
                        retries + 1,
                        max_retries,
                        e,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    retries += 1;
                }
                Err(e) => {
                    bail!(
                        "Failed to connect to IPC server after {} attempts: {}",
                        max_retries,
                        e
                    );
                }
            }
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Disconnect from the server
    pub fn disconnect(&mut self) {
        self.stream = None;
        self.authenticated = false;
        info!("Disconnected from Agent IPC server");
    }

    /// Authenticate with the agent using challenge-response protocol
    ///
    /// This method uses the modern challenge-response protocol which prevents
    /// replay attacks. The flow is:
    ///
    /// 1. Send `RequestChallenge` to the server
    /// 2. Receive `Challenge { nonce, timestamp }` from the server
    /// 3. Compute HMAC-SHA256(nonce || timestamp, token_secret)
    /// 4. Send `AuthenticateChallenge { response }` to the server
    /// 5. Receive `Authenticated` or `Error`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token file cannot be read (requires elevated privileges)
    /// - Challenge request fails
    /// - Authentication is rejected (wrong token, expired challenge, replay)
    pub async fn authenticate(&mut self) -> Result<()> {
        // Load token secret - this requires elevated privileges
        let token_secret = load_token_secret().await?;

        // Step 1: Request challenge from server
        debug!("Requesting authentication challenge from Agent");
        let challenge_response = self.request(IpcMessage::RequestChallenge).await?;

        // Step 2: Extract challenge
        let challenge = match challenge_response {
            IpcMessage::Challenge(c) => c,
            IpcMessage::Error { message, code } => {
                bail!("Failed to get challenge: {} (code: {:?})", message, code);
            }
            _ => bail!(
                "Unexpected response to challenge request: {:?}",
                challenge_response
            ),
        };

        debug!(
            "Received challenge: nonce={}, timestamp={}",
            challenge.nonce, challenge.timestamp
        );

        // Step 3: Compute response using HMAC-SHA256
        let response = ChallengeResponse::create(&challenge, &token_secret);

        // Step 4: Send response
        debug!("Sending challenge response");
        let auth_result = self
            .request(IpcMessage::AuthenticateChallenge { response })
            .await?;

        // Step 5: Check result
        match auth_result {
            IpcMessage::Authenticated => {
                self.authenticated = true;
                info!("Authenticated with Agent via challenge-response");
                Ok(())
            }
            IpcMessage::Error { message, code } => {
                bail!("Authentication failed: {} (code: {:?})", message, code);
            }
            _ => bail!("Unexpected response to authentication: {:?}", auth_result),
        }
    }

    /// Send a message and wait for response
    pub async fn request(&mut self, message: IpcMessage) -> Result<IpcMessage> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected to IPC server"))?;

        // Send request
        MessageFrame::write(stream, &message)
            .await
            .context("Failed to send IPC request")?;

        // Read response
        let response = MessageFrame::read(stream)
            .await
            .context("Failed to read IPC response")?;

        Ok(response)
    }

    // ==================== Convenience methods ====================

    /// Get agent status
    pub async fn get_status(&mut self) -> Result<AgentStatus> {
        let response = self.request(IpcMessage::GetStatus).await?;
        match response {
            IpcMessage::StatusUpdate(status) => Ok(status),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get agent metrics
    pub async fn get_metrics(&mut self) -> Result<AgentMetrics> {
        let response = self.request(IpcMessage::GetMetrics).await?;
        match response {
            IpcMessage::MetricsUpdate(metrics) => Ok(metrics),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get component status
    pub async fn get_component_status(&mut self) -> Result<ComponentStatus> {
        let response = self.request(IpcMessage::GetComponentStatus).await?;
        match response {
            IpcMessage::ComponentStatusUpdate(status) => Ok(status),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get current performance profile
    pub async fn get_performance_profile(&mut self) -> Result<PerformanceProfile> {
        let response = self.request(IpcMessage::GetPerformanceProfile).await?;
        match response {
            IpcMessage::PerformanceProfileResponse(profile) => Ok(profile),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Set performance profile (requires authentication)
    pub async fn set_performance_profile(&mut self, profile: PerformanceProfile) -> Result<()> {
        if !self.is_authenticated() {
            bail!("Authentication required to change performance profile");
        }

        let response = self
            .request(IpcMessage::SetPerformanceProfile { profile })
            .await?;

        match response {
            IpcMessage::ProfileChanged { .. } | IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, code } => {
                if code.as_deref() == Some("AUTH_REQUIRED") {
                    bail!("Authentication required");
                }
                bail!("Server error: {}", message);
            }
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get alerts
    pub async fn get_alerts(
        &mut self,
        since: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<AlertNotification>> {
        let response = self.request(IpcMessage::GetAlerts { since, limit }).await?;
        match response {
            IpcMessage::Alerts(alerts) => Ok(alerts),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get logs
    pub async fn get_logs(
        &mut self,
        since: Option<DateTime<Utc>>,
        level: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<LogEntry>> {
        let response = self
            .request(IpcMessage::GetLogs {
                since,
                level,
                limit,
            })
            .await?;
        match response {
            IpcMessage::LogEntries(logs) => Ok(logs),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Start scan
    pub async fn start_scan(
        &mut self,
        path: PathBuf,
        recursive: bool,
        scan_archives: bool,
    ) -> Result<()> {
        let response = self
            .request(IpcMessage::StartScan {
                path,
                recursive,
                scan_archives,
            })
            .await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get version info
    pub async fn get_version(&mut self) -> Result<VersionInfo> {
        let response = self.request(IpcMessage::GetVersion).await?;
        match response {
            IpcMessage::VersionInfo(info) => Ok(info),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get quarantined files
    pub async fn get_quarantined_files(&mut self) -> Result<Vec<QuarantineEntry>> {
        let response = self.request(IpcMessage::GetQuarantinedFiles).await?;
        match response {
            IpcMessage::QuarantinedFiles(files) => Ok(files),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Restore file from quarantine
    pub async fn restore_quarantined_file(&mut self, quarantine_id: String) -> Result<()> {
        let response = self
            .request(IpcMessage::RestoreFile { quarantine_id })
            .await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Delete quarantined file permanently
    pub async fn delete_quarantined_file(&mut self, quarantine_id: String) -> Result<()> {
        let response = self
            .request(IpcMessage::DeleteQuarantinedFile { quarantine_id })
            .await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Kill process
    pub async fn kill_process(&mut self, pid: u32) -> Result<()> {
        let response = self.request(IpcMessage::KillProcess { pid }).await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Execute response action
    pub async fn execute_action(&mut self, action: ResponseAction) -> Result<()> {
        let response = self.request(IpcMessage::ExecuteAction { action }).await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Acknowledge alert
    pub async fn acknowledge_alert(&mut self, alert_id: String) -> Result<()> {
        let response = self
            .request(IpcMessage::AcknowledgeAlert { alert_id })
            .await?;
        match response {
            IpcMessage::Success => Ok(()),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }

    /// Get process tree
    pub async fn get_process_tree(&mut self) -> Result<Vec<ProcessInfo>> {
        let response = self.request(IpcMessage::GetProcessTree).await?;
        match response {
            IpcMessage::ProcessTree(tree) => Ok(tree),
            IpcMessage::Error { message, .. } => bail!("Server error: {}", message),
            _ => bail!("Unexpected response: {:?}", response),
        }
    }
}

// ==================== Token Handling ====================

/// Get default token file path
fn default_token_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Tamandua\ipc_token.json")
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua/ipc_token.json")
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/tamandua/ipc_token.json")
    }
}

/// Authentication token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcToken {
    secret: String,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
}

/// Load and hash the authentication token (legacy)
///
/// **Deprecated**: Use `load_token_secret()` with challenge-response auth instead.
async fn load_token_hash() -> Result<String> {
    let path = default_token_path();
    let data = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("Failed to read token file: {}", path.display()))?;

    let token: IpcToken = serde_json::from_str(&data).context("Failed to parse token file")?;

    let mut hasher = Sha256::new();
    hasher.update(token.secret.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Load the raw authentication token secret for challenge-response auth
///
/// # Errors
///
/// Returns a detailed error if the token cannot be read:
/// - Token file not found: Agent may not be installed or running
/// - Permission denied: CLI must run with elevated privileges (Run as Administrator / sudo)
/// - Parse error: Token file is corrupted
async fn load_token_secret() -> Result<String> {
    let path = default_token_path();
    match tokio::fs::read_to_string(&path).await {
        Ok(data) => {
            let token: IpcToken =
                serde_json::from_str(&data).context("Failed to parse token file")?;
            Ok(token.secret)
        }
        Err(e) => {
            // Provide helpful error messages for common issues
            let err_msg = if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "Token file not found at {}. Is the Tamandua Agent service installed and running?",
                    path.display()
                )
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                #[cfg(windows)]
                let hint =
                    "The CLI must 'Run as Administrator' to authenticate with the Agent service.";
                #[cfg(unix)]
                let hint = "The CLI must run with elevated privileges (sudo) to authenticate with the Agent service.";

                format!(
                    "Permission denied reading token file: {}. {}",
                    path.display(),
                    hint
                )
            } else {
                format!("Failed to read token file {}: {}", path.display(), e)
            };

            warn!("{}", err_msg);
            bail!("{}", err_msg)
        }
    }
}

// ==================== Authentication Types ====================

/// Challenge sent from server to client for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Random nonce (32 bytes, hex-encoded)
    pub nonce: String,
    /// Unix timestamp when challenge was created
    pub timestamp: u64,
}

/// Response from client to server challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The nonce from the challenge (echoed back)
    pub nonce: String,
    /// The timestamp from the challenge (echoed back)
    pub timestamp: u64,
    /// HMAC-SHA256(nonce || timestamp, token_secret), hex-encoded
    pub signature: String,
}

impl ChallengeResponse {
    /// Create a response to a challenge using the token secret
    pub fn create(challenge: &AuthChallenge, secret: &str) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");

        // HMAC(nonce || timestamp, secret)
        mac.update(challenge.nonce.as_bytes());
        mac.update(&challenge.timestamp.to_le_bytes());

        let signature = hex::encode(mac.finalize().into_bytes());

        Self {
            nonce: challenge.nonce.clone(),
            timestamp: challenge.timestamp,
            signature,
        }
    }
}

// ==================== IPC Message Types ====================
// These match the GUI's IpcMessage types exactly for protocol compatibility

/// Messages exchanged between CLI and Agent service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    // Read Operations
    GetStatus,
    GetMetrics,
    GetAlerts {
        since: Option<DateTime<Utc>>,
        limit: Option<usize>,
    },
    GetLogs {
        since: Option<DateTime<Utc>>,
        level: Option<String>,
        limit: Option<usize>,
    },
    GetQuarantinedFiles,
    GetActiveConnections,
    GetProcessTree,
    GetVersion,
    GetComponentStatus,
    GetPerformanceProfile,

    // Write Operations (require auth)
    /// Authenticate with token hash (legacy - still supported for backwards compatibility)
    Authenticate {
        token_hash: String,
    },

    /// Request authentication challenge (new challenge-response protocol)
    RequestChallenge,

    /// Respond to authentication challenge
    AuthenticateChallenge {
        response: ChallengeResponse,
    },
    StartScan {
        path: PathBuf,
        recursive: bool,
        scan_archives: bool,
    },
    CancelScan {
        scan_id: String,
    },
    UpdateConfig {
        config: AgentConfigUpdate,
    },
    ExecuteAction {
        action: ResponseAction,
    },
    RestoreFile {
        quarantine_id: String,
    },
    DeleteQuarantinedFile {
        quarantine_id: String,
    },
    KillProcess {
        pid: u32,
    },
    TestBackendConnection,
    CheckForUpdates,
    ApplyUpdate,
    AcknowledgeAlert {
        alert_id: String,
    },
    SetPerformanceProfile {
        profile: PerformanceProfile,
    },

    // Responses
    /// Authentication challenge from server
    Challenge(AuthChallenge),

    StatusUpdate(AgentStatus),
    MetricsUpdate(AgentMetrics),
    ScanProgress {
        scan_id: String,
        path: PathBuf,
        progress: f32,
        files_scanned: u64,
        threats_found: u32,
    },
    ScanComplete {
        scan_id: String,
        results: ScanResults,
    },
    Alert(AlertNotification),
    LogEntries(Vec<LogEntry>),
    Alerts(Vec<AlertNotification>),
    QuarantinedFiles(Vec<QuarantineEntry>),
    ActiveConnections(Vec<NetworkConnection>),
    ProcessTree(Vec<ProcessInfo>),
    VersionInfo(VersionInfo),
    BackendTestResult {
        connected: bool,
        latency_ms: Option<u64>,
        error: Option<String>,
    },
    UpdateCheckResult {
        update_available: bool,
        current_version: String,
        latest_version: Option<String>,
        release_notes: Option<String>,
        download_size: Option<u64>,
    },
    UpdateProgress {
        version: String,
        downloaded_bytes: u64,
        total_bytes: u64,
        percent: f32,
    },
    UpdateInstalling {
        version: String,
    },
    UpdateReady {
        version: String,
        requires_restart: bool,
    },
    UpdateError {
        message: String,
        recoverable: bool,
    },
    ComponentStatusUpdate(ComponentStatus),
    PerformanceProfileResponse(PerformanceProfile),
    ProfileChanged {
        old: PerformanceProfile,
        new: PerformanceProfile,
        collectors_affected: Vec<String>,
    },
    Authenticated,
    Success,
    Error {
        message: String,
        code: Option<String>,
    },
}

// ==================== Data Types ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub version: String,
    pub state: AgentState,
    pub backend_connected: bool,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub collectors_running: Vec<String>,
    pub protection_enabled: bool,
    pub scan_in_progress: bool,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentState {
    Starting,
    Running,
    Degraded,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetrics {
    pub timestamp: DateTime<Utc>,
    pub events_processed: u64,
    pub events_per_second: f64,
    pub alerts_generated: u32,
    pub actions_executed: u32,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub collector_metrics: Vec<CollectorMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetrics {
    pub name: String,
    pub events_collected: u64,
    pub events_per_second: f64,
    pub errors: u32,
    pub cpu_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub driver: DriverStatus,
    pub collectors: Vec<CollectorStatus>,
    pub backend: BackendStatus,
    pub pressure_level: PressureLevel,
    pub health: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverStatus {
    pub loaded: bool,
    pub version: Option<String>,
    pub events_captured: u64,
    pub last_event_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub running: bool,
    pub events_per_second: f64,
    pub total_events: u64,
    pub errors: u32,
    pub last_error: Option<String>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub connected: bool,
    pub url: String,
    pub latency_ms: Option<u64>,
    pub events_queued: u64,
    pub events_sent: u64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    None,
    Light,
    Moderate,
    Heavy,
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PressureLevel::None => write!(f, "none"),
            PressureLevel::Light => write!(f, "light"),
            PressureLevel::Moderate => write!(f, "moderate"),
            PressureLevel::Heavy => write!(f, "heavy"),
            PressureLevel::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub checks: Vec<HealthCheck>,
    pub last_check_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthState::Healthy => write!(f, "healthy"),
            HealthState::Degraded => write!(f, "degraded"),
            HealthState::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceProfile {
    Aggressive,
    Balanced,
    Lightweight,
}

impl std::fmt::Display for PerformanceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerformanceProfile::Aggressive => write!(f, "aggressive"),
            PerformanceProfile::Balanced => write!(f, "balanced"),
            PerformanceProfile::Lightweight => write!(f, "lightweight"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotification {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub threat_name: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub file_path: Option<PathBuf>,
    pub mitre_tactics: Vec<String>,
    pub remediation: Option<String>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Low => write!(f, "low"),
            AlertSeverity::Medium => write!(f, "medium"),
            AlertSeverity::High => write!(f, "high"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub module: Option<String>,
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub threats: Vec<ThreatDetection>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub file_path: PathBuf,
    pub threat_name: String,
    pub severity: AlertSeverity,
    pub detection_method: String,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_at: DateTime<Utc>,
    pub threat_name: String,
    pub file_size: u64,
    pub file_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: PathBuf,
    pub command_line: String,
    pub user: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub started_at: DateTime<Utc>,
    pub children: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub build_date: String,
    pub commit_hash: String,
    pub rust_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigUpdate {
    pub scan_interval_seconds: Option<u64>,
    pub heartbeat_interval_seconds: Option<u64>,
    pub enable_real_time_protection: Option<bool>,
    pub enable_cloud_lookup: Option<bool>,
    pub excluded_paths: Option<Vec<PathBuf>>,
    pub excluded_processes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    KillProcess { pid: u32 },
    QuarantineFile { path: PathBuf },
    IsolateHost,
    RestoreHost,
    BlockIp { ip: String },
    UnblockIp { ip: String },
}
