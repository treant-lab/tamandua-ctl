//! CLI argument definitions using clap derive
//!
//! All commands and subcommands are defined here using clap's derive macros.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Tamandua EDR command-line control tool
#[derive(Parser, Debug)]
#[command(name = "tamandua-ctl")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Output format (json for machine-readable output)
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// IPC socket/pipe path (defaults to system path)
    #[arg(long, global = true, env = "TAMANDUA_IPC_PATH")]
    pub ipc_path: Option<String>,

    /// Connection timeout in seconds
    #[arg(long, default_value = "5", global = true)]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show agent status and health information
    Status(StatusArgs),

    /// List and search telemetry events
    Events(EventsArgs),

    /// List, acknowledge, and manage alerts
    Alerts(AlertsArgs),

    /// Show and modify agent configuration
    Config(ConfigArgs),

    /// Start an on-demand scan
    Scan(ScanArgs),

    /// Manage quarantined files
    Quarantine(QuarantineArgs),

    /// Execute response actions
    Response(ResponseArgs),

    /// Remote server operations
    Remote(RemoteArgs),

    /// Show version information
    Version,
}

// ==================== Status Command ====================

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Show detailed component status
    #[arg(short, long)]
    pub detailed: bool,

    /// Show performance metrics
    #[arg(short, long)]
    pub metrics: bool,

    /// Watch mode - continuously update status
    #[arg(short, long)]
    pub watch: bool,

    /// Update interval for watch mode (seconds)
    #[arg(long, default_value = "2")]
    pub interval: u64,
}

// ==================== Events Command ====================

#[derive(Args, Debug)]
pub struct EventsArgs {
    #[command(subcommand)]
    pub command: Option<EventsSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum EventsSubcommand {
    /// List recent events
    List(EventsListArgs),

    /// Search events by criteria
    Search(EventsSearchArgs),

    /// Show event statistics
    Stats,
}

#[derive(Args, Debug)]
pub struct EventsListArgs {
    /// Maximum number of events to show
    #[arg(short = 'n', long, default_value = "50")]
    pub limit: usize,

    /// Show events since this time (e.g., "1h", "30m", "2024-01-01")
    #[arg(short, long)]
    pub since: Option<String>,

    /// Filter by event type
    #[arg(short = 't', long)]
    pub event_type: Option<String>,

    /// Filter by severity level
    #[arg(long)]
    pub severity: Option<Severity>,
}

#[derive(Args, Debug)]
pub struct EventsSearchArgs {
    /// Search query
    pub query: String,

    /// Maximum results
    #[arg(short = 'n', long, default_value = "100")]
    pub limit: usize,
}

// ==================== Alerts Command ====================

#[derive(Args, Debug)]
pub struct AlertsArgs {
    #[command(subcommand)]
    pub command: Option<AlertsSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum AlertsSubcommand {
    /// List alerts
    List(AlertsListArgs),

    /// Acknowledge an alert
    Ack(AlertAckArgs),

    /// Show alert details
    Show(AlertShowArgs),

    /// Show alert statistics
    Stats,
}

#[derive(Args, Debug)]
pub struct AlertsListArgs {
    /// Maximum number of alerts to show
    #[arg(short = 'n', long, default_value = "50")]
    pub limit: usize,

    /// Show events since this time
    #[arg(short, long)]
    pub since: Option<String>,

    /// Filter by severity
    #[arg(long)]
    pub severity: Option<Severity>,

    /// Show only unacknowledged alerts
    #[arg(long)]
    pub unacked: bool,

    /// Show all alerts (including acknowledged)
    #[arg(short, long)]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct AlertAckArgs {
    /// Alert ID to acknowledge
    pub alert_id: String,

    /// Acknowledgement note
    #[arg(short, long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct AlertShowArgs {
    /// Alert ID to show
    pub alert_id: String,
}

// ==================== Config Command ====================

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: Option<ConfigSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigSubcommand {
    /// Show current configuration
    Show,

    /// Get a specific configuration value
    Get(ConfigGetArgs),

    /// Set a configuration value (requires authentication)
    Set(ConfigSetArgs),

    /// Get/set performance profile
    Profile(ProfileArgs),

    /// Reload configuration from disk
    Reload,
}

#[derive(Args, Debug)]
pub struct ConfigGetArgs {
    /// Configuration key to get
    pub key: String,
}

#[derive(Args, Debug)]
pub struct ConfigSetArgs {
    /// Configuration key to set
    pub key: String,

    /// Value to set
    pub value: String,
}

#[derive(Args, Debug)]
pub struct ProfileArgs {
    /// Profile to set (aggressive, balanced, lightweight)
    #[arg(value_enum)]
    pub profile: Option<PerformanceProfileArg>,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum PerformanceProfileArg {
    Aggressive,
    Balanced,
    Lightweight,
}

// ==================== Scan Command ====================

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub command: ScanSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ScanSubcommand {
    /// Start a new scan
    Start(ScanStartArgs),

    /// Show scan status
    Status,

    /// Cancel running scan
    Cancel(ScanCancelArgs),

    /// List recent scan results
    History(ScanHistoryArgs),
}

#[derive(Args, Debug)]
pub struct ScanStartArgs {
    /// Path to scan
    pub path: PathBuf,

    /// Scan recursively
    #[arg(short, long, default_value = "true")]
    pub recursive: bool,

    /// Scan inside archive files
    #[arg(short, long)]
    pub archives: bool,

    /// Wait for scan to complete
    #[arg(short, long)]
    pub wait: bool,
}

#[derive(Args, Debug)]
pub struct ScanCancelArgs {
    /// Scan ID to cancel (or "all")
    pub scan_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct ScanHistoryArgs {
    /// Number of recent scans to show
    #[arg(short = 'n', long, default_value = "10")]
    pub limit: usize,
}

// ==================== Quarantine Command ====================

#[derive(Args, Debug)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    pub command: Option<QuarantineSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum QuarantineSubcommand {
    /// List quarantined files
    List(QuarantineListArgs),

    /// Show quarantine entry details
    Show(QuarantineShowArgs),

    /// Restore a file from quarantine
    Restore(QuarantineRestoreArgs),

    /// Permanently delete a quarantined file
    Delete(QuarantineDeleteArgs),
}

#[derive(Args, Debug)]
pub struct QuarantineListArgs {
    /// Maximum entries to show
    #[arg(short = 'n', long, default_value = "50")]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct QuarantineShowArgs {
    /// Quarantine entry ID
    pub id: String,
}

#[derive(Args, Debug)]
pub struct QuarantineRestoreArgs {
    /// Quarantine entry ID
    pub id: String,

    /// Force restore without confirmation
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct QuarantineDeleteArgs {
    /// Quarantine entry ID
    pub id: String,

    /// Force delete without confirmation
    #[arg(short, long)]
    pub force: bool,
}

// ==================== Response Command ====================

#[derive(Args, Debug)]
pub struct ResponseArgs {
    #[command(subcommand)]
    pub command: ResponseSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ResponseSubcommand {
    /// Kill a process
    Kill(KillArgs),

    /// Quarantine a file
    QuarantineFile(QuarantineFileArgs),

    /// Isolate the host from network
    Isolate,

    /// Restore host network connectivity
    Restore,

    /// Block an IP address
    BlockIp(BlockIpArgs),

    /// Unblock an IP address
    UnblockIp(UnblockIpArgs),
}

#[derive(Args, Debug)]
pub struct KillArgs {
    /// Process ID to kill
    pub pid: u32,

    /// Force kill (SIGKILL on Unix)
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct QuarantineFileArgs {
    /// File path to quarantine
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct BlockIpArgs {
    /// IP address to block
    pub ip: String,

    /// Duration in seconds (0 = permanent)
    #[arg(short, long, default_value = "0")]
    pub duration: u64,
}

#[derive(Args, Debug)]
pub struct UnblockIpArgs {
    /// IP address to unblock
    pub ip: String,
}

// ==================== Remote Command ====================

#[derive(Args, Debug)]
pub struct RemoteArgs {
    #[command(subcommand)]
    pub command: RemoteSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum RemoteSubcommand {
    /// Store a server/operator token for later remote commands
    Login(RemoteLoginArgs),

    /// List agents from the Tamandua server
    Agents(RemoteAgentsArgs),

    /// List alerts from the Tamandua server
    Alerts(RemoteAlertsArgs),

    /// Open an authenticated live response shell through the Tamandua server
    Shell(RemoteShellArgs),

    /// Execute one non-interactive live response command through the Tamandua server
    Command(RemoteCommandArgs),

    /// Upload a local file to an agent through audited live response
    Upload(RemoteUploadArgs),
}

#[derive(Args, Debug)]
pub struct RemoteAgentsArgs {
    #[command(subcommand)]
    pub command: RemoteAgentsSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum RemoteAgentsSubcommand {
    /// List enrolled agents visible to the operator
    List(RemoteAgentsListArgs),
}

#[derive(Args, Debug)]
pub struct RemoteAgentsListArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard/API JWT. If omitted, saved remote login is used.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Filter by server-side status such as online, offline, degraded, isolated
    #[arg(long)]
    pub status: Option<String>,
}

#[derive(Args, Debug)]
pub struct RemoteAlertsArgs {
    #[command(subcommand)]
    pub command: RemoteAlertsSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum RemoteAlertsSubcommand {
    /// List alerts visible to the operator
    List(RemoteAlertsListArgs),
}

#[derive(Args, Debug)]
pub struct RemoteAlertsListArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard/API JWT. If omitted, saved remote login is used.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Filter by agent UUID
    #[arg(long, env = "TAMANDUA_AGENT_ID")]
    pub agent_id: Option<String>,

    /// Filter by minimum or exact server severity, depending on backend semantics
    #[arg(long)]
    pub severity: Option<Severity>,

    /// Filter by status such as new, investigating, resolved, false_positive, active
    #[arg(long)]
    pub status: Option<String>,

    /// Maximum number of alerts to show
    #[arg(long, default_value = "50")]
    pub limit: u32,
}

#[derive(Args, Debug)]
pub struct RemoteLoginArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard socket JWT generated by the web UI. If omitted, browser login is used.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Print the login URL instead of opening the browser
    #[arg(long)]
    pub no_browser: bool,
}

#[derive(Args, Debug)]
pub struct RemoteShellArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard socket JWT. This is not an enrollment token.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Target agent UUID
    #[arg(long, env = "TAMANDUA_AGENT_ID")]
    pub agent_id: String,

    /// Connect as view-only
    #[arg(long)]
    pub view_only: bool,

    /// Enable supervisor mode when allowed by the server
    #[arg(long)]
    pub supervisor_mode: bool,
}

#[derive(Args, Debug)]
pub struct RemoteCommandArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard socket JWT. This is not an enrollment token.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Target agent UUID
    #[arg(long, env = "TAMANDUA_AGENT_ID")]
    pub agent_id: String,

    /// Enable supervisor mode when allowed by the server
    #[arg(long)]
    pub supervisor_mode: bool,

    /// Stop after this many seconds without new output once the command is sent
    #[arg(long, default_value = "2")]
    pub idle_timeout: u64,

    /// Maximum seconds to wait for the agent to confirm shell startup before dispatching the command
    #[arg(long, default_value = "45")]
    pub shell_start_timeout: u64,

    /// Maximum seconds to wait for join, command dispatch, and output
    #[arg(long, default_value = "30")]
    pub overall_timeout: u64,

    /// Command and arguments to execute. Use -- before commands with flags.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RemoteUploadArgs {
    /// Tamandua server base URL, for example https://tamandua.treantlab.org
    #[arg(long, env = "TAMANDUA_SERVER")]
    pub server: Option<String>,

    /// Operator dashboard socket JWT. If omitted, saved remote login is used.
    #[arg(long, env = "TAMANDUA_TOKEN")]
    pub token: Option<String>,

    /// Target agent UUID
    #[arg(long, env = "TAMANDUA_AGENT_ID")]
    pub agent_id: String,

    /// Local file to upload
    pub local_path: PathBuf,

    /// Destination path on the agent
    pub remote_path: String,

    /// Command timeout in seconds
    #[arg(long, default_value = "120")]
    pub timeout: u64,

    /// End the live response session after upload
    #[arg(long, default_value_t = true)]
    pub close_session: bool,
}

// ==================== Shared Types ====================

#[derive(ValueEnum, Clone, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}
