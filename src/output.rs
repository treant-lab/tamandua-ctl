//! Output formatting utilities
//!
//! Handles JSON and table output formatting for CLI commands.

use anyhow::Result;
use serde::Serialize;

/// Output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

/// Output handler
pub struct Output {
    format: OutputFormat,
    quiet: bool,
}

impl Output {
    /// Create a new output handler
    pub fn new(format: OutputFormat, quiet: bool) -> Self {
        Self { format, quiet }
    }

    /// Check if JSON output is enabled
    pub fn is_json(&self) -> bool {
        self.format == OutputFormat::Json
    }

    /// Check if quiet mode is enabled
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Print a line (respects quiet mode for table output)
    pub fn println(&self, msg: &str) {
        if self.quiet && self.format == OutputFormat::Table {
            return;
        }
        println!("{}", msg);
    }

    /// Print JSON output
    pub fn print_json<T: Serialize>(&self, value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        println!("{}", json);
        Ok(())
    }

    /// Print a line that's always shown (even in quiet mode)
    pub fn println_always(&self, msg: &str) {
        println!("{}", msg);
    }

    /// Print to stderr (for errors)
    pub fn eprintln(&self, msg: &str) {
        eprintln!("{}", msg);
    }
}

impl Default for Output {
    fn default() -> Self {
        Self::new(OutputFormat::Table, false)
    }
}
