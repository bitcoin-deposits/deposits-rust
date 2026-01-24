// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Logging macros for Bitcoin Deposits Protocol
//!
//! These macros provide an LDK-compatible logging interface backed by the `tracing` crate.
//! This allows code to be moved from deposits-ldk to deposits-core while maintaining
//! familiar logging patterns.
//!
//! ## Usage
//!
//! ```ignore
//! use deposits_core::{log_info, log_debug, log_error};
//!
//! // The logger parameter is accepted for API compatibility but ignored
//! // (tracing uses global subscribers instead)
//! log_info!(logger, "Processing message from {}", peer_id);
//! log_debug!(logger, "State updated: seq={}, hash={:?}", seq, hash);
//! log_error!(logger, "Failed to process: {}", error);
//! ```
//!
//! ## Migration from LDK macros
//!
//! To migrate code from deposits-ldk to deposits-core:
//! 1. Replace `use lightning::{log_info, log_debug, ...}` with `use deposits_core::{log_info, log_debug, ...}`
//! 2. The call sites remain unchanged: `log_info!(self.logger, "message")`
//!
//! ## Structured logging
//!
//! For new code, prefer using tracing's structured fields directly:
//! ```ignore
//! tracing::info!(peer = %peer_id, seq = sequence, "Processing message");
//! ```

/// Log at the `ERROR` level.
///
/// The logger parameter is accepted for LDK API compatibility but ignored.
#[macro_export]
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {
        tracing::error!($($arg)*)
    };
}

/// Log at the `WARN` level.
///
/// The logger parameter is accepted for LDK API compatibility but ignored.
#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {
        tracing::warn!($($arg)*)
    };
}

/// Log at the `INFO` level.
///
/// The logger parameter is accepted for LDK API compatibility but ignored.
#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        tracing::info!($($arg)*)
    };
}

/// Log at the `DEBUG` level.
///
/// The logger parameter is accepted for LDK API compatibility but ignored.
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {
        tracing::debug!($($arg)*)
    };
}

/// Log at the `TRACE` level.
///
/// The logger parameter is accepted for LDK API compatibility but ignored.
#[macro_export]
macro_rules! log_trace {
    ($logger:expr, $($arg:tt)*) => {
        tracing::trace!($($arg)*)
    };
}

#[cfg(test)]
mod tests {
    // Note: These tests verify the macros compile correctly.
    // Actual log output depends on the tracing subscriber configuration.

    struct DummyLogger;

    #[test]
    fn test_log_macros_compile() {
        let _logger = DummyLogger;

        log_error!(_logger, "error message: {}", 42);
        log_warn!(_logger, "warning message");
        log_info!(_logger, "info message with value: {}", "test");
        log_debug!(_logger, "debug message");
        log_trace!(_logger, "trace message");
    }

    #[test]
    fn test_log_macros_with_complex_expressions() {
        let _logger = &DummyLogger;
        let value = 123;
        let name = "test";

        log_info!(_logger, "Complex: {} = {}", name, value);
        log_debug!(_logger, "Formatted: {:?}", Some(value));
    }
}
