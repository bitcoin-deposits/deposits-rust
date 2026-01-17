// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Logger adapter for deposits-core
//!
//! This module provides an adapter that implements deposits-core's Logger trait
//! using LDK's Logger trait, enabling deposits-core to log through LDK's logging
//! infrastructure.

use std::ops::Deref;

use deposits_core::traits::{Logger as CoreLogger, LogLevel};
use lightning::util::logger::Logger as LdkLogger;

/// Adapter that implements deposits-core's Logger trait using LDK's Logger
pub struct LdkLoggerAdapter<L: Deref>
where
    L::Target: LdkLogger,
{
    logger: L,
}

impl<L: Deref> LdkLoggerAdapter<L>
where
    L::Target: LdkLogger,
{
    /// Create a new LDK logger adapter
    pub fn new(logger: L) -> Self {
        Self { logger }
    }
}

/// Macro to log through LDK's logger with proper lifetime handling
/// This is needed because format_args! creates temporaries that must be
/// consumed in the same expression
macro_rules! ldk_log {
    ($logger:expr, $level:expr, $($arg:tt)*) => {
        $logger.log(lightning::util::logger::Record::new(
            $level,
            None,
            None,
            format_args!($($arg)*),
            "deposits_ldk::logger",
            file!(),
            line!(),
            None,
        ))
    }
}

/// Log at info level - exported for use by other modules
#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        lightning::util::logger::Logger::log($logger.deref(), lightning::util::logger::Record::new(
            lightning::util::logger::Level::Info,
            None,
            None,
            format_args!($($arg)*),
            "deposits_ldk",
            file!(),
            line!(),
            None,
        ))
    }
}

impl<L: Deref + Send + Sync> CoreLogger for LdkLoggerAdapter<L>
where
    L::Target: LdkLogger,
{
    fn log(&self, level: LogLevel, message: &str) {
        use lightning::util::logger::Level;

        match level {
            LogLevel::Error => ldk_log!(self.logger, Level::Error, "[deposits] {}", message),
            LogLevel::Warn => ldk_log!(self.logger, Level::Warn, "[deposits] {}", message),
            LogLevel::Info => ldk_log!(self.logger, Level::Info, "[deposits] {}", message),
            LogLevel::Debug => ldk_log!(self.logger, Level::Debug, "[deposits] {}", message),
            LogLevel::Trace => ldk_log!(self.logger, Level::Trace, "[deposits] {}", message),
        }
    }
}

/// A simple stdout logger for testing
pub struct StdoutLogger;

impl CoreLogger for StdoutLogger {
    fn log(&self, level: LogLevel, message: &str) {
        let level_str = match level {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        };
        println!("[{}] {}", level_str, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdout_logger() {
        let logger = StdoutLogger;
        logger.log(LogLevel::Info, "Test message");
        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");
    }
}
