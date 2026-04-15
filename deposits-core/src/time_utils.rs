//! Time utilities for Bitcoin Deposits protocol
//!
//! Provides consistent time handling across the protocol implementation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds
pub fn now_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Convert SystemTime to Unix timestamp in seconds
pub fn systemtime_to_unix_timestamp(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Convert Unix timestamp to SystemTime
pub fn unix_timestamp_to_systemtime(timestamp: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(timestamp)
}

/// Check if a Unix timestamp has expired compared to current time
pub fn is_expired(timestamp: u64) -> bool {
    now_unix_timestamp() > timestamp
}

/// Check if a SystemTime has expired compared to current time
pub fn is_systemtime_expired(time: SystemTime) -> bool {
    SystemTime::now() > time
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_now_unix_timestamp() {
        let timestamp = now_unix_timestamp();
        assert!(timestamp > 0);

        // Should be roughly current time (within a few seconds)
        let system_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((timestamp as i64 - system_now as i64).abs() < 5);
    }

    #[test]
    fn test_systemtime_conversion() {
        let now = SystemTime::now();
        let timestamp = systemtime_to_unix_timestamp(now);
        let converted_back = unix_timestamp_to_systemtime(timestamp);

        // Should be within 1 second due to precision loss
        let diff = now
            .duration_since(converted_back)
            .unwrap_or_else(|_| converted_back.duration_since(now).unwrap());
        assert!(diff < Duration::from_secs(1));
    }

    #[test]
    fn test_expiration_checks() {
        let past_timestamp = now_unix_timestamp() - 100;
        let future_timestamp = now_unix_timestamp() + 100;

        assert!(is_expired(past_timestamp));
        assert!(!is_expired(future_timestamp));

        let past_time = SystemTime::now() - Duration::from_secs(100);
        let future_time = SystemTime::now() + Duration::from_secs(100);

        assert!(is_systemtime_expired(past_time));
        assert!(!is_systemtime_expired(future_time));
    }
}
