//! Prometheus-compatible metrics for deposits-bdk
//!
//! Provides metrics for monitoring node health, Nostr messaging, and protocol operations.
//!
//! # Usage
//!
//! Initialize metrics at startup:
//! ```ignore
//! use deposits_bdk::metrics;
//! metrics::init_metrics(9090)?;
//! ```
//!
//! Then use the metric recording functions throughout the code:
//! ```ignore
//! metrics::record_connection();
//! metrics::record_request_sent("deposit_open");
//! metrics::record_response_received(true);
//! ```

use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::time::Duration;

/// Initialize the Prometheus metrics exporter.
///
/// Starts an HTTP server on the given port that serves metrics at `/metrics`.
/// Returns the socket address the server is listening on.
pub fn init_metrics(port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let builder = PrometheusBuilder::new();
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let handle = builder
        .with_http_listener(addr)
        .install()?;

    // Describe all metrics
    describe_metrics();

    tracing::info!("Prometheus metrics available at http://0.0.0.0:{}/metrics", port);

    Ok(addr)
}

/// Initialize metrics without HTTP server (for testing or embedded use).
/// Metrics can still be recorded but won't be exposed.
pub fn init_metrics_noop() {
    // Install a no-op recorder - metrics are recorded but not exported
    // This is useful for tests or when metrics aren't needed
    let _ = PrometheusBuilder::new().install();
    describe_metrics();
}

fn describe_metrics() {
    // Connection metrics
    describe_counter!(
        "nostr_connections_total",
        "Total number of Nostr relay connections made"
    );
    describe_counter!(
        "nostr_disconnections_total",
        "Total number of Nostr relay disconnections"
    );
    describe_gauge!(
        "nostr_connections_active",
        "Current number of active Nostr relay connections"
    );

    // Request metrics
    describe_counter!(
        "nostr_requests_sent_total",
        "Total Nostr requests sent, labeled by action type"
    );
    describe_counter!(
        "nostr_requests_received_total",
        "Total Nostr requests received, labeled by action type"
    );

    // Response metrics
    describe_counter!(
        "nostr_responses_sent_total",
        "Total Nostr responses sent, labeled by status (success/error)"
    );
    describe_counter!(
        "nostr_responses_received_total",
        "Total Nostr responses received, labeled by status (success/error)"
    );

    // Queue metrics
    describe_gauge!(
        "pending_cosign_requests",
        "Number of pending co-sign requests awaiting response"
    );
    describe_gauge!(
        "pending_collateral_requests",
        "Number of pending collateral lock requests"
    );
    describe_gauge!(
        "pending_deposit_offers",
        "Number of pending deposit offers"
    );

    // Latency metrics
    describe_histogram!(
        "nostr_request_duration_seconds",
        "Time from request sent to response received"
    );
    describe_histogram!(
        "nostr_request_processing_seconds",
        "Time to process an incoming Nostr request (node-side)"
    );
    describe_histogram!(
        "cosign_request_duration_seconds",
        "Time to complete a co-sign request"
    );
    describe_histogram!(
        "ledger_operation_duration_seconds",
        "Time to complete a ledger operation"
    );

    // Ledger metrics
    describe_gauge!(
        "ledger_count",
        "Number of ledgers managed by this node"
    );
    describe_counter!(
        "ledger_operations_total",
        "Total ledger operations performed, labeled by type"
    );
    describe_gauge!(
        "ledger_history_length",
        "Number of history entries (sequence number) per ledger"
    );

    // Deposit balance metrics
    describe_gauge!(
        "deposit_reserves_balance_sats",
        "Current reserves balance in satoshis"
    );
    describe_gauge!(
        "deposit_total_balance_sats",
        "Total deposits under management in satoshis"
    );
    describe_gauge!(
        "deposit_ledger_balance_sats",
        "Balance for a specific ledger in satoshis, labeled by ledger_id"
    );
    describe_gauge!(
        "deposit_balance_sats",
        "Balance for a specific deposit in satoshis, labeled by deposit_id"
    );
    describe_counter!(
        "deposit_accepted_total",
        "Total number of deposits accepted"
    );
    describe_counter!(
        "deposit_rejected_total",
        "Total number of deposits rejected"
    );
}

// ============================================================================
// Connection metrics
// ============================================================================

/// Record a new connection to a Nostr relay.
pub fn record_connection() {
    counter!("nostr_connections_total").increment(1);
    gauge!("nostr_connections_active").increment(1.0);
}

/// Record a disconnection from a Nostr relay.
pub fn record_disconnection() {
    counter!("nostr_disconnections_total").increment(1);
    gauge!("nostr_connections_active").decrement(1.0);
}

/// Set the number of active connections (for initialization or correction).
pub fn set_active_connections(count: usize) {
    gauge!("nostr_connections_active").set(count as f64);
}

// ============================================================================
// Request/Response metrics
// ============================================================================

/// Record a request sent via Nostr.
pub fn record_request_sent(action: &str) {
    counter!("nostr_requests_sent_total", "action" => action.to_string()).increment(1);
}

/// Record a request received via Nostr.
pub fn record_request_received(action: &str) {
    counter!("nostr_requests_received_total", "action" => action.to_string()).increment(1);
}

/// Record a response sent via Nostr.
pub fn record_response_sent(action: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    counter!("nostr_responses_sent_total", "action" => action.to_string(), "status" => status).increment(1);
}

/// Record a response received via Nostr.
pub fn record_response_received(action: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    counter!("nostr_responses_received_total", "action" => action.to_string(), "status" => status).increment(1);
}

// ============================================================================
// Queue metrics
// ============================================================================

/// Set the number of pending co-sign requests.
pub fn set_pending_cosign_requests(count: usize) {
    gauge!("pending_cosign_requests").set(count as f64);
}

/// Set the number of pending collateral lock requests.
pub fn set_pending_collateral_requests(count: usize) {
    gauge!("pending_collateral_requests").set(count as f64);
}

/// Set the number of pending deposit offers.
pub fn set_pending_deposit_offers(count: usize) {
    gauge!("pending_deposit_offers").set(count as f64);
}

// ============================================================================
// Latency metrics
// ============================================================================

/// Record request duration (time from send to response).
pub fn record_request_duration(action: &str, duration: Duration) {
    histogram!("nostr_request_duration_seconds", "action" => action.to_string())
        .record(duration.as_secs_f64());
}

/// Record request processing time (node-side time to handle a request).
pub fn record_request_processing(action: &str, success: bool, duration: Duration) {
    let status = if success { "success" } else { "error" };
    histogram!("nostr_request_processing_seconds", "action" => action.to_string(), "status" => status)
        .record(duration.as_secs_f64());
}

/// Record co-sign request duration.
pub fn record_cosign_duration(duration: Duration) {
    histogram!("cosign_request_duration_seconds").record(duration.as_secs_f64());
}

/// Record ledger operation duration.
pub fn record_ledger_operation_duration(op_type: &str, duration: Duration) {
    histogram!("ledger_operation_duration_seconds", "type" => op_type.to_string())
        .record(duration.as_secs_f64());
}

// ============================================================================
// Ledger metrics
// ============================================================================

/// Set the number of ledgers.
pub fn set_ledger_count(count: usize) {
    gauge!("ledger_count").set(count as f64);
}

/// Record a ledger operation.
pub fn record_ledger_operation(op_type: &str) {
    counter!("ledger_operations_total", "type" => op_type.to_string()).increment(1);
}

/// Set the history length (sequence number) for a ledger.
pub fn set_ledger_history_length(ledger_id: &str, length: usize) {
    // Use first 16 chars of ledger_id as label to keep cardinality reasonable
    let short_id = if ledger_id.len() > 16 { &ledger_id[..16] } else { ledger_id };
    gauge!("ledger_history_length", "ledger_id" => short_id.to_string()).set(length as f64);
}

// ============================================================================
// Deposit balance metrics
// ============================================================================

/// Set the total reserves balance across all ledgers in satoshis.
pub fn set_reserves_balance_sats(amount: u64) {
    gauge!("deposit_reserves_balance_sats").set(amount as f64);
}

/// Set the total deposits under management in satoshis.
pub fn set_total_deposit_balance_sats(amount: u64) {
    gauge!("deposit_total_balance_sats").set(amount as f64);
}

/// Set the balance for a specific ledger in satoshis.
pub fn set_ledger_deposit_balance_sats(ledger_id: &str, amount: u64) {
    // Use first 16 chars of ledger_id as label to keep cardinality reasonable
    let short_id = if ledger_id.len() > 16 { &ledger_id[..16] } else { ledger_id };
    gauge!("deposit_ledger_balance_sats", "ledger_id" => short_id.to_string()).set(amount as f64);
}

/// Set the balance for a specific deposit in satoshis.
pub fn set_deposit_balance_sats(deposit_id: &str, amount: u64) {
    // Use first 16 chars of deposit_id as label to keep cardinality reasonable
    let short_id = if deposit_id.len() > 16 { &deposit_id[..16] } else { deposit_id };
    gauge!("deposit_balance_sats", "deposit_id" => short_id.to_string()).set(amount as f64);
}

/// Record a deposit acceptance.
pub fn record_deposit_accepted() {
    counter!("deposit_accepted_total").increment(1);
}

/// Record a deposit rejection.
pub fn record_deposit_rejected() {
    counter!("deposit_rejected_total").increment(1);
}

// ============================================================================
// Periodic stats dump
// ============================================================================

/// Stats snapshot for periodic logging.
#[derive(Debug, Default)]
pub struct StatsSnapshot {
    pub connections_active: usize,
    pub pending_cosign: usize,
    pub pending_collateral: usize,
    pub pending_offers: usize,
    pub ledger_count: usize,
}

impl std::fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "connections={} pending_cosign={} pending_collateral={} pending_offers={} ledgers={}",
            self.connections_active,
            self.pending_cosign,
            self.pending_collateral,
            self.pending_offers,
            self.ledger_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_can_be_recorded() {
        // Just verify the metrics don't panic
        record_connection();
        record_disconnection();
        record_request_sent("test");
        record_request_received("test");
        record_response_sent("test", true);
        record_response_received("test", false);
        set_pending_cosign_requests(5);
        record_cosign_duration(Duration::from_millis(100));
    }
}
