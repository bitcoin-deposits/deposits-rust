//! Prometheus-compatible metrics for deposits-node
//!
//! Provides metrics for monitoring node health, Nostr messaging, and protocol operations.
//!
//! # Usage
//!
//! Initialize metrics at startup:
//! ```ignore
//! use deposits_node::metrics;
//! metrics::init_metrics(9090)?;
//! ```
//!
//! Then use the metric recording functions throughout the code:
//! ```ignore
//! metrics::record_connection();
//! metrics::record_request_sent("deposit_open");
//! metrics::record_response_received(true);
//! ```

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
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

    builder.with_http_listener(addr).install()?;

    // Describe all metrics
    describe_metrics();

    tracing::info!(
        "Prometheus metrics available at http://0.0.0.0:{}/metrics",
        port
    );

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

    describe_counter!(
        "nostr_responses_by_ledger_total",
        "Total Nostr responses sent, labeled by action, ledger_id, and status"
    );
    describe_counter!(
        "deposits_transfers_completed_total",
        "Total transfers completed, labeled by ledger_id"
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
    describe_gauge!("pending_deposit_offers", "Number of pending deposit offers");

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
    describe_gauge!("ledger_count", "Number of ledgers managed by this node");
    describe_counter!(
        "ledger_operations_total",
        "Total ledger operations performed, labeled by type"
    );
    describe_gauge!(
        "ledger_history_length",
        "Number of history entries (sequence number) per ledger"
    );
    describe_gauge!(
        "history_memory_estimate_bytes",
        "Estimated total bytes used by in-memory ledger history"
    );

    // Event store metrics
    describe_gauge!(
        "event_store_events_total",
        "Total events in the content-addressed event store"
    );
    describe_gauge!(
        "event_store_unknown_events",
        "Events with Unknown validity (parent missing or unvalidated)"
    );
    describe_counter!(
        "event_store_inserts_total",
        "Total events inserted into event store, labeled by validity outcome"
    );
    describe_counter!(
        "event_store_gap_fills_total",
        "Total gap-fill attempts, labeled by outcome (success/partial/failed)"
    );
    describe_histogram!(
        "event_store_gap_fill_duration_seconds",
        "Time to complete a gap-fill fetch from relay"
    );
    describe_counter!(
        "ledger_update_received_total",
        "Total ledger updates received via Nostr, labeled by result (valid/unknown/duplicate)"
    );
    describe_counter!(
        "cosign_freshness_recovery_total",
        "Cosign freshness recovery attempts, labeled by outcome (recovered/stale/gap_filled)"
    );
    describe_gauge!(
        "event_store_validated_tip",
        "Highest validated sequence number per ledger in event store"
    );
    describe_gauge!(
        "stale_joined_ledgers",
        "Number of joined ledgers with detected gaps awaiting background fill"
    );
    describe_gauge!(
        "event_store_evictions_total",
        "Cumulative number of events evicted from the event store"
    );
    describe_counter!(
        "ledger_compaction_total",
        "Number of JSONL file compactions (full rewrites)"
    );

    // Request freshness metrics
    describe_histogram!(
        "request_age_seconds",
        "Age of incoming requests (now - created_at) labeled by action"
    );
    describe_counter!(
        "cosign_stale_discarded_total",
        "Cosign requests discarded because created_at was too old"
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

    // Run loop & cosign pipeline diagnostics
    describe_histogram!(
        "run_loop_iteration_seconds",
        "Duration of a full run loop iteration"
    );
    describe_histogram!(
        "request_drain_batch_size",
        "Number of requests drained in a single batch"
    );
    describe_histogram!(
        "sign_and_broadcast_seconds",
        "Duration of sign_and_broadcast labeled by outcome (success/timeout/error)"
    );
    describe_histogram!(
        "cosign_attempt_seconds",
        "Duration of a single cosign attempt labeled by outcome (success/timeout/error)"
    );
    describe_counter!(
        "mini_loop_updates_drained_total",
        "Total ledger updates drained inside the cosign mini loop"
    );
    describe_counter!(
        "mini_loop_cosign_requests_handled_total",
        "Total cross-cosign requests handled inside the cosign mini loop"
    );
    describe_counter!(
        "mini_loop_deferred_requests_total",
        "Total non-cosign requests deferred (re-queued) from the cosign mini loop"
    );
    describe_counter!(
        "broadcast_channel_lag_total",
        "Total broadcast channel lag events by receiver"
    );
    describe_counter!(
        "broadcast_channel_lag_events_total",
        "Total events dropped due to broadcast channel lag"
    );
    describe_histogram!(
        "pre_cosign_drain_count",
        "Number of updates drained in pre-cosign drain"
    );
    describe_counter!(
        "pre_cosign_drain_caught_up_total",
        "Pre-cosign drains that successfully caught up"
    );
    describe_counter!(
        "pre_cosign_drain_still_stale_total",
        "Pre-cosign drains that did not catch up"
    );

    // Run loop phase breakdown
    describe_histogram!(
        "run_loop_phase_seconds",
        "Duration of individual run loop phases, labeled by phase"
    );
    describe_histogram!(
        "notification_drain_count",
        "Number of nostr notifications parsed per process_events call"
    );
    describe_counter!(
        "notification_dedup_skipped_total",
        "Notifications skipped by early event-ID dedup (avoided full parse)"
    );

    // Per-thread CPU profiling
    describe_gauge!(
        "thread_cpu_seconds",
        "CPU seconds per thread, labeled by thread name and mode (user/system)"
    );

    // Nostr publish latency
    describe_histogram!(
        "nostr_publish_seconds",
        "Time to publish an event to the relay"
    );

    // Diagnostic gauges
    describe_gauge!(
        "processed_requests_current",
        "Size of current-generation processed requests dedup set"
    );
    describe_gauge!(
        "processed_requests_prev",
        "Size of previous-generation processed requests dedup set"
    );
    describe_gauge!(
        "event_store_by_parent_size",
        "Number of entries in event store reverse (by_parent) index"
    );
    describe_histogram!(
        "insert_event_seconds",
        "Time to insert an event into the event store (includes clone + hash verify)"
    );
    describe_histogram!("persist_ledger_seconds", "Time to persist a ledger to disk");

    // Process metrics (Linux /proc)
    describe_gauge!(
        "process_cpu_seconds_total",
        "Total user+system CPU seconds consumed by this process"
    );
    describe_gauge!(
        "process_cpu_user_seconds",
        "User CPU seconds consumed by this process"
    );
    describe_gauge!(
        "process_cpu_system_seconds",
        "System CPU seconds consumed by this process"
    );
    describe_gauge!(
        "process_resident_memory_bytes",
        "Resident set size (RSS) in bytes"
    );
    describe_gauge!("process_threads", "Number of threads in this process");
    describe_gauge!(
        "process_io_write_bytes_total",
        "Total bytes written to disk (from /proc/self/io)"
    );
    describe_gauge!(
        "process_io_read_bytes_total",
        "Total bytes read from disk (from /proc/self/io)"
    );
    describe_gauge!(
        "process_io_write_syscalls_total",
        "Total write syscalls (from /proc/self/io)"
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
    counter!("nostr_responses_sent_total", "action" => action.to_string(), "status" => status)
        .increment(1);
}

/// Record a response sent via Nostr, tagged by ledger.
pub fn record_response_sent_for_ledger(action: &str, ledger_id: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    counter!("nostr_responses_by_ledger_total",
        "action" => action.to_string(),
        "ledger_id" => short_id.to_string(),
        "status" => status)
    .increment(1);
}

/// Record a response received via Nostr.
pub fn record_response_received(action: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    counter!("nostr_responses_received_total", "action" => action.to_string(), "status" => status)
        .increment(1);
}

// ============================================================================
// Ledger operation metrics
// ============================================================================

/// Record a transfer_complete operation successfully appended to a ledger.
/// This is the definitive "transfer throughput" metric — one increment per
/// completed transfer on this operator's ledger.
pub fn record_transfer_completed(ledger_id: &str) {
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    counter!("deposits_transfers_completed_total", "ledger_id" => short_id.to_string())
        .increment(1);
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
pub fn record_request_processing(action: &str, ledger_id: &str, success: bool, duration: Duration) {
    let status = if success { "success" } else { "error" };
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    histogram!("nostr_request_processing_seconds",
        "action" => action.to_string(),
        "ledger_id" => short_id.to_string(),
        "status" => status)
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
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    gauge!("ledger_history_length", "ledger_id" => short_id.to_string()).set(length as f64);
}

/// Set estimated total in-memory history bytes across all ledgers.
pub fn set_history_memory_estimate_bytes(bytes: u64) {
    gauge!("history_memory_estimate_bytes").set(bytes as f64);
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
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    gauge!("deposit_ledger_balance_sats", "ledger_id" => short_id.to_string()).set(amount as f64);
}

/// Set the balance for a specific deposit in satoshis.
pub fn set_deposit_balance_sats(deposit_id: &str, amount: u64) {
    // Use first 16 chars of deposit_id as label to keep cardinality reasonable
    let short_id = if deposit_id.len() > 8 {
        &deposit_id[..8]
    } else {
        deposit_id
    };
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
// Event store metrics
// ============================================================================

/// Set the total number of events in the event store.
pub fn set_event_store_total(count: usize) {
    gauge!("event_store_events_total").set(count as f64);
}

/// Set the number of Unknown-validity events in the event store.
pub fn set_event_store_unknown(count: usize) {
    gauge!("event_store_unknown_events").set(count as f64);
}

/// Record an event store insert with its validity outcome.
pub fn record_event_store_insert(validity: &str) {
    counter!("event_store_inserts_total", "validity" => validity.to_string()).increment(1);
}

/// Record a gap-fill attempt with its outcome.
pub fn record_gap_fill(outcome: &str) {
    counter!("event_store_gap_fills_total", "outcome" => outcome.to_string()).increment(1);
}

/// Record gap-fill fetch duration.
pub fn record_gap_fill_duration(duration: Duration) {
    histogram!("event_store_gap_fill_duration_seconds").record(duration.as_secs_f64());
}

/// Record a ledger update received via Nostr.
pub fn record_ledger_update_received(result: &str) {
    counter!("ledger_update_received_total", "result" => result.to_string()).increment(1);
}

/// Record a cosign freshness recovery attempt.
pub fn record_cosign_freshness_recovery(outcome: &str) {
    counter!("cosign_freshness_recovery_total", "outcome" => outcome.to_string()).increment(1);
}

/// Set the validated tip (highest validated seq) for a ledger in the event store.
pub fn set_event_store_validated_tip(ledger_id: &str, tip: u64) {
    let short_id = if ledger_id.len() > 8 {
        &ledger_id[..8]
    } else {
        ledger_id
    };
    gauge!("event_store_validated_tip", "ledger_id" => short_id.to_string()).set(tip as f64);
}

/// Set the number of stale joined ledgers awaiting gap-fill.
pub fn set_stale_joined_ledgers(count: usize) {
    gauge!("stale_joined_ledgers").set(count as f64);
}

/// Set the cumulative number of events evicted from the event store.
pub fn set_event_store_evictions(count: u64) {
    gauge!("event_store_evictions_total").set(count as f64);
}

/// Record the age of an incoming request (now - created_at).
pub fn record_request_age(action: &str, age_secs: f64) {
    histogram!("request_age_seconds", "action" => action.to_string()).record(age_secs);
}

/// Record a cosign request discarded due to staleness.
pub fn record_cosign_stale_discarded() {
    counter!("cosign_stale_discarded_total").increment(1);
}

// ============================================================================
// Run loop & cosign pipeline diagnostics
// ============================================================================

/// Record the duration of a full run loop iteration.
pub fn record_run_loop_iteration(duration: Duration) {
    histogram!("run_loop_iteration_seconds").record(duration.as_secs_f64());
}

/// Record process_events timeout used (1ms=busy, 100ms=idle).
pub fn record_events_timeout_ms(ms: u64) {
    gauge!("events_timeout_ms").set(ms as f64);
}

/// Record the number of requests drained in a single batch.
pub fn record_request_drain_batch_size(count: usize) {
    histogram!("request_drain_batch_size").record(count as f64);
}

/// Record sign_and_broadcast duration labeled by outcome.
pub fn record_sign_and_broadcast(outcome: &str, duration: Duration) {
    histogram!("sign_and_broadcast_seconds", "outcome" => outcome.to_string())
        .record(duration.as_secs_f64());
}

/// Record a single cosign attempt duration labeled by outcome.
pub fn record_cosign_attempt(outcome: &str, duration: Duration) {
    histogram!("cosign_attempt_seconds", "outcome" => outcome.to_string())
        .record(duration.as_secs_f64());
}

/// Record per-member co-sign round-trip time.
pub fn record_cosign_rtt(member: &str, duration: Duration) {
    histogram!("cosign_rtt_seconds", "member" => member.to_string()).record(duration.as_secs_f64());
}

/// Record events processed inside the cosign mini loop per attempt.
pub fn record_mini_loop_activity(
    updates_drained: usize,
    cosign_requests_handled: usize,
    deferred_requests: usize,
) {
    counter!("mini_loop_updates_drained_total").increment(updates_drained as u64);
    counter!("mini_loop_cosign_requests_handled_total").increment(cosign_requests_handled as u64);
    counter!("mini_loop_deferred_requests_total").increment(deferred_requests as u64);
}

/// Record a broadcast channel lag event.
pub fn record_broadcast_lag(receiver: &str, dropped: u64) {
    counter!("broadcast_channel_lag_total", "receiver" => receiver.to_string()).increment(1);
    counter!("broadcast_channel_lag_events_total", "receiver" => receiver.to_string())
        .increment(dropped);
}

/// Record pre-cosign drain results.
pub fn record_pre_cosign_drain(updates_drained: usize, caught_up: bool) {
    histogram!("pre_cosign_drain_count").record(updates_drained as f64);
    if caught_up {
        counter!("pre_cosign_drain_caught_up_total").increment(1);
    } else if updates_drained > 0 {
        counter!("pre_cosign_drain_still_stale_total").increment(1);
    }
}

// ============================================================================
// Run loop phase breakdown
// ============================================================================

/// Record the duration of a run loop phase.
pub fn record_run_loop_phase(phase: &str, duration: Duration) {
    histogram!("run_loop_phase_seconds", "phase" => phase.to_string())
        .record(duration.as_secs_f64());
}

/// Record number of notifications drained per process_events call.
pub fn record_notification_drain_count(count: u32) {
    histogram!("notification_drain_count").record(count as f64);
}

/// Record notifications skipped by early event-ID dedup.
pub fn record_notification_dedup_skipped(count: u32) {
    counter!("notification_dedup_skipped_total").increment(count as u64);
}

/// Record Nostr event publish latency.
pub fn record_nostr_publish(duration: Duration) {
    histogram!("nostr_publish_seconds").record(duration.as_secs_f64());
}

// ============================================================================
// Per-thread CPU profiling (Linux /proc/self/task)
// ============================================================================

/// Emit per-thread CPU metrics from /proc/self/task/*/stat.
/// Each thread gets a gauge labeled by its comm name and TID.
/// Call periodically (e.g., every 5s) alongside emit_process_metrics().
/// No-op on non-Linux platforms.
pub fn emit_thread_cpu_metrics() {
    #[cfg(target_os = "linux")]
    {
        let task_dir = match std::fs::read_dir("/proc/self/task") {
            Ok(d) => d,
            Err(_) => return,
        };
        let clk_tck = 100.0_f64;
        for entry in task_dir.flatten() {
            let tid = entry.file_name();
            let tid_str = tid.to_string_lossy();

            // Read thread name from comm
            let comm_path = format!("/proc/self/task/{}/comm", tid_str);
            let thread_name = std::fs::read_to_string(&comm_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| tid_str.to_string());

            // Read stat for CPU times
            let stat_path = format!("/proc/self/task/{}/stat", tid_str);
            let stat = match std::fs::read_to_string(&stat_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Parse: skip past comm field (in parens), then fields after
            if let Some(comm_end) = stat.find(')') {
                let after_comm = &stat[comm_end + 2..];
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // utime=field[11], stime=field[12] (0-indexed after comm)
                if fields.len() > 12 {
                    if let Ok(utime) = fields[11].parse::<u64>() {
                        gauge!("thread_cpu_seconds",
                            "thread" => thread_name.clone(),
                            "tid" => tid_str.to_string(),
                            "mode" => "user"
                        )
                        .set(utime as f64 / clk_tck);
                    }
                    if let Ok(stime) = fields[12].parse::<u64>() {
                        gauge!("thread_cpu_seconds",
                            "thread" => thread_name.clone(),
                            "tid" => tid_str.to_string(),
                            "mode" => "system"
                        )
                        .set(stime as f64 / clk_tck);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Diagnostic gauges & histograms
// ============================================================================

/// Set the current-generation processed requests set size.
pub fn set_processed_requests_current(count: usize) {
    gauge!("processed_requests_current").set(count as f64);
}

/// Set the previous-generation processed requests set size.
pub fn set_processed_requests_prev(count: usize) {
    gauge!("processed_requests_prev").set(count as f64);
}

/// Set the event store by_parent reverse index size.
pub fn set_event_store_by_parent_size(count: usize) {
    gauge!("event_store_by_parent_size").set(count as f64);
}

/// Record event store insert duration.
pub fn record_insert_event_duration(duration: Duration) {
    histogram!("insert_event_seconds").record(duration.as_secs_f64());
}

/// Record ledger persist-to-disk duration.
pub fn record_persist_ledger_duration(duration: Duration) {
    histogram!("persist_ledger_seconds").record(duration.as_secs_f64());
}

/// Record a JSONL file compaction (full rewrite).
pub fn record_ledger_compaction() {
    counter!("ledger_compaction_total").increment(1);
}

// ============================================================================
// Process metrics (Linux /proc/self)
// ============================================================================

/// Emit process-level metrics from /proc/self.
/// Call this periodically (e.g., every 5s) from the run loop.
/// No-op on non-Linux platforms (macOS dev builds).
pub fn emit_process_metrics() {
    #[cfg(target_os = "linux")]
    {
        // CPU time from /proc/self/stat
        // Fields: pid comm state ppid ... utime(14) stime(15) ... num_threads(20) ...
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            let _fields: Vec<&str> = stat.split_whitespace().collect();
            // Find end of comm field (enclosed in parens) to handle spaces in process name
            if let Some(comm_end) = stat.find(')') {
                let after_comm = &stat[comm_end + 2..]; // skip ") "
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // After comm: state(0) ppid(1) ... utime(11) stime(12) ... num_threads(17)
                if fields.len() > 17 {
                    let clk_tck = 100.0_f64; // sysconf(_SC_CLK_TCK), 100 on Linux
                    if let Ok(utime) = fields[11].parse::<u64>() {
                        let user_secs = utime as f64 / clk_tck;
                        gauge!("process_cpu_user_seconds").set(user_secs);
                    }
                    if let Ok(stime) = fields[12].parse::<u64>() {
                        let sys_secs = stime as f64 / clk_tck;
                        gauge!("process_cpu_system_seconds").set(sys_secs);
                    }
                    if let (Ok(utime), Ok(stime)) =
                        (fields[11].parse::<u64>(), fields[12].parse::<u64>())
                    {
                        let total_secs = (utime + stime) as f64 / clk_tck;
                        gauge!("process_cpu_seconds_total").set(total_secs);
                    }
                    if let Ok(threads) = fields[17].parse::<u64>() {
                        gauge!("process_threads").set(threads as f64);
                    }
                }
            }
        }

        // RSS from /proc/self/status
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("VmRSS:") {
                    // Value is in kB
                    if let Ok(kb) = val.trim().trim_end_matches(" kB").trim().parse::<u64>() {
                        gauge!("process_resident_memory_bytes").set((kb * 1024) as f64);
                    }
                }
            }
        }

        // I/O from /proc/self/io
        if let Ok(io) = std::fs::read_to_string("/proc/self/io") {
            for line in io.lines() {
                if let Some(val) = line.strip_prefix("write_bytes: ") {
                    if let Ok(bytes) = val.trim().parse::<u64>() {
                        gauge!("process_io_write_bytes_total").set(bytes as f64);
                    }
                }
                if let Some(val) = line.strip_prefix("read_bytes: ") {
                    if let Ok(bytes) = val.trim().parse::<u64>() {
                        gauge!("process_io_read_bytes_total").set(bytes as f64);
                    }
                }
                if let Some(val) = line.strip_prefix("syscw: ") {
                    if let Ok(count) = val.trim().parse::<u64>() {
                        gauge!("process_io_write_syscalls_total").set(count as f64);
                    }
                }
            }
        }
    }
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
