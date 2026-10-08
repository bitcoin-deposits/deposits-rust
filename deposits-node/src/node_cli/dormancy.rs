//! `deposits-node dormancy <offer|accept|notice|credit> LEDGER [--flags]` — DEP-20 §8 operator
//! actions, sent to the running daemon. Flags (as the daemon's params):
//!   offer                                   the manifest a notice now would migrate
//!   accept  --manifest HEX --total-msats N [--offer-event-id HEX] [--expiry-blocks N] [--premium-deposit HEX]
//!   notice  --rotation-height N [--receiver PUBKEY --manifest HEX --accept HEX [--premium-msats N]]
//!   credit  --manifest HEX --txid TXID --vout N [--premium-msats N]

use super::{parse_config, send_daemon_request};
use crate::Node;

const PARAMS: &[(&str, &str, bool)] = &[
    ("--manifest", "manifest", false),
    ("--total-msats", "total_msats", true),
    ("--offer-event-id", "offer_event_id", false),
    ("--expiry-blocks", "expiry_blocks", true),
    ("--premium-deposit", "premium_deposit", false),
    ("--rotation-height", "rotation_height", true),
    ("--receiver", "receiver", false),
    ("--accept", "accept", false),
    ("--premium-msats", "premium_msats", true),
    ("--txid", "txid", false),
    ("--vout", "vout", true),
];

pub async fn dormancy_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let action = args
        .first()
        .ok_or("dormancy <offer|accept|notice|credit> LEDGER ...")?;
    let ledger = args.get(1).ok_or("LEDGER required")?;
    let mut params = serde_json::Map::new();
    let mut config_args = Vec::new();
    let mut i = 2;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args.get(i + 1).cloned().unwrap_or_default();
        match PARAMS.iter().find(|(f, _, _)| *f == flag) {
            Some((_, key, numeric)) => {
                let v = if *numeric {
                    serde_json::json!(value
                        .parse::<u64>()
                        .map_err(|_| format!("{flag}: expected a number"))?)
                } else {
                    serde_json::json!(value)
                };
                params.insert(key.to_string(), v);
                i += 2;
            }
            None => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(value);
                    i += 1;
                }
                i += 1;
            }
        }
    }
    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;
    let ledger_id = super::resolve_to_ledger_id(&node, ledger)?;
    drop(node);
    let result = send_daemon_request(
        &config,
        &ledger_id,
        &format!("dormancy_{action}"),
        serde_json::Value::Object(params),
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
