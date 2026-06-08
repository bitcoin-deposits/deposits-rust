//! Peer discovery — fetch Kind 39100 ledger advertisements off the
//! configured relays, group by operator pubkey, rank by activity, and
//! surface them as a "popular peers" directory the wizard uses to
//! seed an operator's initial cosigner picks.
//!
//! No protocol changes: the same Kind 39100 events the existing
//! `ledger discover` wallet flow reads. We just shape the result
//! differently (per-operator summary, not per-ledger) and cache for
//! a 5-minute window so revisiting the wizard tab doesn't refire a
//! fan-out fetch.

use deposits_hub_proto::transport::HubTransport;
use nostr_sdk::prelude::*;
use nostr_sdk::{Alphabet, SingleLetterTag};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Kind 39100 — operator's per-ledger advertisement. Same constant the
/// wallet uses; inlined here so this crate doesn't have to depend on
/// `deposits-nostr` for one number.
const KIND_LEDGER_ADVERTISE: u16 = 39100;

/// Single-letter `n` tag — the network the ad applies to ("bitcoin",
/// "regtest", "signet"). Used as the filter so we don't get other
/// networks' chatter.
const NETWORK_TAG: Alphabet = Alphabet::N;

/// How long a discovery result stays "fresh" before the next call
/// triggers a re-fetch. 5 min is the sweet spot: shorter than a
/// typical wizard session (so reopening the peers page sees latest
/// activity), longer than the relay cost of a single fan-out.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// One operator's discovery summary. Aggregates every Kind 39100 ad
/// they've published on the chosen network into a single row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeerInfo {
    /// Operator's secp256k1 pubkey (hex). Stable across ad re-publishes.
    pub operator_pubkey: String,
    /// Free-text operator name from the most recent ad, if set.
    pub operator_name: Option<String>,
    /// Number of distinct ledger_ids this operator advertised at least
    /// once. Loose proxy for "how big / active this operator is."
    pub ledger_count: usize,
    /// Sorted list of ledger_ids for the multiselect target.
    pub ledger_ids: Vec<String>,
    /// Unix timestamp of the most recent ad seen across all this
    /// operator's ledgers. Used as the secondary rank.
    pub latest_ad_unix: u64,
    /// Annual custody fee in basis points, from the most-recent ad.
    /// `None` when no ad parsed cleanly (defensive — shouldn't happen).
    pub annual_fee_bps: Option<u32>,
}

/// Sliver of an ad we actually care about — keeps us from pulling in
/// the full `LedgerAdvertisement` struct (which lives in
/// `deposits-nostr` and carries 20+ fields). Manually deserialized
/// from each event's JSON content; missing fields default.
#[derive(Debug, serde::Deserialize)]
struct AdSliver {
    ledger_id: String,
    operator_pubkey: String,
    #[serde(default)]
    operator_name: Option<String>,
    #[serde(default)]
    annual_fee_bps: u32,
}

/// Fetch every Kind 39100 ad on the given network, group by operator
/// pubkey, rank by (ledger_count desc, latest_ad_unix desc).
///
/// Reuses the hub's existing relay client (no second connection).
/// Times out after 10 seconds — partial results are returned rather
/// than failing, since stale-but-present beats no-list-at-all in a
/// wizard context.
pub async fn discover_peers(
    transport: &HubTransport,
    network: &str,
) -> Result<Vec<PeerInfo>, String> {
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
        .custom_tag(SingleLetterTag::lowercase(NETWORK_TAG), [network]);

    let events = transport
        .client()
        .fetch_events(vec![filter], Some(Duration::from_secs(10)))
        .await
        .map_err(|e| format!("fetch peer ads: {}", e))?;

    let mut by_op: BTreeMap<String, AggregatedOp> = BTreeMap::new();
    for evt in events.iter() {
        let Ok(ad) = serde_json::from_str::<AdSliver>(&evt.content) else {
            continue;
        };
        let ts = evt.created_at.as_u64();
        let entry = by_op
            .entry(ad.operator_pubkey.clone())
            .or_insert_with(|| AggregatedOp {
                operator_pubkey: ad.operator_pubkey.clone(),
                operator_name: ad.operator_name.clone(),
                ledger_ids: Default::default(),
                latest_ad_unix: 0,
                annual_fee_bps: 0,
            });
        entry.ledger_ids.insert(ad.ledger_id.clone());
        if ts > entry.latest_ad_unix {
            entry.latest_ad_unix = ts;
            // Most-recent ad wins for the name + fees fields — operators
            // sometimes rename/repirice between publishes.
            if ad.operator_name.is_some() {
                entry.operator_name = ad.operator_name.clone();
            }
            entry.annual_fee_bps = ad.annual_fee_bps;
        }
    }

    let mut out: Vec<PeerInfo> = by_op
        .into_values()
        .map(|a| PeerInfo {
            operator_pubkey: a.operator_pubkey,
            operator_name: a.operator_name,
            ledger_count: a.ledger_ids.len(),
            ledger_ids: a.ledger_ids.into_iter().collect(),
            latest_ad_unix: a.latest_ad_unix,
            annual_fee_bps: Some(a.annual_fee_bps),
        })
        .collect();

    // Primary: most ledgers (rough activity proxy). Tiebreak: most
    // recent ad (freshest signal first).
    out.sort_by(|a, b| {
        b.ledger_count
            .cmp(&a.ledger_count)
            .then(b.latest_ad_unix.cmp(&a.latest_ad_unix))
    });
    Ok(out)
}

/// 5-minute TTL cache over [`discover_peers`]. Keyed by `network`.
/// One entry — the wizard only ever queries one network at a time.
pub struct PeerCache {
    network: String,
    fetched_at: Instant,
    peers: Vec<PeerInfo>,
}

impl PeerCache {
    /// Return the cached list if fresh, else `None` (caller should
    /// re-fetch). Network mismatch counts as stale.
    pub fn get(&self, network: &str) -> Option<&[PeerInfo]> {
        if self.network != network {
            return None;
        }
        if self.fetched_at.elapsed() > DISCOVERY_TTL {
            return None;
        }
        Some(&self.peers)
    }

    /// Fresh cache from a just-completed discovery.
    pub fn new(network: String, peers: Vec<PeerInfo>) -> Self {
        Self {
            network,
            fetched_at: Instant::now(),
            peers,
        }
    }
}

struct AggregatedOp {
    operator_pubkey: String,
    operator_name: Option<String>,
    ledger_ids: std::collections::BTreeSet<String>,
    latest_ad_unix: u64,
    annual_fee_bps: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer(pk: &str, ledgers: usize, latest: u64) -> PeerInfo {
        PeerInfo {
            operator_pubkey: pk.into(),
            operator_name: Some(format!("op-{}", &pk[..pk.len().min(4)])),
            ledger_count: ledgers,
            ledger_ids: (0..ledgers).map(|i| format!("lid-{}-{}", pk, i)).collect(),
            latest_ad_unix: latest,
            annual_fee_bps: Some(50),
        }
    }

    #[test]
    fn cache_returns_fresh_within_ttl() {
        let cache = PeerCache::new(
            "regtest".into(),
            vec![sample_peer("aa", 3, 1_700_000_000)],
        );
        let got = cache.get("regtest").expect("cached");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].operator_pubkey, "aa");
    }

    #[test]
    fn cache_misses_on_network_mismatch() {
        let cache = PeerCache::new(
            "regtest".into(),
            vec![sample_peer("aa", 1, 0)],
        );
        assert!(cache.get("bitcoin").is_none());
    }
}
