//! Content-addressed event store for ledger sync.
//!
//! Events are the durable unit — stored by `content_hash`, validated via
//! memoized hash-chain verification, and gaps are normal/recoverable.
//! Ledger state is derived from validated chains.

use std::collections::{HashMap, VecDeque};

use bitcoin::secp256k1::PublicKey;

use crate::types::SignedLedgerUpdate;

/// Validation status of a stored event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    /// Hash chain verified back to a trusted root.
    Valid,
    /// Hash chain verification failed (broken chain).
    Invalid,
    /// Parent not yet available or not yet validated.
    Unknown,
}

/// An event stored in the event store with its validation status.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub update: SignedLedgerUpdate,
    pub validity: Validity,
}

/// Composite key for secondary index: (ledger_id, operator_id compressed bytes, sequence).
type SeqKey = ([u8; 32], [u8; 33], u64);

/// Composite key for tip tracking: (ledger_id, operator_id compressed bytes).
type TipKey = ([u8; 32], [u8; 33]);

/// Content-addressed event store.
///
/// Primary key is `content_hash`. Secondary index maps
/// `(ledger_id, operator_id, seq)` to `content_hash`.
/// Validation is memoized — O(1) steady state after initial chain walk.
pub struct EventStore {
    /// Primary index: content_hash → stored event.
    events: HashMap<[u8; 32], StoredEvent>,
    /// Secondary index: (ledger_id, operator_id_bytes, seq) → content_hash.
    by_seq: HashMap<SeqKey, [u8; 32]>,
    /// Reverse index: previous_hash → list of child content_hashes.
    /// Used by propagate_forward for O(1) child lookup instead of O(N) full scan.
    by_parent: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Tip: (ledger_id, operator_id_bytes) → highest validated sequence number.
    validated_tips: HashMap<TipKey, u64>,
    /// Running count of events with Unknown validity (avoids O(N) filter scan).
    unknown_count: usize,
    /// FIFO insertion order for eviction (front = oldest).
    insertion_order: VecDeque<[u8; 32]>,
    /// Maximum number of events before eviction (0 = unlimited).
    max_events: usize,
    /// Cumulative count of evicted events (for metrics).
    evicted_total: u64,
}

impl EventStore {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            by_seq: HashMap::new(),
            by_parent: HashMap::new(),
            validated_tips: HashMap::new(),
            unknown_count: 0,
            insertion_order: VecDeque::new(),
            max_events: 0,
            evicted_total: 0,
        }
    }

    /// Create an event store with a maximum capacity. Once full, the oldest
    /// events are evicted in FIFO order to stay at or below `max_events`.
    pub fn with_max_events(max_events: usize) -> Self {
        Self {
            events: HashMap::new(),
            by_seq: HashMap::new(),
            by_parent: HashMap::new(),
            validated_tips: HashMap::new(),
            unknown_count: 0,
            insertion_order: VecDeque::new(),
            max_events,
            evicted_total: 0,
        }
    }

    /// Number of events in the store.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Number of entries in the by_parent reverse index.
    pub fn by_parent_len(&self) -> usize {
        self.by_parent.len()
    }

    /// Insert an event. Returns `true` if the event is new (not a duplicate).
    ///
    /// On insert:
    /// 1. Store with `Validity::Unknown`
    /// 2. Check parent's validity to determine this event's validity
    /// 3. If marked `Valid`, propagate forward to any waiting children
    pub fn insert(&mut self, update: SignedLedgerUpdate) -> bool {
        let hash = update.content_hash;

        // Duplicate check — already stored
        if self.events.contains_key(&hash) {
            return false;
        }

        // Build index keys
        let seq_key = Self::seq_key(&update);
        let parent_hash = update.previous_hash;

        // Determine validity based on parent
        let validity = self.determine_validity(&update);

        if validity == Validity::Unknown {
            self.unknown_count += 1;
        }

        self.events.insert(hash, StoredEvent { update, validity });
        self.by_seq.insert(seq_key, hash);
        self.by_parent.entry(parent_hash).or_default().push(hash);
        self.insertion_order.push_back(hash);

        // Evict oldest events if over capacity
        if self.max_events > 0 {
            while self.events.len() > self.max_events {
                self.evict_oldest();
            }
        }

        // Update tip if valid
        if validity == Validity::Valid {
            self.update_tip(&hash);
            // Forward-propagate: check if any existing Unknown events
            // have this hash as their previous_hash
            self.propagate_forward(hash);
        }

        true
    }

    /// Primary lookup by content_hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&StoredEvent> {
        self.events.get(hash)
    }

    /// Secondary lookup by (ledger_id, operator_id, seq).
    pub fn get_by_seq(
        &self,
        ledger_id: &[u8; 32],
        operator_id: &PublicKey,
        seq: u64,
    ) -> Option<&StoredEvent> {
        let key = (*ledger_id, operator_id.serialize(), seq);
        self.by_seq.get(&key).and_then(|hash| self.events.get(hash))
    }

    /// Highest validated sequence number for (ledger, operator).
    pub fn validated_tip(&self, ledger_id: &[u8; 32], operator_id: &PublicKey) -> Option<u64> {
        let key = (*ledger_id, operator_id.serialize());
        self.validated_tips.get(&key).copied()
    }

    /// Find missing sequence numbers in [0, target_seq] for (ledger, operator).
    pub fn find_gaps(
        &self,
        ledger_id: &[u8; 32],
        operator_id: &PublicKey,
        target_seq: u64,
    ) -> Vec<u64> {
        let op_bytes = operator_id.serialize();
        let mut gaps = Vec::new();
        for seq in 0..=target_seq {
            let key = (*ledger_id, op_bytes, seq);
            if !self.by_seq.contains_key(&key) {
                gaps.push(seq);
            }
        }
        gaps
    }

    /// Check whether we have a complete Valid chain from seq 0 to `seq`.
    pub fn has_valid_chain_to(
        &self,
        ledger_id: &[u8; 32],
        operator_id: &PublicKey,
        seq: u64,
    ) -> bool {
        match self.validated_tip(ledger_id, operator_id) {
            Some(tip) => tip >= seq,
            None => false,
        }
    }

    /// Build an ordered list of validated updates from seq 0 to the tip.
    pub fn validated_chain(
        &self,
        ledger_id: &[u8; 32],
        operator_id: &PublicKey,
    ) -> Vec<&SignedLedgerUpdate> {
        let op_bytes = operator_id.serialize();
        let tip = match self.validated_tips.get(&(*ledger_id, op_bytes)) {
            Some(&t) => t,
            None => return Vec::new(),
        };

        let mut chain = Vec::with_capacity((tip + 1) as usize);
        for seq in 0..=tip {
            let key = (*ledger_id, op_bytes, seq);
            if let Some(hash) = self.by_seq.get(&key) {
                if let Some(stored) = self.events.get(hash) {
                    if stored.validity == Validity::Valid {
                        chain.push(&stored.update);
                    } else {
                        // Chain broken — stop here
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        chain
    }

    /// Count of events with Unknown validity (potential gap-fill targets).
    pub fn unknown_count(&self) -> usize {
        self.unknown_count
    }

    /// Cumulative count of events evicted since creation.
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }

    // ── private helpers ──

    /// Evict the oldest event (front of insertion_order).
    /// Removes from events, by_seq, and by_parent (as a child of its parent).
    fn evict_oldest(&mut self) {
        let hash = loop {
            match self.insertion_order.pop_front() {
                Some(h) => {
                    // Skip if already removed (e.g. duplicate hash from re-insert path)
                    if self.events.contains_key(&h) {
                        break h;
                    }
                }
                None => return, // Nothing left to evict
            }
        };

        if let Some(stored) = self.events.remove(&hash) {
            // Remove from by_seq
            let seq_key = Self::seq_key(&stored.update);
            self.by_seq.remove(&seq_key);

            // Remove from parent's children list in by_parent
            let parent_hash = stored.update.previous_hash;
            if let Some(children) = self.by_parent.get_mut(&parent_hash) {
                children.retain(|h| h != &hash);
                if children.is_empty() {
                    self.by_parent.remove(&parent_hash);
                }
            }

            if stored.validity == Validity::Unknown {
                self.unknown_count = self.unknown_count.saturating_sub(1);
            }

            self.evicted_total += 1;
        }
    }

    /// Build the secondary index key from an update.
    fn seq_key(update: &SignedLedgerUpdate) -> SeqKey {
        (
            update.ledger_id,
            update.operator_id.serialize(),
            update.sequence_number,
        )
    }

    /// Determine validity of a new event based on its parent.
    fn determine_validity(&self, update: &SignedLedgerUpdate) -> Validity {
        // Seq 0: chain root — previous_hash must be all zeros
        if update.sequence_number == 0 {
            if update.previous_hash != [0u8; 32] {
                return Validity::Invalid;
            }
            // Verify hash: SHA256(seq || prev_hash || message) == content_hash
            if update.compute_hash() == update.content_hash {
                return Validity::Valid;
            } else {
                return Validity::Invalid;
            }
        }

        // Non-root: look up parent by previous_hash
        match self.events.get(&update.previous_hash) {
            Some(parent) => match parent.validity {
                Validity::Valid => {
                    // Parent valid — verify our hash
                    if update.compute_hash() == update.content_hash {
                        Validity::Valid
                    } else {
                        Validity::Invalid
                    }
                }
                Validity::Invalid => Validity::Invalid,
                Validity::Unknown => Validity::Unknown,
            },
            // Parent not in store
            None => Validity::Unknown,
        }
    }

    /// Update the validated tip for this event's (ledger, operator) if needed.
    fn update_tip(&mut self, hash: &[u8; 32]) {
        let stored = match self.events.get(hash) {
            Some(s) => s,
            None => return,
        };
        let key = (
            stored.update.ledger_id,
            stored.update.operator_id.serialize(),
        );
        let seq = stored.update.sequence_number;
        let entry = self.validated_tips.entry(key).or_insert(0);
        // Tip is the highest seq with a complete valid chain from 0.
        // We only advance if seq == current_tip + 1 (consecutive) or seq == 0.
        if seq == 0 || seq == *entry + 1 {
            *entry = seq;
            // Keep advancing if the next seq is already valid
            self.advance_tip(key);
        }
    }

    /// Advance the tip as far as possible (for when we filled a gap).
    fn advance_tip(&mut self, tip_key: TipKey) {
        let current = match self.validated_tips.get(&tip_key) {
            Some(&t) => t,
            None => return,
        };
        let mut seq = current + 1;
        loop {
            let key = (tip_key.0, tip_key.1, seq);
            if let Some(hash) = self.by_seq.get(&key) {
                if let Some(stored) = self.events.get(hash) {
                    if stored.validity == Validity::Valid {
                        seq += 1;
                        continue;
                    }
                }
            }
            break;
        }
        if seq - 1 > current {
            self.validated_tips.insert(tip_key, seq - 1);
        }
    }

    /// After marking an event Valid, find any Unknown children waiting on it
    /// and recursively validate them.
    fn propagate_forward(&mut self, parent_hash: [u8; 32]) {
        // O(1) child lookup via reverse index instead of O(N) full scan
        let children: Vec<[u8; 32]> = match self.by_parent.get(&parent_hash) {
            Some(kids) => kids
                .iter()
                .filter(|hash| {
                    self.events
                        .get(*hash)
                        .map(|s| s.validity == Validity::Unknown)
                        .unwrap_or(false)
                })
                .copied()
                .collect(),
            None => return,
        };

        for child_hash in children {
            // Re-validate the child
            let valid = {
                let child = &self.events[&child_hash];
                child.update.compute_hash() == child.update.content_hash
            };

            let new_validity = if valid {
                Validity::Valid
            } else {
                Validity::Invalid
            };

            if let Some(stored) = self.events.get_mut(&child_hash) {
                stored.validity = new_validity;
            }
            // Transitioned out of Unknown
            self.unknown_count = self.unknown_count.saturating_sub(1);

            if new_validity == Validity::Valid {
                self.update_tip(&child_hash);
                // Recurse
                self.propagate_forward(child_hash);
            }
        }
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    /// Helper to create a keypair for testing.
    fn test_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    /// Helper to compute hash the same way SignedLedgerUpdate::compute_hash does.
    fn compute_hash(seq: u64, prev_hash: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seq.to_le_bytes());
        hasher.update(prev_hash);
        hasher.update(message);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Build a test update at a given sequence, chaining from prev_hash.
    fn make_update(
        ledger_id: [u8; 32],
        operator_id: PublicKey,
        seq: u64,
        prev_hash: [u8; 32],
        message: &[u8],
    ) -> SignedLedgerUpdate {
        let content_hash = compute_hash(seq, &prev_hash, message);
        SignedLedgerUpdate {
            message: message.to_vec(),
            message_type: 0x0001,
            operator_id,
            ledger_id,
            sequence_number: seq,
            previous_hash: prev_hash,
            content_hash,
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    /// Build a chain of N updates starting from seq 0.
    /// Messages include ledger_id prefix so different ledgers produce different hashes.
    fn make_chain(
        ledger_id: [u8; 32],
        operator_id: PublicKey,
        count: u64,
    ) -> Vec<SignedLedgerUpdate> {
        let mut chain = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..count {
            let msg = format!("lid-{:02x}-msg-{}", ledger_id[0], seq).into_bytes();
            let update = make_update(ledger_id, operator_id, seq, prev, &msg);
            prev = update.content_hash;
            chain.push(update);
        }
        chain
    }

    #[test]
    fn test_insert_and_get() {
        let (_, pk) = test_keypair();
        let lid = [0xAA; 32];
        let chain = make_chain(lid, pk, 3);

        let mut store = EventStore::new();
        for u in &chain {
            assert!(store.insert(u.clone()));
        }
        assert_eq!(store.len(), 3);

        // Get by hash
        assert!(store.get(&chain[0].content_hash).is_some());
        assert!(store.get(&chain[2].content_hash).is_some());

        // Get by seq
        assert!(store.get_by_seq(&lid, &pk, 0).is_some());
        assert!(store.get_by_seq(&lid, &pk, 2).is_some());
        assert!(store.get_by_seq(&lid, &pk, 5).is_none());
    }

    #[test]
    fn test_duplicate_insert_returns_false() {
        let (_, pk) = test_keypair();
        let chain = make_chain([0xBB; 32], pk, 1);
        let mut store = EventStore::new();
        assert!(store.insert(chain[0].clone()));
        assert!(!store.insert(chain[0].clone()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_sequential_validation() {
        let (_, pk) = test_keypair();
        let lid = [0xCC; 32];
        let chain = make_chain(lid, pk, 5);

        let mut store = EventStore::new();
        for u in &chain {
            store.insert(u.clone());
        }

        // All should be Valid
        for u in &chain {
            let stored = store.get(&u.content_hash).unwrap();
            assert_eq!(
                stored.validity,
                Validity::Valid,
                "seq {} should be valid",
                u.sequence_number
            );
        }

        // Tip should be 4
        assert_eq!(store.validated_tip(&lid, &pk), Some(4));
    }

    #[test]
    fn test_out_of_order_with_forward_propagation() {
        let (_, pk) = test_keypair();
        let lid = [0xDD; 32];
        let chain = make_chain(lid, pk, 4);

        let mut store = EventStore::new();

        // Insert seq 2, 3 first (out of order, parent missing)
        store.insert(chain[2].clone());
        store.insert(chain[3].clone());
        assert_eq!(
            store.get(&chain[2].content_hash).unwrap().validity,
            Validity::Unknown
        );
        assert_eq!(
            store.get(&chain[3].content_hash).unwrap().validity,
            Validity::Unknown
        );

        // Insert seq 0 — valid (root)
        store.insert(chain[0].clone());
        assert_eq!(
            store.get(&chain[0].content_hash).unwrap().validity,
            Validity::Valid
        );

        // seq 1 still missing, so 2 and 3 remain Unknown
        assert_eq!(
            store.get(&chain[2].content_hash).unwrap().validity,
            Validity::Unknown
        );

        // Insert seq 1 — should trigger forward propagation to 2 and 3
        store.insert(chain[1].clone());
        assert_eq!(
            store.get(&chain[1].content_hash).unwrap().validity,
            Validity::Valid
        );
        assert_eq!(
            store.get(&chain[2].content_hash).unwrap().validity,
            Validity::Valid
        );
        assert_eq!(
            store.get(&chain[3].content_hash).unwrap().validity,
            Validity::Valid
        );

        assert_eq!(store.validated_tip(&lid, &pk), Some(3));
    }

    #[test]
    fn test_invalid_hash() {
        let (_, pk) = test_keypair();
        let lid = [0xEE; 32];
        let chain = make_chain(lid, pk, 2);

        let mut store = EventStore::new();
        store.insert(chain[0].clone());

        // Create a tampered update — wrong content_hash
        let mut bad = chain[1].clone();
        bad.content_hash = [0xFF; 32]; // wrong hash
        store.insert(bad.clone());

        assert_eq!(
            store.get(&bad.content_hash).unwrap().validity,
            Validity::Invalid
        );
        assert_eq!(store.validated_tip(&lid, &pk), Some(0)); // only seq 0
    }

    #[test]
    fn test_invalid_parent_propagates() {
        let (_, pk) = test_keypair();
        let lid = [0x11; 32];

        // Build a chain of 3
        let chain = make_chain(lid, pk, 3);

        let mut store = EventStore::new();
        store.insert(chain[0].clone());

        // Tamper seq 1
        let mut bad1 = chain[1].clone();
        bad1.content_hash = [0xFF; 32];
        store.insert(bad1.clone());

        // Now insert something that chains off the bad hash
        let bad_child = make_update(lid, pk, 2, bad1.content_hash, b"child-of-bad");
        store.insert(bad_child.clone());

        assert_eq!(
            store.get(&bad1.content_hash).unwrap().validity,
            Validity::Invalid
        );
        assert_eq!(
            store.get(&bad_child.content_hash).unwrap().validity,
            Validity::Invalid
        );
    }

    #[test]
    fn test_find_gaps() {
        let (_, pk) = test_keypair();
        let lid = [0x22; 32];
        let chain = make_chain(lid, pk, 6);

        let mut store = EventStore::new();
        // Insert seq 0, 1, 3, 5 (missing 2, 4)
        store.insert(chain[0].clone());
        store.insert(chain[1].clone());
        store.insert(chain[3].clone());
        store.insert(chain[5].clone());

        let gaps = store.find_gaps(&lid, &pk, 5);
        assert_eq!(gaps, vec![2, 4]);
    }

    #[test]
    fn test_has_valid_chain_to() {
        let (_, pk) = test_keypair();
        let lid = [0x33; 32];
        let chain = make_chain(lid, pk, 5);

        let mut store = EventStore::new();
        for u in &chain[..3] {
            store.insert(u.clone());
        }

        assert!(store.has_valid_chain_to(&lid, &pk, 0));
        assert!(store.has_valid_chain_to(&lid, &pk, 2));
        assert!(!store.has_valid_chain_to(&lid, &pk, 3));
        assert!(!store.has_valid_chain_to(&lid, &pk, 4));
    }

    #[test]
    fn test_validated_chain() {
        let (_, pk) = test_keypair();
        let lid = [0x44; 32];
        let chain = make_chain(lid, pk, 4);

        let mut store = EventStore::new();
        for u in &chain {
            store.insert(u.clone());
        }

        let validated = store.validated_chain(&lid, &pk);
        assert_eq!(validated.len(), 4);
        for (i, u) in validated.iter().enumerate() {
            assert_eq!(u.sequence_number, i as u64);
        }
    }

    #[test]
    fn test_multiple_ledgers_independent() {
        let (_, pk) = test_keypair();
        let lid_a = [0x55; 32];
        let lid_b = [0x66; 32];
        let chain_a = make_chain(lid_a, pk, 3);
        let chain_b = make_chain(lid_b, pk, 5);

        let mut store = EventStore::new();
        for u in &chain_a {
            store.insert(u.clone());
        }
        for u in &chain_b {
            store.insert(u.clone());
        }

        assert_eq!(store.validated_tip(&lid_a, &pk), Some(2));
        assert_eq!(store.validated_tip(&lid_b, &pk), Some(4));
        assert_eq!(store.len(), 8);
    }

    #[test]
    fn test_seq0_wrong_prev_hash() {
        let (_, pk) = test_keypair();
        let lid = [0x77; 32];

        // seq 0 with non-zero previous_hash — should be Invalid
        let mut update = make_update(lid, pk, 0, [0u8; 32], b"genesis");
        update.previous_hash = [0x01; 32];
        // Recompute hash with wrong prev
        update.content_hash = compute_hash(0, &update.previous_hash, &update.message);

        let mut store = EventStore::new();
        store.insert(update.clone());
        assert_eq!(
            store.get(&update.content_hash).unwrap().validity,
            Validity::Invalid
        );
    }

    #[test]
    fn test_unknown_count() {
        let (_, pk) = test_keypair();
        let lid = [0x88; 32];
        let chain = make_chain(lid, pk, 4);

        let mut store = EventStore::new();
        // Insert seq 2 and 3 only (parents missing)
        store.insert(chain[2].clone());
        store.insert(chain[3].clone());

        assert_eq!(store.unknown_count(), 2);

        // Now insert seq 0 and 1 — everything resolves
        store.insert(chain[0].clone());
        store.insert(chain[1].clone());
        assert_eq!(store.unknown_count(), 0);
    }

    #[test]
    fn test_eviction_basic() {
        let (_, pk) = test_keypair();
        let lid = [0x99; 32];
        let chain = make_chain(lid, pk, 10);

        let mut store = EventStore::with_max_events(5);
        for u in &chain {
            store.insert(u.clone());
        }

        // Should have evicted down to 5
        assert_eq!(store.len(), 5);
        assert_eq!(store.evicted_total(), 5);

        // Oldest events (seq 0-4) should be gone
        for u in &chain[..5] {
            assert!(store.get(&u.content_hash).is_none());
        }
        // Newest events (seq 5-9) should remain
        for u in &chain[5..] {
            assert!(store.get(&u.content_hash).is_some());
        }
    }

    #[test]
    fn test_eviction_cleans_by_seq() {
        let (_, pk) = test_keypair();
        let lid = [0xA1; 32];
        let chain = make_chain(lid, pk, 6);

        let mut store = EventStore::with_max_events(3);
        for u in &chain {
            store.insert(u.clone());
        }

        // Evicted seq 0-2 should not be findable by seq
        assert!(store.get_by_seq(&lid, &pk, 0).is_none());
        assert!(store.get_by_seq(&lid, &pk, 1).is_none());
        assert!(store.get_by_seq(&lid, &pk, 2).is_none());

        // Remaining seq 3-5 should still be findable
        assert!(store.get_by_seq(&lid, &pk, 3).is_some());
        assert!(store.get_by_seq(&lid, &pk, 5).is_some());
    }

    #[test]
    fn test_eviction_decrements_unknown_count() {
        let (_, pk) = test_keypair();
        let lid_a = [0xA2; 32];
        let lid_b = [0xA4; 32];
        let chain_a = make_chain(lid_a, pk, 4);
        let chain_b = make_chain(lid_b, pk, 4);

        // Start with max 4 events. Insert 2 valid + 2 unknown.
        let mut store = EventStore::with_max_events(4);
        // Two valid events (seq 0-1 of chain_a)
        store.insert(chain_a[0].clone());
        store.insert(chain_a[1].clone());
        assert_eq!(store.unknown_count(), 0);

        // Two unknown events (seq 2-3 of chain_b, parents missing)
        store.insert(chain_b[2].clone());
        store.insert(chain_b[3].clone());
        assert_eq!(store.unknown_count(), 2);
        assert_eq!(store.len(), 4);

        // Insert one more valid event — evicts chain_a[0] (Valid), unknown stays 2
        store.insert(chain_a[2].clone());
        assert_eq!(store.len(), 4);
        assert_eq!(store.unknown_count(), 2);
        assert_eq!(store.evicted_total(), 1);

        // Insert another — evicts chain_a[1] (Valid), unknown still 2
        store.insert(chain_a[3].clone());
        assert_eq!(store.unknown_count(), 2);
        assert_eq!(store.evicted_total(), 2);

        // Insert one more (new ledger seq 0) — evicts chain_b[2] (Unknown), unknown drops to 1
        let chain_c = make_chain([0xA5; 32], pk, 1);
        store.insert(chain_c[0].clone());
        assert_eq!(store.len(), 4);
        assert_eq!(store.unknown_count(), 1); // chain_b[2] evicted (was Unknown)
        assert_eq!(store.evicted_total(), 3);
    }

    #[test]
    fn test_unlimited_mode_no_eviction() {
        let (_, pk) = test_keypair();
        let lid = [0xA3; 32];
        let chain = make_chain(lid, pk, 100);

        let mut store = EventStore::new(); // unlimited
        for u in &chain {
            store.insert(u.clone());
        }

        assert_eq!(store.len(), 100);
        assert_eq!(store.evicted_total(), 0);
    }
}
