// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Reserves commitment operations for the Bitcoin Deposits protocol.

use bitcoin::secp256k1::PublicKey;
use super::core::{build_taproot_reserves_script, DepositsHandler};
use super::messages::DepositsMessage;
use deposits_core::DepositsError;
use deposits_core::messages::CoordinationMsg;
use super::ledger_ext::LedgerExt;
use deposits_core::VoterSet;
use deposits_core::CommitmentExtraOutput;
use deposits_core::{log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;
use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Refresh reserves commitment after ACKed ledger update (operator only)
    pub(super) fn refresh_reserves_commitment(&self, partner: PublicKey) -> Result<(), DepositsError> {
        // Get ledger state - only for ledgers where we're operator
        let (hash, key, reserves, needs_update, remote_hash, voter_set) = match self.get_operator_ledger_state(partner) {
            Some(state) => state,
            None => return Ok(()), // Not operator, skip
        };

        if !needs_update { return Ok(()); }

        self.send_update_reserves(partner, hash, reserves, voter_set, remote_hash, Some(key))
    }

    /// Get operator ledger state if we're the operator
    fn get_operator_ledger_state(&self, partner: PublicKey) -> Option<([u8; 32], (PublicKey, String), u64, bool, [u8; 32], VoterSet)> {
        let ledgers = self.ledgers.lock().unwrap();
        let key = (self.our_node_id, partner.to_string());
        let ledger_arc = ledgers.get(&key)?;
        let ledger = ledger_arc.read().unwrap();

        let acked = ledger.state.partner_deepest_ack_hash;
        let committed = ledger.state.channel_deepest_commitment_hash;
        let needs_update = acked != committed && acked != [0u8; 32];
        let reserves = ledger.reserves_amount();
        let voter_set = ledger.construct_voter_set();

        let remote_hash = ledgers.get(&(partner, self.our_node_id.to_string()))
            .map(|arc| arc.read().unwrap().tail_hash())
            .unwrap_or([0u8; 32]);

        Some((acked, key, reserves, needs_update, remote_hash, voter_set))
    }

    /// Send UpdateReserves to partner
    fn send_update_reserves(
        &self,
        partner: PublicKey,
        hash: [u8; 32],
        reserves: u64,
        voter_set: VoterSet,
        remote_hash: [u8; 32],
        update_key: Option<(PublicKey, String)>,
    ) -> Result<(), DepositsError> {
        let cm = self.channel_manager.as_ref().ok_or(DepositsError::InvalidChannelState)?;
        let channel = cm.list_channels_with_counterparty(&partner).first()
            .ok_or(DepositsError::InvalidChannelState)?.clone();

        let reserves_sats = std::cmp::max(reserves, 330);
        let script = build_taproot_reserves_script(voter_set, hash, self.network)?;

        log_info!(self.logger, "🔄 UpdateReserves to {} hash {:02x?}", partner, &hash[0..8]);

        let script_clone = script.clone();
        let script_bytes = script.as_bytes().to_vec();

        let output = CommitmentExtraOutput { amount_satoshis: reserves_sats, script_pubkey: script };
        cm.propose_extra_outputs(&partner, &channel.channel_id, vec![output])
            .map_err(|_| DepositsError::InvalidChannelState)?;

        // Track pending commitment
        {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            self.pending_reserves_commitments.lock().unwrap().insert(partner, (script_clone, hash, reserves_sats, now));
        }

        // Send custom message
        let msg = DepositsMessage::Coordination(CoordinationMsg::UpdateReserves {
            channel_id: channel.channel_id.0, reserves_sats, script_pubkey: script_bytes,
            ledger_hash: hash, remote_ledger_hash: remote_hash,
        });

        if let Err(e) = self.send_message(partner, msg) {
            log_error!(self.logger, "Failed to send UpdateReserves: {:?}", e);
        } else {
            log_info!(self.logger, "📤 Sent UpdateReserves hash {:02x?}", &hash[0..8]);
        }

        // Update commitment hash if key provided
        if let Some(key) = update_key {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&key) {
                let mut ledger = arc.write().unwrap();
                ledger.state.channel_deepest_commitment_hash = hash;
                let _ = self.persist_ledger_state(&ledger);
            }
        }

        Ok(())
    }

    /// Commit specific hash to channel (predict-then-commit pattern)
    pub(super) fn commit_specific_hash_to_channel(
        &self,
        partner: PublicKey,
        hash: [u8; 32],
        reserves: u64,
        voter_set: VoterSet,
    ) -> Result<(), DepositsError> {
        let remote_hash = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.get(&(partner, self.our_node_id.to_string()))
                .map(|arc| arc.read().unwrap().tail_hash())
                .unwrap_or([0u8; 32])
        };

        log_info!(self.logger, "🔄 PREDICT-COMMIT: hash {:02x?}", &hash[0..8]);
        self.send_update_reserves(partner, hash, reserves, voter_set, remote_hash, None)
    }
}
