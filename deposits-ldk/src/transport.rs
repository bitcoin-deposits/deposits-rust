// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Peer Transport Implementation
//!
//! Implements the `PeerTransport` trait using LDK's CustomMessageHandler interface.

use bitcoin::secp256k1::PublicKey;
use deposits_core::traits::{PeerTransport, TransportError};

use std::collections::HashSet;
use std::sync::Mutex;

/// LDK-based peer transport for Bitcoin Deposits protocol messages.
///
/// This adapter queues outgoing messages which are then retrieved by the
/// LDK peer handler via `get_and_clear_pending_msg()`.
pub struct LdkTransport {
    /// Pending outgoing messages: (peer, message_bytes)
    pending_messages: Mutex<Vec<(PublicKey, Vec<u8>)>>,
    /// Currently connected peers
    connected_peers: Mutex<HashSet<PublicKey>>,
}

impl LdkTransport {
    /// Create a new LDK transport adapter.
    pub fn new() -> Self {
        Self {
            pending_messages: Mutex::new(Vec::new()),
            connected_peers: Mutex::new(HashSet::new()),
        }
    }

    /// Get and clear pending outgoing messages.
    ///
    /// Called by the LDK CustomMessageHandler integration to retrieve
    /// messages that need to be sent to peers.
    pub fn get_and_clear_pending_messages(&self) -> Vec<(PublicKey, Vec<u8>)> {
        let mut pending = self.pending_messages.lock().unwrap();
        std::mem::take(&mut *pending)
    }

    /// Notify that a peer has connected.
    pub fn peer_connected(&self, peer: PublicKey) {
        let mut peers = self.connected_peers.lock().unwrap();
        peers.insert(peer);
    }

    /// Notify that a peer has disconnected.
    pub fn peer_disconnected(&self, peer: &PublicKey) {
        let mut peers = self.connected_peers.lock().unwrap();
        peers.remove(peer);
    }
}

impl Default for LdkTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTransport for LdkTransport {
    fn send(&self, peer: PublicKey, message: &[u8]) -> Result<(), TransportError> {
        // Check if peer is connected
        {
            let peers = self.connected_peers.lock().unwrap();
            if !peers.contains(&peer) {
                return Err(TransportError::PeerNotConnected(peer));
            }
        }

        // Queue the message
        let mut pending = self.pending_messages.lock().unwrap();
        pending.push((peer, message.to_vec()));
        Ok(())
    }

    fn broadcast(&self, peers: &[PublicKey], message: &[u8]) -> Result<(), TransportError> {
        let connected = self.connected_peers.lock().unwrap();
        let mut pending = self.pending_messages.lock().unwrap();

        for peer in peers {
            if connected.contains(peer) {
                pending.push((*peer, message.to_vec()));
            }
            // Skip disconnected peers silently for broadcast
        }

        Ok(())
    }

    fn is_connected(&self, peer: &PublicKey) -> bool {
        let peers = self.connected_peers.lock().unwrap();
        peers.contains(peer)
    }

    fn connected_peers(&self) -> Vec<PublicKey> {
        let peers = self.connected_peers.lock().unwrap();
        peers.iter().copied().collect()
    }
}

/// Raw message wrapper for LDK CustomMessageHandler integration.
///
/// This wraps raw protocol message bytes for transport through LDK's
/// custom message system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDepositsMessage(pub Vec<u8>);

impl RawDepositsMessage {
    /// Create a new raw message from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the message type from the first 2 bytes.
    pub fn message_type(&self) -> u16 {
        if self.0.len() >= 2 {
            u16::from_be_bytes([self.0[0], self.0[1]])
        } else {
            0
        }
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_transport_send_to_connected_peer() {
        let transport = LdkTransport::new();
        let peer = test_pubkey();

        // Connect peer
        transport.peer_connected(peer);
        assert!(transport.is_connected(&peer));

        // Send message
        let msg = vec![0x80, 0x01, 1, 2, 3];
        transport.send(peer, &msg).unwrap();

        // Check pending
        let pending = transport.get_and_clear_pending_messages();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, peer);
        assert_eq!(pending[0].1, msg);
    }

    #[test]
    fn test_transport_send_to_disconnected_peer() {
        let transport = LdkTransport::new();
        let peer = test_pubkey();

        // Not connected
        let result = transport.send(peer, &[1, 2, 3]);
        assert!(matches!(result, Err(TransportError::PeerNotConnected(_))));
    }

    #[test]
    fn test_transport_peer_lifecycle() {
        let transport = LdkTransport::new();
        let peer = test_pubkey();

        assert!(!transport.is_connected(&peer));
        assert!(transport.connected_peers().is_empty());

        transport.peer_connected(peer);
        assert!(transport.is_connected(&peer));
        assert_eq!(transport.connected_peers(), vec![peer]);

        transport.peer_disconnected(&peer);
        assert!(!transport.is_connected(&peer));
        assert!(transport.connected_peers().is_empty());
    }

    #[test]
    fn test_transport_broadcast() {
        let transport = LdkTransport::new();
        let peer1 = test_pubkey();
        let peer2 = test_pubkey_2();

        // Connect only peer1
        transport.peer_connected(peer1);

        // Broadcast to both
        let msg = vec![1, 2, 3];
        transport.broadcast(&[peer1, peer2], &msg).unwrap();

        // Only connected peer should receive
        let pending = transport.get_and_clear_pending_messages();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, peer1);
    }

    #[test]
    fn test_raw_message() {
        let msg = RawDepositsMessage::new(vec![0x80, 0x01, 1, 2, 3]);
        assert_eq!(msg.message_type(), 0x8001);
        assert_eq!(msg.as_bytes(), &[0x80, 0x01, 1, 2, 3]);
    }
}
