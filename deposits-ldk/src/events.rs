// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Event Emitter Implementation
//!
//! Implements the `EventEmitter` trait for emitting protocol events
//! to external consumers.

use deposits_core::traits::{EventEmitter, ProtocolEvent};

use std::sync::Mutex;

/// Callback-based event emitter.
///
/// Wraps a callback function that receives protocol events.
pub struct CallbackEventEmitter {
    callback: Box<dyn Fn(ProtocolEvent) + Send + Sync>,
}

impl CallbackEventEmitter {
    /// Create a new event emitter with a callback.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(ProtocolEvent) + Send + Sync + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl EventEmitter for CallbackEventEmitter {
    fn emit(&self, event: ProtocolEvent) {
        (self.callback)(event);
    }
}

/// Channel-based event emitter.
///
/// Sends events through an mpsc channel for async processing.
pub struct ChannelEventEmitter {
    sender: std::sync::mpsc::Sender<ProtocolEvent>,
}

impl ChannelEventEmitter {
    /// Create a new channel-based emitter.
    ///
    /// Returns the emitter and a receiver for consuming events.
    pub fn new() -> (Self, std::sync::mpsc::Receiver<ProtocolEvent>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (Self { sender }, receiver)
    }
}

impl EventEmitter for ChannelEventEmitter {
    fn emit(&self, event: ProtocolEvent) {
        // Ignore send errors (receiver dropped)
        let _ = self.sender.send(event);
    }
}

/// In-memory event collector for testing.
#[derive(Default)]
pub struct MemoryEventEmitter {
    events: Mutex<Vec<ProtocolEvent>>,
}

impl MemoryEventEmitter {
    /// Create a new in-memory event collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all collected events.
    pub fn get_events(&self) -> Vec<ProtocolEvent> {
        let events = self.events.lock().unwrap();
        events.clone()
    }

    /// Clear all events.
    pub fn clear(&self) {
        let mut events = self.events.lock().unwrap();
        events.clear();
    }

    /// Get count of events.
    pub fn len(&self) -> usize {
        let events = self.events.lock().unwrap();
        events.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EventEmitter for MemoryEventEmitter {
    fn emit(&self, event: ProtocolEvent) {
        let mut events = self.events.lock().unwrap();
        events.push(event);
    }
}

/// No-op event emitter that discards all events.
pub struct NullEventEmitter;

impl EventEmitter for NullEventEmitter {
    fn emit(&self, _event: ProtocolEvent) {
        // Discard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_memory_emitter() {
        let emitter = MemoryEventEmitter::new();

        assert!(emitter.is_empty());

        emitter.emit(ProtocolEvent::DepositOpened {
            operator: test_pubkey(),
            reserves_id: test_pubkey_2().to_string(),
            deposit_pubkey: test_pubkey(),
        });

        assert_eq!(emitter.len(), 1);

        let events = emitter.get_events();
        assert!(matches!(events[0], ProtocolEvent::DepositOpened { .. }));

        emitter.clear();
        assert!(emitter.is_empty());
    }

    #[test]
    fn test_callback_emitter() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        let emitter = CallbackEventEmitter::new(move |_event| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        emitter.emit(ProtocolEvent::LedgerSynced {
            operator: test_pubkey(),
            reserves_id: test_pubkey_2().to_string(),
            sequence: 1,
            hash: [0u8; 32],
        });

        assert_eq!(count.load(Ordering::SeqCst), 1);

        emitter.emit(ProtocolEvent::LedgerSynced {
            operator: test_pubkey(),
            reserves_id: test_pubkey_2().to_string(),
            sequence: 2,
            hash: [0u8; 32],
        });

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_channel_emitter() {
        let (emitter, receiver) = ChannelEventEmitter::new();

        emitter.emit(ProtocolEvent::RecoveryStarted {
            operator: test_pubkey(),
            reserves_id: test_pubkey_2().to_string(),
        });

        let event = receiver.recv().unwrap();
        assert!(matches!(event, ProtocolEvent::RecoveryStarted { .. }));
    }

    #[test]
    fn test_null_emitter() {
        let emitter = NullEventEmitter;

        // Should not panic
        emitter.emit(ProtocolEvent::Error {
            operator: test_pubkey(),
            reserves_id: test_pubkey_2().to_string(),
            error: "test error".to_string(),
        });
    }
}
