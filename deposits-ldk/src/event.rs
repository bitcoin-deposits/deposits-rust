// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Event queue for deposits handler.
//!
//! This module provides an EventQueue type that wraps the EventEmitter trait,
//! providing compatibility with the handler code that uses add_event().
//!
//! ## Event System Abstraction
//!
//! The `DepositsEventEmitter` trait allows different event backends to be used:
//! - `EventQueue` (this module) - simple in-memory queue
//! - ldk-node's EventQueue - integrates with ldk-node's event system
//! - Custom implementations for other Lightning implementations

use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use lightning::util::logger::Logger as LdkLogger;

use super::handler::events::DepositsEvent;

/// Trait for emitting deposits protocol events.
///
/// This trait allows the handler to work with different event backends.
/// Implementations can integrate with various Lightning node event systems.
pub trait DepositsEventEmitter: Send + Sync {
    /// Emit a deposits protocol event.
    fn emit_deposits_event(&self, event: DepositsEvent) -> Result<(), ()>;
}

/// An event that can be queued.
#[derive(Clone, Debug)]
pub enum Event {
    /// A deposits protocol event.
    Deposits {
        /// The deposits event.
        event: DepositsEvent,
    },
}

/// Event queue for collecting and processing events.
pub struct EventQueue<L: Deref>
where
    L::Target: LdkLogger,
{
    queue: Arc<Mutex<VecDeque<Event>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    logger: L,
}

impl<L: Deref> EventQueue<L>
where
    L::Target: LdkLogger,
{
    /// Create a new event queue.
    pub fn new(logger: L) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            waker: Arc::new(Mutex::new(None)),
            logger,
        }
    }

    /// Add an event to the queue.
    pub fn add_event(&self, event: Event) -> Result<(), ()> {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(event);

        // Wake any waiting async tasks
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }

        Ok(())
    }

    /// Take the next event from the queue.
    pub fn next_event(&self) -> Option<Event> {
        let mut queue = self.queue.lock().unwrap();
        queue.pop_front()
    }

    /// Register a waker for async notification.
    pub fn set_waker(&self, waker: Waker) {
        *self.waker.lock().unwrap() = Some(waker);
    }

    /// Get the number of pending events.
    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<L: Deref + Send + Sync> DepositsEventEmitter for EventQueue<L>
where
    L::Target: LdkLogger,
{
    fn emit_deposits_event(&self, event: DepositsEvent) -> Result<(), ()> {
        self.add_event(Event::Deposits { event })
    }
}

impl<L: Deref + Clone> Clone for EventQueue<L>
where
    L::Target: LdkLogger,
{
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            waker: Arc::clone(&self.waker),
            logger: self.logger.clone(),
        }
    }
}
