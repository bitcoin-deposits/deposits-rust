// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signature utilities for the Bitcoin Deposits protocol.
//!
//! This module re-exports signature utilities from deposits-core.
//! See [`deposits_core::signature_utils`] for the implementation.

// Re-export all signature utilities from deposits-core
pub use deposits_core::signature_utils::{
    create_deposit_guarantee_signature,
    verify_deposit_guarantee_signature,
    create_payment_authorization_signature,
};
