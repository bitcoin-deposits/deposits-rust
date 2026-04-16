// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core data types for the Bitcoin Deposits Protocol.
//!
//! These types are Lightning-implementation agnostic and use serde for serialization.

mod conformance;
mod core;
mod ledger_state;
mod serde_helpers;
mod updates;

pub use self::core::*;
pub use conformance::*;
pub use ledger_state::*;
pub use serde_helpers::*;
pub use updates::*;
