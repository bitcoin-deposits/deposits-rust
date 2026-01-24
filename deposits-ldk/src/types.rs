// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Type aliases for common types used in deposits-ldk.
//!
//! Re-exports `HashStrategy` from deposits-core for backwards compatibility.

use lightning::util::persist::KVStoreSync;

/// Dynamic storage type - wraps LDK's KVStoreSync trait object
pub type DynStore = dyn KVStoreSync + Sync + Send;

// Re-export HashStrategy from deposits-core
pub use deposits_core::HashStrategy;
