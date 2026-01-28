// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Stub types for legacy protocol components.
//!
//! These stubs allow the handler code to compile while the migration is in progress.
//! TODO: Remove these stubs and properly migrate or remove the functionality.

use std::ops::Deref;
use lightning::util::logger::Logger as LdkLogger;

/// Stub for DepositsProtocol (legacy protocol manager).
///
/// This is a placeholder that allows compilation. The actual functionality
/// will be migrated or removed in a future commit.
pub struct DepositsProtocol<L: Deref>
where
    L::Target: LdkLogger,
{
    _marker: std::marker::PhantomData<L>,
}

impl<L: Deref> DepositsProtocol<L>
where
    L::Target: LdkLogger,
{
    /// Create a stub protocol instance (does nothing).
    pub fn stub() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    /// Create a new protocol instance (stub - ignores all parameters).
    pub fn new(
        _secret_key: bitcoin::secp256k1::SecretKey,
        _store: std::sync::Arc<dyn lightning::util::persist::KVStoreSync + Sync + Send>,
        _logger: L,
    ) -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}
