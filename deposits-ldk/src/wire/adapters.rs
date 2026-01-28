// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Wire Adapters - REMOVED
//!
//! The `Ldk*Msg` wrapper types have been removed. They were unused dead code.
//!
//! The `DepositsMessage` enum in `handler/messages.rs` implements `Readable`/`Writeable`
//! directly, so individual message wrappers are not needed.
//!
//! Handler code uses deposits-core message types directly.
