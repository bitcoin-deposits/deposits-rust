// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Macros for handler delegation patterns.

/// Macro for simple handler delegation to core.
///
/// Generates a handler function that:
/// 1. Logs receipt of message
/// 2. Delegates to core handler
/// 3. Logs success/failure
/// 4. Returns Ok(())
macro_rules! delegate_to_core {
    (
        $fn_name:ident,
        $msg_type:ty,
        $log_prefix:expr,
        $core_fn:path
    ) => {
        pub(super) fn $fn_name(
            &self,
            msg: &$msg_type,
            sender: bitcoin::secp256k1::PublicKey,
        ) -> Result<(), lightning::ln::msgs::LightningError> {
            deposits_core::log_info!(self.logger, "{}: Processing", $log_prefix);
            match $core_fn(self, msg, sender) {
                Ok(_) => deposits_core::log_info!(self.logger, "{}: Success", $log_prefix),
                Err(e) => deposits_core::log_warn!(self.logger, "{}: Error: {:?}", $log_prefix, e),
            }
            Ok(())
        }
    };
}

pub(super) use delegate_to_core;
