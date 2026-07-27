//! Inbound request handlers, split by request domain. Each child
//! module contributes its own `impl Node` block so every handler
//! remains a method on `Node`. Shared helpers
//! (resolve_attested_sender, check_admin_authorized) live here.

use super::*;

pub mod admin;
pub mod cooperative_refund;
pub mod cosign;
pub mod custody;
pub mod deposits;
pub mod health;
pub mod invoice;
pub mod quorum;
pub mod transfer;

impl Node {
    /// Resolve the "effective sender" of a request, collapsing DEP-04
    /// subkey delegation so downstream ACL checks see the account
    /// pubkey rather than the delegated signer.
    ///
    /// When a request carries `["v", <account>]` + `["va", <sig>]` tags,
    /// this verifies:
    ///   - `sig` is a valid BIP-340 Schnorr signature, by `account`, over
    ///     `SHA256("nostr301:" + sender)`;
    ///   - the account has published a Kind 10301 list that includes the
    ///     sender in `inbox_keys` AND does NOT list it in
    ///     `revoked_subkeys`.
    ///
    /// On success returns the account pubkey (hex xonly). With no
    /// delegation tags, returns the original sender unchanged. An invalid
    /// or revoked delegation returns `Err(...)` so callers can reject
    /// the request with a clear code instead of silently falling back
    /// to the direct sender.
    pub(crate) async fn resolve_attested_sender(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<String, String> {
        let (account, sig_hex) = match (&request.subkey_account, &request.subkey_attestation) {
            (Some(a), Some(s)) => (a, s),
            (None, None) => return Ok(request.sender.clone()),
            _ => {
                return Err("subkey delegation requires BOTH `v` and `va` tags".to_string());
            }
        };

        // Sanity-check hex lengths up front so we can produce a clean
        // error before paying for Schnorr verification / Nostr fetches.
        if account.len() != 64 || !account.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "subkey account `{}` is not 32-byte xonly hex",
                account
            ));
        }
        if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("subkey attestation must be 64-byte hex (Schnorr)".to_string());
        }

        // ── Verify the Schnorr attestation: sig(msg, account) ──
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{schnorr, Message, XOnlyPublicKey};
        let msg_str = format!("nostr301:{}", request.sender);
        let digest = sha256::Hash::hash(msg_str.as_bytes());
        let msg = Message::from_digest(digest.to_byte_array());

        let account_bytes =
            hex::decode(account).map_err(|e| format!("invalid subkey account hex: {}", e))?;
        let xonly = XOnlyPublicKey::from_slice(&account_bytes)
            .map_err(|e| format!("invalid subkey account xonly: {}", e))?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| format!("invalid subkey attestation hex: {}", e))?;
        let sig = schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid Schnorr signature: {}", e))?;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|_| "subkey attestation signature failed verification".to_string())?;

        // ── Policy check: Kind 10301 list must include sender as
        //    active (in inbox_keys) and NOT revoked. ──
        let (inbox, revoked) =
            self.nostr.fetch_subkey_list(account).await.map_err(|e| {
                format!("failed to fetch subkey list for {}: {}", &account[..16], e)
            })?;
        if revoked.iter().any(|k| k == &request.sender) {
            return Err(format!(
                "sender {} is revoked on account {}'s subkey list",
                &request.sender[..16],
                &account[..16]
            ));
        }
        if !inbox.iter().any(|k| k == &request.sender) {
            return Err(format!(
                "sender {} is not in account {}'s inbox_keys",
                &request.sender[..16],
                &account[..16]
            ));
        }

        tracing::info!(
            "Resolved subkey {} → account {} via DEP-04 attestation",
            &request.sender[..16.min(request.sender.len())],
            &account[..16]
        );
        Ok(account.clone())
    }

    /// Check whether an incoming request is authorized to invoke admin-class
    /// actions (e.g. `ledger_open`, `reserves_create`). Admin requests must
    /// be gift-wrapped and the unwrapped sender must match either our own
    /// operator pubkey (local CLI using the operator seed) or the admin
    /// pubkey registered at bootstrap (remote admin with their own key).
    ///
    /// Returns `Ok(())` if authorized; otherwise returns the standard
    /// handler failure tuple for the caller to return directly.
    pub(crate) fn check_admin_authorized(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<(), (bool, Option<String>, Option<String>)> {
        let Some(sender_hex) = request.gift_wrap_sender.as_deref() else {
            return Err((
                false,
                None,
                Some("admin request must be gift-wrapped".to_string()),
            ));
        };

        // Our operator identity as x-only hex (nostr key == operator key).
        let our_xonly = {
            let (xo, _) = self.node_id.x_only_public_key();
            hex::encode(xo.serialize())
        };
        if sender_hex == our_xonly {
            return Ok(());
        }

        if let Some(admin_pk) = &self.admin_pubkey {
            if sender_hex == admin_pk.to_hex() {
                return Ok(());
            }
        }

        Err((
            false,
            None,
            Some(format!(
                "admin request from {}: not operator or registered admin",
                &sender_hex[..16.min(sender_hex.len())]
            )),
        ))
    }
}
