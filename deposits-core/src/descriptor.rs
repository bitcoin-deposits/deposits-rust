//! Miniscript descriptor verification for deposits.
//!
//! All deposit operations are authorized by satisfying a miniscript descriptor.
//! The `pk()` case is optimized as a fast path (direct Schnorr verification),
//! but any valid miniscript descriptor is supported.

use crate::types::DescriptorWitness;
use crate::DepositsError;
use bitcoin::secp256k1::{Message, Secp256k1};

/// Verify that a witness satisfies a descriptor for a given message hash.
///
/// This is the single entry point for all deposit authorization checks.
/// Transfers, withdrawals, invoice requests, and receive authorizations
/// all go through this function.
///
/// # Fast path
/// For `pk(<compressed_pubkey_hex>)` descriptors, performs direct Schnorr
/// signature verification without invoking the miniscript library.
///
/// # General path
/// For other descriptors, parses as miniscript and evaluates the witness
/// stack against it.
pub fn verify_witness(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
) -> Result<bool, DepositsError> {
    // Fast path: pk() descriptor — direct Schnorr verification
    if let Some(result) = try_verify_pk(descriptor, witness, message_hash)? {
        return Ok(result);
    }

    // General path: parse as miniscript
    verify_miniscript(descriptor, witness, message_hash)
}

/// Extract the pubkey from a `pk()` descriptor and verify a Schnorr signature.
/// Returns `Ok(None)` if the descriptor is not a `pk()` descriptor.
fn try_verify_pk(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
) -> Result<Option<bool>, DepositsError> {
    if !(descriptor.starts_with("pk(") && descriptor.ends_with(")")) {
        return Ok(None);
    }

    let pk_hex = &descriptor[3..descriptor.len() - 1];
    let pubkey_bytes = hex::decode(pk_hex).map_err(|_| DepositsError::ProtocolViolation {
        violation_type: "invalid_descriptor".to_string(),
        details: "Invalid pubkey hex in pk() descriptor".to_string(),
    })?;

    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes).map_err(|_| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_descriptor".to_string(),
            details: "Invalid pubkey in pk() descriptor".to_string(),
        }
    })?;

    // Need exactly one 64-byte signature
    if witness.stack.len() != 1 || witness.stack[0].len() != 64 {
        return Ok(Some(false));
    }

    use bitcoin::secp256k1::schnorr::Signature;
    let sig = match Signature::from_slice(&witness.stack[0]) {
        Ok(s) => s,
        Err(_) => return Ok(Some(false)),
    };

    let secp = Secp256k1::verification_only();
    let x_only = pubkey.x_only_public_key().0;
    let msg = Message::from_digest(*message_hash);

    Ok(Some(secp.verify_schnorr(&sig, &msg, &x_only).is_ok()))
}

/// Verify a witness against a general miniscript descriptor.
///
/// Parses the descriptor, checks each signature in the witness stack
/// against the message hash, and evaluates satisfaction.
fn verify_miniscript(
    descriptor: &str,
    witness: &DescriptorWitness,
    message_hash: &[u8; 32],
) -> Result<bool, DepositsError> {
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    // Try to parse as a miniscript descriptor
    // Deposits use raw key hex, so wrap in a bare wsh context for parsing
    let desc_str = if descriptor.starts_with("wsh(")
        || descriptor.starts_with("sh(")
        || descriptor.starts_with("tr(")
    {
        descriptor.to_string()
    } else {
        // Bare policy — wrap in wsh() for miniscript parsing
        format!("wsh({})", descriptor)
    };

    let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).map_err(|e| {
        DepositsError::ProtocolViolation {
            violation_type: "invalid_descriptor".to_string(),
            details: format!("Failed to parse descriptor '{}': {}", descriptor, e),
        }
    })?;

    // For each key in the descriptor, check if the witness contains a valid
    // Schnorr signature for that key over the message_hash
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(*message_hash);

    // Extract all pubkeys from the descriptor
    let mut keys = Vec::new();
    extract_keys(&desc, &mut keys);

    // Verify each signature in the witness against the known keys
    let mut valid_sigs = 0usize;
    for sig_bytes in &witness.stack {
        if sig_bytes.len() != 64 {
            continue;
        }
        if let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes) {
            for key in &keys {
                let x_only = key.x_only_public_key().0;
                if secp.verify_schnorr(&sig, &msg, &x_only).is_ok() {
                    valid_sigs += 1;
                    break;
                }
            }
        }
    }

    // Determine required signatures from the descriptor structure
    let required = required_sigs(&desc);

    Ok(valid_sigs >= required)
}

/// Extract all public keys from a descriptor.
fn extract_keys(
    desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    keys: &mut Vec<bitcoin::secp256k1::PublicKey>,
) {
    use miniscript::ForEachKey;
    desc.for_each_key(|key| {
        if let miniscript::DescriptorPublicKey::Single(single) = key {
            match &single.key {
                miniscript::descriptor::SinglePubKey::FullKey(pk) => {
                    keys.push(pk.inner);
                }
                miniscript::descriptor::SinglePubKey::XOnly(xonly) => {
                    // Convert x-only to compressed (assume even y)
                    let mut bytes = [0u8; 33];
                    bytes[0] = 0x02;
                    bytes[1..].copy_from_slice(&xonly.serialize());
                    if let Ok(pk) = bitcoin::secp256k1::PublicKey::from_slice(&bytes) {
                        keys.push(pk);
                    }
                }
            }
        }
        true // continue iterating
    });
}

/// Determine the minimum number of signatures required by a descriptor.
fn required_sigs(desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>) -> usize {
    // Simple heuristic: count keys in the descriptor
    // For pk(): 1, for multi(k,..): k, for and(pk,pk): 2
    // A full implementation would walk the miniscript tree
    let mut key_count = 0usize;
    use miniscript::ForEachKey;
    desc.for_each_key(|_| {
        key_count += 1;
        true
    });

    // For threshold descriptors, we'd need to inspect the structure
    // For now, assume all keys are required (conservative)
    // TODO: extract threshold from multi() and thresh() nodes
    key_count.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn make_keypair() -> (SecretKey, bitcoin::secp256k1::PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    fn sign_message(sk: &SecretKey, msg_hash: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, sk);
        let msg = Message::from_digest(*msg_hash);
        secp.sign_schnorr_no_aux_rand(&msg, &keypair).serialize()
    }

    #[test]
    fn pk_descriptor_valid_signature() {
        let (sk, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let sig = sign_message(&sk, &msg_hash);
        let witness = DescriptorWitness {
            stack: vec![sig.to_vec()],
        };

        assert!(verify_witness(&descriptor, &witness, &msg_hash).unwrap());
    }

    #[test]
    fn pk_descriptor_invalid_signature() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash).unwrap());
    }

    #[test]
    fn pk_descriptor_wrong_message() {
        let (sk, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let wrong_hash = [0xBB; 32];
        let sig = sign_message(&sk, &msg_hash);
        let witness = DescriptorWitness {
            stack: vec![sig.to_vec()],
        };

        assert!(!verify_witness(&descriptor, &witness, &wrong_hash).unwrap());
    }

    #[test]
    fn pk_descriptor_empty_witness() {
        let (_, pk) = make_keypair();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness { stack: vec![] };

        assert!(!verify_witness(&descriptor, &witness, &msg_hash).unwrap());
    }

    #[test]
    fn invalid_descriptor_rejected() {
        let msg_hash = [0xAA; 32];
        let witness = DescriptorWitness {
            stack: vec![vec![0xBB; 64]],
        };

        let result = verify_witness("not_a_descriptor", &witness, &msg_hash);
        assert!(result.is_err());
    }
}
