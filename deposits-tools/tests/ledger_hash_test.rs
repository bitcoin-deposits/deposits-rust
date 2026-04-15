//! Test for ledger hash commitment transaction integration

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::{opcodes::all::OP_RETURN, script::Builder, Amount, Transaction, TxOut};
    use deposits_core::DepositsError;

    /// Test the ledger hash OP_RETURN output creation and extraction
    #[test]
    fn test_ledger_hash_op_return() {
        // Create test ledger hash
        let test_ledger_hash = [0x42u8; 32];
        let prefix = b"BDLH";

        // Create OP_RETURN script with ledger hash
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(prefix)
            .push_slice(&test_ledger_hash)
            .into_script();

        // Create transaction output
        let output = TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        };

        // Test extraction logic
        let extracted_hash = extract_ledger_hash_from_output(&output, prefix);
        assert_eq!(extracted_hash, Some(test_ledger_hash));

        println!("✅ Ledger hash OP_RETURN creation and extraction test passed!");
    }

    /// Extract ledger hash from an OP_RETURN output
    fn extract_ledger_hash_from_output(output: &TxOut, expected_prefix: &[u8]) -> Option<[u8; 32]> {
        // Check if this is an OP_RETURN output
        if output.value != Amount::ZERO {
            return None;
        }

        let script = &output.script_pubkey;
        let script_bytes = script.as_bytes();

        // Minimum length: OP_RETURN (1) + prefix_len (1) + prefix (4) + hash_len (1) + hash (32) = 39 bytes
        if script_bytes.len() < 39 {
            return None;
        }

        // Check for OP_RETURN opcode
        if script_bytes[0] != OP_RETURN.to_u8() {
            return None;
        }

        // Check prefix length and value
        let prefix_len = script_bytes[1] as usize;
        if prefix_len != expected_prefix.len() || script_bytes.len() < 2 + prefix_len + 1 + 32 {
            return None;
        }

        let actual_prefix = &script_bytes[2..2 + prefix_len];
        if actual_prefix != expected_prefix {
            return None;
        }

        // Check hash length
        let hash_len_pos = 2 + prefix_len;
        let hash_len = script_bytes[hash_len_pos] as usize;
        if hash_len != 32 || script_bytes.len() < hash_len_pos + 1 + hash_len {
            return None;
        }

        // Extract hash
        let hash_start = hash_len_pos + 1;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_bytes[hash_start..hash_start + 32]);

        Some(hash)
    }

    #[test]
    fn test_commitment_transaction_with_ledger_hash() {
        // Create basic commitment transaction
        let mut commitment_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Test ledger hash
        let ledger_hash = [0x99u8; 32];

        // Create and add ledger hash output
        let prefix = b"BDLH";
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(prefix)
            .push_slice(&ledger_hash)
            .into_script();

        let ledger_hash_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        };

        commitment_tx.output.push(ledger_hash_output);

        // Validate transaction contains correct ledger hash
        let found_hash = validate_commitment_ledger_hash(&commitment_tx, ledger_hash);
        assert!(found_hash.is_ok(), "Should validate correct ledger hash");

        // Test with wrong hash
        let wrong_hash = [0xAAu8; 32];
        let wrong_result = validate_commitment_ledger_hash(&commitment_tx, wrong_hash);
        assert!(wrong_result.is_err(), "Should fail with wrong ledger hash");

        // Test with no ledger hash
        let empty_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let missing_result = validate_commitment_ledger_hash(&empty_tx, ledger_hash);
        assert!(
            missing_result.is_err(),
            "Should fail when ledger hash is missing"
        );

        println!("✅ Commitment transaction ledger hash validation test passed!");
    }

    /// Validate that a commitment transaction contains the expected ledger hash
    fn validate_commitment_ledger_hash(
        commitment_tx: &Transaction,
        expected_ledger_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        // Search for OP_RETURN output containing ledger hash
        let prefix = b"BDLH";

        for output in &commitment_tx.output {
            if let Some(found_hash) = extract_ledger_hash_from_output(output, prefix) {
                if found_hash == expected_ledger_hash {
                    return Ok(()); // Found matching ledger hash
                } else {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "ledger_hash_mismatch".to_string(),
                        details: format!(
                            "Commitment transaction contains incorrect ledger hash. Expected: {:?}, Found: {:?}",
                            expected_ledger_hash,
                            found_hash
                        ),
                    });
                }
            }
        }

        // No ledger hash found
        Err(DepositsError::ProtocolViolation {
            violation_type: "missing_ledger_hash".to_string(),
            details: "Commitment transaction missing required ledger hash OP_RETURN output"
                .to_string(),
        })
    }
}
