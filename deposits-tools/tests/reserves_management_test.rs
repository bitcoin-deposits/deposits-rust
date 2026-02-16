//! Test for reserves management with 100% deposit backing requirement

#[cfg(test)]
mod tests {
    use deposits_ldk::wire::channel_ledger::ChannelLedger;
    use deposits_ldk::handler::messages::{DepositsMessage, LedgerUpdateMsg, LedgerOperation, LedgerUpdateMsgExt};
    use deposits_core::DepositsError;
    use deposits_core::constants::MIN_RESERVES_RATIO_PERCENT;
    use deposits_core::types::compute_deposit_id;
    use ldk_node::bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
    use ldk_node::bitcoin::secp256k1::rand::rngs::OsRng;
    use ldk_node::bitcoin::Address;
    use ldk_node::bitcoin::address::NetworkUnchecked;

    /// Compute deposit_id from pubkey
    fn deposit_id_from_pubkey(pubkey: &PublicKey) -> [u8; 16] {
        let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
        compute_deposit_id(&descriptor)
    }

    /// Helper to create a unique hash from an integer
    fn hash_from_int(n: u64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&n.to_le_bytes());
        hash
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_reserves_management_100_percent_rule() {
        let mut rng = OsRng;
        let secp = Secp256k1::new();
        let operator_key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let partner_key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));

        let test_address: Address<NetworkUnchecked> = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".parse().unwrap();
        let ledger_address = test_address.assume_checked();
        let mut ledger = ChannelLedger::new(operator_key, partner_key, ledger_address);

        println!("Testing Bitcoin Deposits Reserves Management ({}% Rule)", MIN_RESERVES_RATIO_PERCENT);
        println!("   Minimum reserves ratio: {}%", MIN_RESERVES_RATIO_PERCENT);

        println!("\nTest 1: Initial state - no deposits, no reserves required");
        let status = ledger.get_reserves_status();
        assert_eq!(status.total_deposit_balances, 0, "Should have no deposits initially");
        assert_eq!(status.required_amount, 0, "Should require no reserves with no deposits");
        assert_eq!(status.current_amount, 0, "Should have no reserves initially");

        // Should be able to validate (no deposits = no reserves required)
        assert!(ledger.validate_current_reserves_requirement().is_ok(), "Should validate with no deposits");
        println!("Initial state validation passed");

        println!("\nTest 2: Add deposit without reserves - should be allowed (0% backing)");
        let alice_depositor = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let alice_deposit = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));

        // Add deposit (no balance yet)
        ledger.add_deposit(alice_depositor, alice_deposit, None).expect("Should add deposit");
        assert_eq!(ledger.deposits.len(), 1, "Should have one deposit");

        // Still no balance, so no reserves required
        let status = ledger.get_reserves_status();
        assert_eq!(status.total_deposit_balances, 0);
        assert_eq!(status.required_amount, 0);
        println!("Empty deposit added successfully");

        println!("\nTest 3: Try to add balance without adequate reserves - should fail");
        ledger.mark_committed_to_channel(hash_from_int(1)); // Allow changes

        let balance_amount = 100_000; // 100k sats
        let required_reserves = (balance_amount * MIN_RESERVES_RATIO_PERCENT as u64) / 100; // 100k sats

        println!("   Trying to add {} sats balance", balance_amount);
        println!("   Required reserves: {} sats ({}% of {})", required_reserves, MIN_RESERVES_RATIO_PERCENT, balance_amount);
        println!("   Current reserves: {} sats", ledger.reserves.amount);

        let alice_deposit_id = deposit_id_from_pubkey(&alice_deposit);
        let result = ledger.add_balance_to_deposit(alice_deposit_id, balance_amount);
        assert!(result.is_err(), "Should reject balance increase without adequate reserves");

        if let Err(DepositsError::InsufficientReserves { required, available }) = result {
            assert_eq!(required, required_reserves);
            assert_eq!(available, 0);
            println!("Correctly rejected: Required {} sats, Available {} sats", required, available);
        } else {
            panic!("Expected InsufficientReserves error");
        }

        println!("\nTest 4: Add adequate reserves, then add balance - should work");
        ledger.mark_committed_to_channel(hash_from_int(2)); // Allow changes

        // Add exactly enough reserves using V2 LedgerUpdate API
        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesIncrease { reserves_id: "test".to_string(), new_amount: required_reserves },
        ))).expect("Should add reserves");
        println!("   Added {} sats to reserves", required_reserves);

        ledger.mark_committed_to_channel(hash_from_int(3)); // Allow changes

        // Now balance increase should work
        ledger.add_balance_to_deposit(alice_deposit_id, balance_amount).expect("Should add balance with adequate reserves");

        let status = ledger.get_reserves_status();
        assert_eq!(status.total_deposit_balances, balance_amount);
        assert_eq!(status.required_amount, required_reserves);
        assert_eq!(status.current_amount, required_reserves);
        assert_eq!(status.excess_amount, 0, "Should have exactly enough reserves");

        println!("Balance added successfully with adequate reserves");
        println!("   Final state: {} sats deposits, {} sats reserves ({}%)",
                 status.total_deposit_balances,
                 status.current_amount,
                 (status.current_amount * 100) / status.total_deposit_balances);

        println!("\nTest 5: Try to add more balance without increasing reserves - should fail");
        ledger.mark_committed_to_channel(hash_from_int(4)); // Allow changes

        let additional_balance = 50_000; // 50k sats more
        let result = ledger.add_balance_to_deposit(alice_deposit_id, additional_balance);
        assert!(result.is_err(), "Should reject additional balance without more reserves");

        if let Err(DepositsError::InsufficientReserves { required, available }) = result {
            let expected_required = ((balance_amount + additional_balance) * MIN_RESERVES_RATIO_PERCENT as u64) / 100;
            assert_eq!(required, expected_required);
            assert_eq!(available, required_reserves);
            println!("Correctly rejected additional balance: Required {} sats, Available {} sats", required, available);
        }

        println!("\nTest 6: Add excess reserves, then add balance - should work");
        ledger.mark_committed_to_channel(hash_from_int(5)); // Allow changes

        let excess_reserves = 100_000; // 100k extra reserves
        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesIncrease { reserves_id: "test".to_string(), new_amount: excess_reserves },
        ))).expect("Should add excess reserves");

        let status = ledger.get_reserves_status();
        assert_eq!(status.excess_amount, excess_reserves, "Should track excess reserves");

        ledger.mark_committed_to_channel(hash_from_int(6)); // Allow changes

        // Now additional balance should work
        ledger.add_balance_to_deposit(alice_deposit_id, additional_balance).expect("Should add balance with excess reserves");

        let final_status = ledger.get_reserves_status();
        let final_ratio = (final_status.current_amount * 100) / final_status.total_deposit_balances;
        println!("Additional balance added successfully");
        println!("   Final state: {} sats deposits, {} sats reserves ({}%)",
                 final_status.total_deposit_balances,
                 final_status.current_amount,
                 final_ratio);

        assert!(final_ratio >= MIN_RESERVES_RATIO_PERCENT as u64, "Should maintain at least 100% backing");

        println!("\nTest 7: Multiple deposits with reserves management");
        ledger.mark_committed_to_channel(hash_from_int(7)); // Allow changes

        let bob_depositor = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let bob_deposit = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));

        // Add second deposit
        ledger.add_deposit(bob_depositor, bob_deposit, None).expect("Should add second deposit");

        ledger.mark_committed_to_channel(hash_from_int(8)); // Allow changes

        // Try to add balance to Bob without more reserves
        let bob_balance = 200_000; // 200k sats
        let bob_deposit_id = deposit_id_from_pubkey(&bob_deposit);
        let result = ledger.add_balance_to_deposit(bob_deposit_id, bob_balance);

        // Should fail because total reserves need to cover Alice + Bob balances
        assert!(result.is_err(), "Should require more reserves for second deposit balance");

        // Add enough reserves for both deposits
        let current_total = final_status.total_deposit_balances;
        let new_total_after_bob = current_total + bob_balance;
        let total_required = (new_total_after_bob * MIN_RESERVES_RATIO_PERCENT as u64) / 100;
        let additional_reserves_needed = total_required - final_status.current_amount;

        ledger.mark_committed_to_channel(hash_from_int(9)); // Allow changes
        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesIncrease { reserves_id: "test".to_string(), new_amount: additional_reserves_needed },
        ))).expect("Should add additional reserves");

        ledger.mark_committed_to_channel(hash_from_int(10)); // Allow changes

        // Now Bob's balance should work
        ledger.add_balance_to_deposit(bob_deposit_id, bob_balance).expect("Should add Bob's balance with adequate reserves");

        let multi_deposit_status = ledger.get_reserves_status();
        assert_eq!(multi_deposit_status.deposit_count, 2, "Should have two deposits");

        let multi_ratio = (multi_deposit_status.current_amount * 100) / multi_deposit_status.total_deposit_balances;
        println!("Multiple deposits managed successfully");
        println!("   Final multi-deposit state: {} deposits, {} sats total deposits, {} sats reserves ({}%)",
                 multi_deposit_status.deposit_count,
                 multi_deposit_status.total_deposit_balances,
                 multi_deposit_status.current_amount,
                 multi_ratio);

        assert!(multi_ratio >= MIN_RESERVES_RATIO_PERCENT as u64, "Should maintain at least 100% backing for multiple deposits");

        println!("\nReserves Management Test Completed!");
        println!("   Key security properties verified:");
        println!("   - Deposit balance increases blocked without adequate reserves");
        println!("   - {}% reserves ratio enforced for all operations", MIN_RESERVES_RATIO_PERCENT);
        println!("   - Multiple deposits properly managed with combined reserves");
        println!("   - Excess reserves allow additional deposits");
        println!("   - Precise reserves calculations prevent over/under backing");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_reserves_tracking() {
        let mut rng = OsRng;
        let secp = Secp256k1::new();
        let operator_key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let partner_key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));

        let test_address: Address<NetworkUnchecked> = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".parse().unwrap();
        let ledger_address = test_address.assume_checked();
        let mut ledger = ChannelLedger::new(operator_key, partner_key, ledger_address);

        println!("Testing Reserves Tracking");

        // Set up initial state: 100k deposit with 150k reserves (50k excess)
        let depositor = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let deposit_key = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));

        ledger.add_deposit(depositor, deposit_key, None).unwrap();
        ledger.mark_committed_to_channel(hash_from_int(1));

        let initial_reserves = 150_000; // 150k reserves
        let deposit_balance = 100_000;  // 100k deposit

        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesIncrease { reserves_id: "test".to_string(), new_amount: initial_reserves },
        ))).unwrap();
        ledger.mark_committed_to_channel(hash_from_int(2));

        let deposit_key_id = deposit_id_from_pubkey(&deposit_key);
        ledger.add_balance_to_deposit(deposit_key_id, deposit_balance).unwrap();
        ledger.mark_committed_to_channel(hash_from_int(3));

        println!("   Initial: {} sats deposits, {} sats reserves", deposit_balance, initial_reserves);

        println!("\nTest 1: Check excess reserves calculation");
        let status = ledger.get_reserves_status();
        let expected_required = (deposit_balance * MIN_RESERVES_RATIO_PERCENT as u64) / 100;
        assert_eq!(status.required_amount, expected_required);
        assert_eq!(status.excess_amount, initial_reserves - expected_required);
        println!("   Required: {} sats, Excess: {} sats", status.required_amount, status.excess_amount);

        println!("\nTest 2: Reduce reserves - verify tracking");
        let reduction = 30_000;
        ledger.mark_committed_to_channel(hash_from_int(4));
        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesDecrease { reserves_id: "test".to_string(), new_amount: reduction },
        ))).expect("Should reduce reserves");

        let status_after = ledger.get_reserves_status();
        assert_eq!(status_after.current_amount, initial_reserves - reduction);
        println!("   After reduction: {} sats reserves", status_after.current_amount);

        println!("\nTest 3: Use validate_current_reserves_requirement");
        // Reserves are still 120k which is >= 100k required
        assert!(ledger.validate_current_reserves_requirement().is_ok(), "Should pass with adequate reserves");
        println!("   Validation passed with {} sats reserves for {} sats deposits",
                 status_after.current_amount, status_after.total_deposit_balances);

        println!("\nTest 4: Reduce below minimum and check validation fails");
        // Reduce by 30k more to get to 90k (below 100k required)
        ledger.mark_committed_to_channel(hash_from_int(5));
        ledger.apply_update(DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator_key,
            "test".to_string(),
            LedgerOperation::ReservesDecrease { reserves_id: "test".to_string(), new_amount: 30_000 },
        ))).expect("Message processing succeeds");

        let final_status = ledger.get_reserves_status();
        println!("   After second reduction: {} sats reserves", final_status.current_amount);

        // Now validation should fail
        let validation_result = ledger.validate_current_reserves_requirement();
        assert!(validation_result.is_err(), "Validation should fail when reserves < required");
        if let Err(DepositsError::InsufficientReserves { required, available }) = validation_result {
            println!("   Validation correctly reports: Required {} sats, Available {} sats", required, available);
            assert_eq!(required, expected_required);
            assert_eq!(available, final_status.current_amount);
        }

        println!("\nReserves Tracking Test Completed!");
        println!("   Key behaviors verified:");
        println!("   - Reserves status correctly tracks amounts");
        println!("   - Excess reserves calculation is accurate");
        println!("   - validate_current_reserves_requirement detects shortfalls");
    }
}
