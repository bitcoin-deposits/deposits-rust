#!/bin/bash
#
# Test script for non-conforming behavior: unregister an invoice
# so funds go to the node instead of the deposit, then submit fraud proof.
#
# Usage: ./bin/test-non-conforming.sh [network]

cd "$(dirname "$0")/.."
set -e
. ./bin/_common.sh

NETWORK=$(get_network "${1:-}") || exit 1
validate_network "$NETWORK" || exit 1

mkdir -p log
LOGFILE=log/test-non-conforming-$(date +'%s').log
exec > >(tee -a "$LOGFILE") 2>&1

NWC="../target/release/nwc-client"

echo "=== Non-Conforming Test: Invoice Unregistration + Fraud Proof ==="
echo "Network: $NETWORK"
echo ""

# Run the standard setup
./bin/make-node-wallets.sh
./bin/make-a-wallet.sh alice charlie bob amber
./bin/make-a-wallet.sh bob charlie alice blue
./bin/pay-amber-from-charlie.sh
./bin/pay-blue-from-amber.sh

echo ""
echo "=== Standard setup complete. Now testing non-conforming behavior ==="
echo ""

# Show current state
echo "--- Before non-conforming payment ---"
./bin/updates.sh --verbose

# Get amber's deposit pubkey from balance response (not wallet file - that's NWC pubkey)
BALANCE_RESPONSE=$($NWC -w wallet/amber.json balance 2>/dev/null)
AMBER_DEPOSIT_PUBKEY=$(echo "$BALANCE_RESPONSE" | jq -r '.result.deposit_pubkey')
echo ""
echo "Amber's deposit pubkey: $AMBER_DEPOSIT_PUBKEY"

# Get alice's node ID (the operator)
ALICE_NODE_ID=$(curl -s http://localhost:3011/info | jq -r '.data.node_id')
echo "Alice's node ID (operator): $ALICE_NODE_ID"

# Get amber's current balance
echo ""
echo "--- Amber's balance before ---"
$NWC -w wallet/amber.json balance

# Create an invoice for amber (will be registered for deposit)
echo ""
echo "--- Creating invoice for amber's deposit (5000 msat) ---"
INVOICE_RESPONSE=$($NWC -w wallet/amber.json make-invoice 5000)
echo "$INVOICE_RESPONSE"

# Extract invoice and payment_hash
INVOICE=$(echo "$INVOICE_RESPONSE" | jq -r '.result.invoice')
PAYMENT_HASH=$(echo "$INVOICE_RESPONSE" | jq -r '.result.payment_hash')

echo ""
echo "Invoice: $INVOICE"
echo "Payment Hash: $PAYMENT_HASH"

# Unregister the invoice so it goes to the node instead of the deposit
echo ""
echo "--- UNREGISTERING INVOICE (non-conforming) ---"
# Alice is the operator (port 3011)
UNREGISTER_RESPONSE=$(curl -s -X POST http://localhost:3011/bitcoin-deposits/non-conforming/unregister-invoice \
  -H "Content-Type: application/json" \
  -d "{\"payment_hash\": \"$PAYMENT_HASH\"}")
echo "$UNREGISTER_RESPONSE" | jq .

# Pay the invoice from charlie
echo ""
echo "--- Paying unregistered invoice from charlie ---"
2>/dev/null $NWC -w wallet/charlie.json pay-invoice "$INVOICE" || true

sleep 3

# Get the preimage from charlie's payment record
echo ""
echo "--- Getting payment preimage from charlie (the payer) ---"
# Charlie is port 3013
PAYMENT_RESPONSE=$(curl -s http://localhost:3013/bitcoin-deposits/non-conforming/get-payment/$PAYMENT_HASH)
echo "$PAYMENT_RESPONSE" | jq .

PREIMAGE=$(echo "$PAYMENT_RESPONSE" | jq -r '.data.preimage')
echo ""
echo "Preimage: $PREIMAGE"

if [ "$PREIMAGE" == "null" ] || [ -z "$PREIMAGE" ]; then
    echo "ERROR: Preimage not available yet. Payment may still be in-flight."
    echo "Waiting 5 more seconds..."
    sleep 5
    PAYMENT_RESPONSE=$(curl -s http://localhost:3013/bitcoin-deposits/non-conforming/get-payment/$PAYMENT_HASH)
    PREIMAGE=$(echo "$PAYMENT_RESPONSE" | jq -r '.data.preimage')
    echo "Preimage (retry): $PREIMAGE"
fi

# Show updated state
echo ""
echo "--- After non-conforming payment ---"
./bin/updates.sh --verbose

# Show amber's balance after (should be unchanged since funds went to node)
echo ""
echo "--- Amber's balance after (should be unchanged - funds went to node) ---"
$NWC -w wallet/amber.json balance

echo ""
echo "=== SUBMITTING FRAUD PROOF ==="
echo ""
echo "Bob (the partner who cosigned the invoice) will submit an uncredited payment accusation against Alice (operator)"
echo "This will force-close the alice-bob channel and broadcast the fraud proof to all auditors."
echo ""

if [ "$PREIMAGE" != "null" ] && [ -n "$PREIMAGE" ]; then
    # Submit fraud proof from Bob (port 3012) - the partner who cosigned the invoice
    # Amber's deposit is on the alice-bob ledger, so Bob is the one who can verify
    # This uses the regular endpoint (not non-conforming) - submitting fraud proof is legitimate
    FRAUD_PROOF_RESPONSE=$(curl -s -X POST http://localhost:3012/bitcoin-deposits/submit-fraud-proof \
      -H "Content-Type: application/json" \
      -d "{
        \"operator\": \"$ALICE_NODE_ID\",
        \"payment_hash\": \"$PAYMENT_HASH\",
        \"preimage\": \"$PREIMAGE\",
        \"deposit_pubkey\": \"$AMBER_DEPOSIT_PUBKEY\",
        \"amount_msat\": 5000
      }")
    echo "Fraud proof response:"
    echo "$FRAUD_PROOF_RESPONSE" | jq .
else
    echo "ERROR: Cannot submit fraud proof without preimage"
fi

echo ""
echo "=== Non-Conforming Test Complete ==="
echo ""
echo "Summary:"
echo "1. Amber's deposit balance should NOT have increased by 5000 msat (funds went to Alice's node)"
echo "2. Bob submitted a fraud proof with the preimage proving Alice stole the funds"
echo "3. The channel between Bob and Alice should be force-closed"
echo "4. All auditors (collateral partners) should have received the accusation"
