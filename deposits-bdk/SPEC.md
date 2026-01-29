# deposits-bdk: On-Chain Reserves + Nostr Implementation

**Goal**: Validate that deposits-core is a meaningfully independent library by implementing the protocol with different infrastructure than deposits-ldk.

## Architecture Comparison

| Aspect | deposits-ldk | deposits-bdk |
|--------|-------------|--------------|
| Reserves | Lightning commitment tx outputs | On-chain P2WSH UTXOs |
| Peer messaging | Lightning wire protocol | Nostr encrypted DMs |
| Invoice payments | Native Lightning | External Lightning node/service |
| Speed | Fast (Lightning-native) | Slower (on-chain + relay latency) |
| Complexity | Higher (LDK integration) | Lower (BDK + Nostr) |

## Core Protocol (shared with deposits-ldk)

Both implementations use deposits-core for:
- **Ledger**: Ordered list of operations (Add, Remove, Fee, Credit)
- **State**: Hash chain of signed updates
- **Collateral**: Partner relationships and monitoring
- **Recovery**: Fraud proofs and fund recovery
- **Messages**: LedgerUpdateMsg, CoordinationMsg, RecoveryMsg, etc.

## deposits-bdk Specific

### On-Chain Reserves

Reserves are held in P2WSH outputs:

```
OP_IF
    <operator_pubkey> CHECKSIG
    <timeout> CHECKLOCKTIMEVERIFY
OP_ELSE
    <threshold> <partner1_pubkey> ... <partnerN_pubkey> <N> CHECKMULTISIG
OP_ENDIF
```

- **Normal path**: Operator refreshes reserves before timeout
- **Recovery path**: Partners spend via threshold multisig on fraud evidence

### Nostr Transport

Protocol messages are sent as encrypted Nostr DMs (NIP-04 or NIP-44):

1. Serialize `DepositsMessage` using `encode()`
2. Encrypt to recipient's pubkey
3. Publish to shared relay set
4. Recipient decrypts and processes

Node IDs are secp256k1 pubkeys (same as Nostr pubkeys).

### Lightning Integration

For invoice operations, deposits-bdk connects to an external Lightning node:

- **Creating invoices**: Call Lightning node to generate BOLT11
- **Paying invoices**: Call Lightning node to pay, then record Credit on ledger
- **Receiving payments**: Lightning node notifies of payment, record Credit on ledger

This could be:
- LND via REST/gRPC
- CLN via commando/REST
- LDK-node as a subprocess
- NWC (Nostr Wallet Connect) to a remote wallet

## Implementation Phases

### Phase 1: Single Operator (MVP)
- [ ] BDK wallet with reserves output creation
- [ ] Nostr transport for peer messaging
- [ ] HandlerContext implementation using deposits-core
- [ ] Basic ledger operations (Add, Remove)
- [ ] Lightning integration for invoices (via NWC or LND)

### Phase 2: Collateral Partners
- [ ] Pre-signed recovery transactions
- [ ] Partner monitoring via Nostr subscriptions
- [ ] Quorum voting for recovery
- [ ] Multi-party reserve outputs

### Phase 3: Production Hardening
- [ ] Electrum/Esplora chain sync
- [ ] Persistent storage (SQLite or file-based)
- [ ] Relay failover and redundancy
- [ ] Recovery transaction broadcasting

## What This Validates

If deposits-bdk works, it proves:

1. **deposits-core is transport-agnostic**: Same message handlers work over Lightning wire or Nostr
2. **deposits-core is reserve-agnostic**: Same ledger logic works with commitment tx or UTXO reserves
3. **The protocol is meaningful**: Core concepts survive without Lightning-specific optimizations
4. **Simpler deployments possible**: Operators can run without full LDK integration

## Trade-offs

**Slower**: On-chain reserves require Bitcoin confirmations. Nostr has relay latency.

**Simpler**: No channel management, no liquidity concerns, no routing.

**More transparent**: All reserves visible on-chain. State updates can be published publicly.

**Less private**: On-chain footprint larger than Lightning channels.
