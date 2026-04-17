# Changelog

## 0.1.0 — Initial Release

### Protocol (deposits-protocol)

- TLV wire format with 25 operation types covering deposits, invoices, on-chain, transfers, quorum, and dispute resolution
- Hash-chained ledger updates with operator and co-signer signatures
- Conformance checking framework: `apply_with_verifier()` for watchers, `check_and_apply()` for operators
- `WitnessVerifier` trait for pluggable cryptographic verification
- Reserve sufficiency and witness validation on all lock operations
- Fraud proof construction and causal chain verification
- Kaitai Struct schema (`deposits_protocol.ksy`) as wire format source of truth

### Core (deposits-core)

- Ledger state machine with `append_operation()` and `commit_staged()` flows
- Operation validation: balance checks, dispute state gates, collateral ratchets, fee minimums
- `CoreWitnessVerifier`: real Schnorr/ECDSA verification via miniscript descriptors
- Tapscript reserves: threshold-based spending with degrading timelocks
- Recovery: claim execution, entropy-based winner selection, confiscation transactions
- Event store: content-addressed, gap-tolerant storage for ledger sync

### Node (deposits-node)

- BDK wallet for on-chain reserves (P2WSH and Taproot multisig)
- Nostr transport: NIP-04 DMs, public events (kinds 9100/20101/20102/9103)
- 27 request handlers covering full deposit/transfer/quorum/dispute lifecycle
- Conformance-checked operator path (commit_staged refuses non-conforming state)
- Conformance-logged watcher path (inbound updates checked, violations logged)
- Periodic automation: deposit completion, fee collection, transfer timeouts
- CLI: deposits-node (operator daemon), deposits-wallet (customer wallet)
- Utility binaries: htlc-agent, transfer-simulator, nostr-ping, nostr-bench

### Tools (deposits-tools)

- Local test environment: Docker infrastructure + bare-process operators
- Setup scripts: 4-operator, N-operator (scalable), with optional Lightning
- Test scripts: quorum formation, dispute resolution, Lightning payments
- Replay-ledger TUI for ledger inspection
- LNURL-pay gateway (deposits-lnurl)

### Testing

- 547 tests across all crates
- Integration test crate (tests/) with multi-operator protocol simulations
- Conformance detection tests: reserve violations, bad witnesses, watcher sync
- Protocol codec tests: TLV roundtrips, Kaitai schema validation, hash chains

### CI

- GitHub Actions: format check, clippy (deny warnings), test, build
- Workspace lint configuration with documented deferred-refactor allows
