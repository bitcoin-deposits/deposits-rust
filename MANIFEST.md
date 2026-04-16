# File Manifest

Generated 2026-04-15. Total: ~133,500 lines across 4 crates + tooling.

---

## deposits-protocol

Pure protocol definitions: wire format, types, TLV encoding. No state machine or handler logic.

### src/

```
src/lib.rs                      (47 lines)  — Crate root; re-exports constants, error, fraud, messages, tlv, types, wire_messages
src/constants.rs                (41 lines)  — Protocol constants (reserves limits, timeouts, thresholds)
src/error.rs                   (348 lines)  — Error types for the deposits protocol (DepositsError enum)
src/fraud.rs                   (508 lines)  — Fraud proof construction and verification (FraudProof, FraudBroadcast, causal chains)
src/signature_utils.rs         (249 lines)  — Signing message construction (pure data builders, no crypto ops)
src/tlv.rs                     (997 lines)  — LDK-independent TLV (Type-Length-Value) codec with forward-compatible serialization
src/wire_messages.rs          (1835 lines)  — Wire protocol message structs with LDK-independent serialization
```

### src/messages/

```
src/messages/mod.rs             (37 lines)  — Consolidated message protocol module (12 message types, 6 request/response pairs)
src/messages/constants.rs      (364 lines)  — Protocol version, message type constants (all odd per BOLT 1)
src/messages/tlv_codec.rs     (2599 lines)  — TLV encode/decode implementations for all message types
src/messages/types.rs         (1802 lines)  — Main DepositsMessage enum and LedgerOperation variants
src/messages/wire_types.rs     (986 lines)  — Wire struct definitions (Handshake, Sync, LedgerUpdate, Coordination, Recovery, Collateral)
```

### src/types/

```
src/types/mod.rs                (22 lines)  — Type module root; re-exports core, conformance, ledger_state, updates
src/types/conformance.rs        (89 lines)  — Conformance checking types and traits (reserve backing, witness verification)
src/types/core.rs             (1199 lines)  — Core type definitions (Deposit, FeeStructure, QuorumMember, DescriptorWitness)
src/types/ledger_state.rs      (940 lines)  — LedgerState definition and state transition logic (apply operations)
src/types/serde_helpers.rs     (325 lines)  — Serde helpers and deposit identifier utilities
src/types/updates.rs          (1764 lines)  — Signed ledger updates, audit types, and TLV encoding implementations
```

### tests/

```
tests/audit_features_test.rs   (277 lines)  — Tests for audit-related TLV encoding of LedgerOperations
tests/chain_hash_test.rs       (398 lines)  — Tests for hash chain structure (current_hash, chain_hash, previous_hash linkage)
tests/conformance_test.rs      (266 lines)  — Tests for LedgerState conformance tracking (reserve backing, witness verification)
tests/fraud_proof_test.rs      (628 lines)  — Tests for fraud proof hashing, causal chains, and evidence types
tests/kaitai_roundtrip.rs      (418 lines)  — Roundtrip test: Rust TLV encode -> Kaitai parse -> Rust decode -> re-encode
tests/ksy_catalog_test.rs      (649 lines)  — .ksy comment parser validates wire format against Kaitai Struct spec as source of truth
tests/ksy_schema_validation.rs (617 lines)  — Schema validation: .ksy documentation -> TLV bytes -> Rust decode -> re-encode -> compare
```

### Other files

```
Cargo.toml                      (29 lines)  — Package manifest (deps: bitcoin, serde, thiserror, sha2)
generate.sh                     (42 lines)  — Generate parsers from the Kaitai Struct definition
deposits_protocol.ksy            (N/A)      — Kaitai Struct schema for the TLV wire format
generated/deposits_protocol.rs (758 lines)  — Auto-generated Rust parser from Kaitai Struct
generated/deposits_protocol.py (369 lines)  — Auto-generated Python parser from Kaitai Struct
generated/DepositsProtocol.js    (N/A)      — Auto-generated JavaScript parser from Kaitai Struct
```

---

## deposits-core

Core protocol logic: state machine, validation, signing, ledger, quorum, recovery. Zero Lightning implementation dependencies.

### src/

```
src/lib.rs                     (377 lines)  — Crate root; re-exports all core modules, adapter traits, and types
src/channel_manager_ops.rs     (239 lines)  — ChannelManagerOps trait abstracting LDK channel manager operations
src/descriptor.rs              (311 lines)  — Miniscript descriptor verification for deposit authorization (pk() fast path + generic)
src/event_store.rs             (870 lines)  — Content-addressed event store for ledger sync (hash-based, gap-tolerant)
src/handler.rs                (1517 lines)  — Core protocol state machine, generic over Lightning implementation
src/handler_traits.rs          (245 lines)  — Handler extension traits (CollateralOperations, etc.) for protocol handlers
src/handler_types.rs           (233 lines)  — Handler-specific types (statistics, summaries, state tracking)
src/ledger.rs                 (2499 lines)  — Hash-chained ledger operations with cryptographic proof of history
src/logging.rs                 (116 lines)  — Logging macros (LDK-compatible interface backed by tracing crate)
src/message_processor.rs       (484 lines)  — Trait-based message processing for any Lightning implementation
src/message_validation.rs     (1225 lines)  — Message-level validation (ValidationContext trait, two-layer design)
src/operation_validation.rs   (1502 lines)  — Operation-level pure validation functions for ledger operations
src/payment_tracker.rs         (259 lines)  — Deposit invoice payment tracking with O(1) payment-to-deposit lookups
src/quorum.rs                 (1150 lines)  — Quorum management: peer formation, state sync, voting for conformance
src/recovery.rs               (1048 lines)  — Ledger recovery after force close (evaluation, not accusation)
src/recovery_claim.rs          (931 lines)  — Recovery claim execution: on-chain claim of reserves for non-compliant operators
src/reserves_proposal.rs       (334 lines)  — Reserves output proposal types for Lightning commitment transactions
src/signing.rs                 (898 lines)  — Cryptographic signing and verification (actual crypto ops)
src/tapscript_reserves.rs     (1401 lines)  — Tapscript multisig reserves with threshold-based spending and degrading timelocks
src/time_utils.rs               (82 lines)  — Time utilities (Unix timestamps, SystemTime conversion)
src/traits.rs                 (1122 lines)  — Adapter traits abstracting Lightning implementation specifics (LDK, CLN, etc.)
src/validation.rs             (1515 lines)  — Core economic validation rules (100% reserves, fee limits, balance caps)
```

### src/message_handlers/

```
src/message_handlers/mod.rs     (92 lines)  — Lightning-agnostic handler functions module root
src/message_handlers/admin.rs (1114 lines)  — Fee collection and ledger lifecycle handlers
src/message_handlers/collateral.rs (1075 lines) — Collateral consent request/response handlers
src/message_handlers/deposits.rs (978 lines) — Deposit open/close handlers (porcupine dance cosigning)
src/message_handlers/ledger.rs  (323 lines)  — Generic LedgerUpdate handler (single entry point for all ledger-modifying ops)
src/message_handlers/payments.rs (925 lines) — Payment credit/debit handlers (receiving, sending, invoice management)
src/message_handlers/quorum.rs  (224 lines)  — Quorum join/leave request handlers
src/message_handlers/recovery.rs (528 lines) — Recovery vote and claim signature handlers
src/message_handlers/reserves.rs (544 lines) — Reserves add/remove output handlers
src/message_handlers/types.rs   (255 lines)  — Handler result types (Ok, Response, Rejected, Error)
```

### tests/

```
tests/audit_obligation_test.rs          (365 lines)  — Tests for obligation limits and state changes from audit operations
tests/collateral_deposit_test.rs        (164 lines)  — Tests for is_collateral flag on DepositOpen and CollateralLock validation
tests/cosign_validation_test.rs         (438 lines)  — Tests that cosign validation rejects invalid operations
tests/deposit_balance_limit_test.rs     (178 lines)  — Tests for per-deposit balance limits (MAX_DEPOSIT_BALANCE_MSATS)
tests/fee_change_test.rs               (628 lines)  — Tests for fee change validation with block notice and change limits
tests/quorum_fee_limits_test.rs        (957 lines)  — Tests for quorum member fee limits on QuorumAddMember
tests/receive_requires_sig_test.rs     (316 lines)  — Tests for receive_requires_sig flag propagation through protocol layer
```

### Other files

```
Cargo.toml                      (45 lines)  — Package manifest (deps: bitcoin, sha2, tracing, thiserror, deposits-protocol)
DISPUTES.md                    (180 lines)  — Custody disputes and recovery protocol documentation
```

---

## deposits-node

BDK + Nostr implementation: on-chain wallet, Nostr transport, CLI, node daemon, and utility binaries.

### src/

```
src/lib.rs                      (55 lines)  — Crate root; BDK + Nostr implementation of Bitcoin Deposits protocol
src/error.rs                    (44 lines)  — Error types for deposits-node
src/handler.rs                (1735 lines)  — HandlerContext implementation using BDK wallet and Nostr transport
src/ldk_cli.rs                 (328 lines)  — LDK Server client for Lightning operations (via ldk-server-cli binary)
src/metrics.rs                 (938 lines)  — Prometheus-compatible metrics for node health, Nostr messaging, protocol ops
src/nostr.rs                  (3258 lines)  — Nostr transport for P2P messaging (NIP-04 DMs, public events, ledger addressing)
src/wallet.rs                 (1763 lines)  — BDK wallet for on-chain reserves management (UTXOs instead of commitment outputs)
```

### src/bin/

```
src/bin/deposits-node.rs      (6547 lines)  — Main deposits-node CLI daemon (BDK reserves + Nostr messaging)
src/bin/deposits-wallet.rs    (4435 lines)  — Depositor wallet CLI (discover operators, open deposits, manage balances)
src/bin/htlc-agent.rs         (2124 lines)  — HTLC agent for cross-ledger and Lightning payment routing
src/bin/nostr-bench.rs         (143 lines)  — Microbenchmark for nostr-sdk overhead components
src/bin/nostr-ping.rs          (462 lines)  — Nostr ping test using real Deposits protocol messages (latency measurement)
src/bin/transfer-simulator.rs (2310 lines)  — Rust transfer simulator (replaces Python payment-simulator's transfer loop)
```

### src/cli/

```
src/cli/mod.rs                  (12 lines)  — CLI modules root (common, handlers, nostr_commands, recovery)
src/cli/common.rs              (149 lines)  — Common CLI utilities (key derivation, config parsing, ledger ID resolution)
src/cli/handlers.rs           (1171 lines)  — Request handlers for Nostr-based ledger requests
src/cli/nostr_commands.rs     (2926 lines)  — Nostr CLI commands for ledger operations
src/cli/recovery.rs           (4028 lines)  — Recovery CLI commands (dispute resolution and custody recovery)
```

### src/node/

```
src/node/mod.rs                (427 lines)  — Node struct tying together wallet, nostr, and lightning
src/node/auto_tasks.rs         (600 lines)  — Auto-response tasks (auto-complete funded deposits, etc.)
src/node/coordination.rs       (851 lines)  — Coordination helpers (find ledger for offer, etc.)
src/node/dispute.rs           (1943 lines)  — Dispute handling (auto-arm, fork ledger, publish DisputeEnter/Armed)
src/node/inbound.rs           (1046 lines)  — Inbound Nostr request handling (resolve IDs, filter own events)
src/node/init.rs               (374 lines)  — Node initialization (create wallet, nostr transport, load ledgers)
src/node/ledger_queries.rs    (1828 lines)  — Ledger query operations (auto-rotate winnings to quorum Taproot)
src/node/main_loop.rs         (1890 lines)  — Main event loop (start listening, subscribe, process messages)
src/node/operations.rs        (1372 lines)  — Node operations (collateral obligation limit checks, transfers)
src/node/request_handlers.rs  (4544 lines)  — Request handlers for deposit_open, withdraw, transfer, invoice, etc.
```

### tests/

```
tests/audit_validation_test.rs  (231 lines)  — Node-level audit validation tests (obligation limits, timeouts, descriptor sizes)
tests/gift_wrap_test.rs          (271 lines)  — Gift-wrapped wallet<->node communication tests (NIP-59 structure)
```

### Other files

```
Cargo.toml                     (103 lines)  — Package manifest (deps: bdk, nostr-sdk, deposits-core, tokio, clap)
build.rs                         (9 lines)  — Build script to embed build timestamp
Dockerfile                      (44 lines)  — Slim Rust build for deposits-node binary
COSIGN_ARCHITECTURE.md         (302 lines)  — Cosign data flow architecture documentation
SPEC.md                        (527 lines)  — Bitcoin Deposits implementation specification (draft v0.2)
```

---

## deposits-tools

Tooling, test binaries, integration tests, Docker infrastructure, and operational scripts.

### src/

```
src/lib.rs                       (5 lines)  — Crate root; re-exports network_config
src/network_config.rs          (238 lines)  — Network configuration for test/demo nodes (Regtest, Mutinynet)
```

### src/bin/

```
src/bin/decode-updates.rs      (321 lines)  — Decode SignedLedgerUpdateLog entries from SQLite (hex or base64 input)
src/bin/deposits-lnurl.rs      (485 lines)  — LNURL-pay gateway (LUD-06/LUD-16 -> deposits-node make_invoice via Nostr)
src/bin/discover.rs            (325 lines)  — Discover operators and quorum topology from local JSONL ledger data
src/bin/replay-ledger.rs      (2759 lines)  — Replay ledger chain: fetch updates, walk backward, play forward, pretty-print
src/bin/standalone_reserves_demo.rs (536 lines) — Standalone reserves output demo (mock types)
src/bin/treasury-address.rs     (75 lines)  — Derive treasury address from hex seed file
src/bin/treasury-send.rs       (707 lines)  — Treasury wallet send utility for Mutinynet (fund nodes, reclaim seeds)
```

### tests/

```
tests/audit_ledger_hash_chain.rs       (251 lines)  — Audit ledger hash chain validation (prev_hash == previous new_hash)
tests/invoice_tracking_test.rs         (484 lines)  — Invoice tracking (add on cosign, remove on credit, index sync)
tests/ledger_consolidation_test.rs     (549 lines)  — Unified ledger storage with LedgerRole (Operator, Partner, Auditor)
tests/ledger_hash_test.rs             (169 lines)  — Ledger hash commitment transaction integration tests
tests/ledger_sync_test.rs             (415 lines)  — Ledger sync: operator/partner produce identical hash chains
tests/nip17_gift_wrap_test.rs         (545 lines)  — NIP-17 gift wrap encryption (create -> transmit -> unwrap)
tests/nip44_test.rs                   (508 lines)  — NIP-44 v2 encryption test vectors from official test suite
tests/payment_status_test.rs          (161 lines)  — Payment status types for same-node transfers
tests/quorum_member_test.rs           (837 lines)  — Quorum member management via ledger updates (add, remove, attest)
tests/recovery_handler_test.rs        (351 lines)  — Recovery handler integration (votes, non-conformance, claim signing)
tests/reserves_holding_cell_test.rs   (412 lines)  — Reserves holding cell pattern (concurrent updates, race prevention)
tests/uncredited_payment_test.rs      (336 lines)  — Uncredited payment accusation (serialization, preimage verification)
```

### bin/ (shell scripts)

```
bin/_common.sh                (1085 lines)  — Common functions for test scripts (shared helpers, sourced by others)
bin/discover.sh                  (7 lines)  — Wrapper for the discover binary (operator/quorum topology from Nostr)
bin/flamegraph.sh               (74 lines)  — Capture CPU profile from running deposits-node containers (pprof-rs)
bin/gen-tlv-catalog.sh          (47 lines)  — Generate wallet/tlv-catalog.js from deposits_protocol.ksy
bin/health.sh                   (35 lines)  — Show ledger health for all running operator nodes
bin/htlc-agent.sh               (20 lines)  — HTLC Agent CLI wrapper
bin/ldk-cli-wrapper.sh         (332 lines)  — LDK CLI wrapper with self-pay support (subwallet approach)
bin/ldk-cli.sh                  (27 lines)  — Wrapper for ldk-server-cli (talks to shared lightning container)
bin/ln-faucet.sh                (60 lines)  — Lightning faucet (pays BOLT11 invoice via shared LDK node)
bin/nip05-register.sh           (49 lines)  — Register a user in the fake NIP-05 service
bin/node.sh                     (56 lines)  — Wrapper for running deposits-node commands inside Docker containers
bin/nostr-broadcast.sh          (78 lines)  — Broadcast ledger updates to Nostr relay
bin/nostr-updates.sh           (130 lines)  — Show ledger updates from Nostr relay
bin/redeploy.sh                (124 lines)  — Redeploy nodes with new code, preserving all data
bin/reinit-lightning.sh        (136 lines)  — Reinitialize full test network with Lightning node
bin/reinit.sh                  (129 lines)  — Reinitialize test network (teardown, rebuild, setup-4op)
bin/replay-ledger.sh            (22 lines)  — Wrapper for replay-ledger binary (pretty-print ledger state)
bin/reserves-scripts.sh         (32 lines)  — Show reserves UTXO scripts (full Taproot details)
bin/setup-4op-lightning.sh     (256 lines)  — Four-operator setup with shared Lightning node
bin/setup-4op.sh               (591 lines)  — Multi-operator setup (N operators, reserves, ledgers, quorum, collateral)
bin/setup-htlc-agent.sh        (377 lines)  — Set up HTLC agent (open deposits on every ledger, fund, start)
bin/setup-lnurl.sh              (78 lines)  — Start the LNURL-pay gateway for deposits
bin/setup-nip05-certs.sh        (55 lines)  — Generate self-signed TLS certs for test NIP-05 server
bin/setup-scale-lightning.sh   (591 lines)  — Scalable 12-operator setup with LDK Lightning sidecars (ring topology)
bin/setup-scale.sh             (561 lines)  — Scalable N-operator setup (default 24, semi-random quorum membership)
bin/setup-verifier.sh          (112 lines)  — Set up lightning-verify service and NIP-05 test server
bin/start-operators.sh          (92 lines)  — Start operator watch processes for all nodes
bin/test-bridge.sh             (124 lines)  — Test Lightning bridge between deposit nodes and LDK sidecars
bin/test-dispute-4op.sh       (1111 lines)  — Four-operator dispute protocol test (with on-chain lottery)
bin/test-lightning-deposits.sh (746 lines)  — Lightning payments through deposits end-to-end test
bin/test-lightning.sh          (161 lines)  — Lightning test for shared LDK node + self-pay wrapper
bin/test-quorum.sh            (1507 lines)  — Four-operator x three-ledger quorum test (12 ledgers, 3 members each)
bin/transfer-simulator.sh       (18 lines)  — Wrapper for Rust transfer-simulator binary
bin/txns.sh                    (176 lines)  — Show transactions (non-coinbase)
bin/updates.sh                  (87 lines)  — Show ledger updates for nodes (terse format)
bin/wallet.sh                  (277 lines)  — Wrapper for deposits-wallet CLI
```

### bin/ (Python scripts)

```
bin/decode-update.py           (567 lines)  — Decode and annotate a SignedLedgerUpdate TLV blob (hex dump)
bin/generate-topology.py       (201 lines)  — Generate deterministic network topology for N operator nodes (JSON output)
bin/payment-simulator.py      (2188 lines)  — Payment simulator driving wallet.sh for real ledger activity
bin/strfry-exporter.py         (192 lines)  — strfry Prometheus exporter (event counts by kind via strfry scan)
bin/throughput-test.py         (143 lines)  — High-throughput transfer test using existing deposits
bin/ts-run.py                   (21 lines)  — Timestamp wrapper (prefixes output lines with elapsed seconds)
bin/ws-ping.py                 (187 lines)  — Raw WebSocket Nostr ping test (relay latency without nostr-sdk overhead)
```

### docker/

```
docker/cluster-cli.sh           (67 lines)  — CLI wrapper for the 8-node cluster
docker/discover.sh              (95 lines)  — Discover operators and ledgers from Nostr relay advertisements
docker/entrypoint.sh           (125 lines)  — deposits-node standalone container entrypoint
docker/funds-report.sh         (288 lines)  — On-chain funds report (reserves UTXOs, amounts, quorum info)
docker/ldk-server-entrypoint.sh (47 lines)  — ldk-server container entrypoint (TOML config from env vars)
docker/lightning-verify-entrypoint.sh (6 lines) — Lightning verify container entrypoint
docker/lnurl-server-entrypoint.sh (6 lines) — LNURL server container entrypoint
docker/miner-entrypoint.sh     (17 lines)  — Bitcoin miner container entrypoint (regtest block generation)
docker/node-cli.sh              (52 lines)  — CLI wrapper for deposits-node in Docker containers
docker/open-deposit.sh         (131 lines)  — Open a deposit on a ledger as a customer
docker/slow-relay-entrypoint.sh (34 lines)  — Slow (durable) relay entrypoint (strfry + stream from fast relay)
docker/wallet-cli.sh           (586 lines)  — Lightweight deposits wallet CLI (standalone, seed-based, relay-connected)
docker/docker-compose.4op.yml  (160 lines)  — 4-operator overlay for docker-compose
docker/docker-compose.cluster.yml (280 lines) — 8-node regtest cluster (self-contained deposits network)
```

### config/

```
Cargo.toml                      (91 lines)  — Package manifest (deps: deposits-core, deposits-protocol, bdk, nostr-sdk, tokio)
Dockerfile                      (60 lines)  — Dockerfile for deposits-node nodes (builds CLI, runs it)
Dockerfile.ldk-node             (41 lines)  — Dockerfile for LDK Lightning sidecar (stock ldk-server from source)
Dockerfile.lnurl                (35 lines)  — Dockerfile for LNURL-pay gateway
docker-compose.yml             (323 lines)  — Infrastructure services (relays, bitcoin, miner; nodes run on host)
drop-ephemeral-policy.sh        (37 lines)  — Strfry write policy for slow relay (drops ephemeral kinds 20000-29999)
permissive-write-policy.py      (44 lines)  — Permissive strfry write policy (accepts all events)
prometheus.yml                  (59 lines)  — Prometheus config for deposits-node cluster (15s scrape interval)
mcp-config.json                  (N/A)      — MCP configuration
grafana/provisioning/dashboards/default.yml (12 lines) — Grafana dashboard provisioning
grafana/provisioning/datasources/prometheus.yml (11 lines) — Grafana Prometheus datasource
grafana/dashboards/deposits-node.json (N/A) — Grafana dashboard definition for deposits-node
config/strfry.conf               (N/A)      — strfry relay configuration
config/strfry-slow.conf          (N/A)      — strfry slow relay configuration
config/deposit_allowlist.txt     (N/A)      — Deposit access control allowlist
wallet/Dockerfile                (4 lines)  — Nginx container serving wallet web UI
wallet/serve.sh                  (6 lines)  — Serve wallet on localhost:8888 (ES modules need HTTP)
```

### Documentation

```
OPERATIONS.md                  (174 lines)  — Test network operations guide (relay architecture)
README.md                      (116 lines)  — Docker environment README
SPEC.md                        (419 lines)  — Implementation specification (draft v0.2)
doc/AUDITOR_RECEIVER_BUG.md    (263 lines)  — Bug report: incomplete audit logs
doc/AUDITOR_RECEIVER_BUG_RESOLUTION.md (148 lines) — Resolution status for auditor receiver bug
doc/AUDIT_BROADCAST_DEBUG.md   (100 lines)  — Audit broadcast debugging guide
doc/BUG_FIX_INCOMPLETE_AUDITS.md (266 lines) — Bug fix: incomplete audit logs for third-party auditors
doc/CLAUDE.md                    (2 lines)  — AI development guidelines
doc/COMMITMENT_SIGNATURE_INVESTIGATION.md (373 lines) — Commitment signature failure investigation
doc/DEPOSIT_ACCESS_CONTROL.md  (199 lines)  — Deposit access control system documentation
doc/ENVIRONMENT_SETUP.md       (112 lines)  — Turnkey environment setup guide
doc/LNURL_GATEWAY.md           (182 lines)  — LNURL-pay gateway documentation (lightning addresses for deposits)
doc/PLAN_LEDGER_SYNC.md         (87 lines)  — Plan to fix ledger divergence bug
doc/QUICK_START.md              (97 lines)  — Quick start guide for deposits environment
doc/RESERVES_IMPLEMENTATION_PLAN.md (307 lines) — Reserves integration implementation plan
doc/RESERVES_INTEGRATION_PLAN.md (451 lines) — Reserves output integration plan
doc/SKILL.md                   (125 lines)  — deposits-wallet skill documentation
doc/TODO.md                    (127 lines)  — Implementation status and TODO tracking
doc/ZERO_TOLERANCE_COMMITMENT.md (366 lines) — Zero-tolerance commitment update implementation
doc/architecture.md            (240 lines)  — LDK Node architecture overview
doc/constraints.md              (18 lines)  — Wallet verification constraints
doc/deposits.md               (1047 lines)  — Bitcoin Deposits protocol overview
doc/introduction.md             (51 lines)  — Bitcoin Deposits introduction (custodial wallet on Lightning)
doc/plan.md                   (2078 lines)  — Protocol implementation plan (LDK Node integration strategy)
doc/protocol.md                (369 lines)  — Technical specification v1.0
```

---

## Root

### Documentation

```
ARCHITECTURE.md               (1552 lines)  — System architecture and protocol specification (v1)
CUSTODY_LOTTERY.md              (249 lines)  — Custody lottery: on-chain dispute resolution
PROTOCOL.md                    (986 lines)  — Bitcoin Deposits protocol overview (collateral-secured verifiable ledgers)
WHITEPAPER.md                  (115 lines)  — Bitcoin Deposits whitepaper (abstract)
PLAN.md                         (56 lines)  — Release preparation plan
DEP-01.md                       (47 lines)  — DEP purpose and guidelines
DEP-02.md                      (319 lines)  — Ledger state model
DEP-03.md                       (89 lines)  — On-chain transactions
DEP-04.md                      (225 lines)  — Peer messaging
DEP-05.md                      (136 lines)  — Quorum and collateral
DEP-06.md                      (147 lines)  — Fraud proofs and recovery
DEP-07.md                       (67 lines)  — Fee schedules
DEP-08.md                      (118 lines)  — Deposits
DEP-09.md                       (93 lines)  — Transfers
DEP-10.md                       (95 lines)  — Payment channels
DEP-11.md                       (96 lines)  — Time obligations
DEP-12.md                       (92 lines)  — Delivery escalation
DEP-13.md                      (219 lines)  — Couriers
```

### Configuration

```
Cargo.toml                      (32 lines)  — Workspace manifest (members: deposits-protocol, deposits-core, deposits-node, deposits-tools)
rustfmt.toml                     (1 line)   — Rust formatting config (edition = "2021")
.github/workflows/ci.yml        (58 lines)  — CI workflow (push to main, pull requests)
.gitignore                       (N/A)      — Git ignore rules
.gitmodules                      (N/A)      — Git submodule configuration
.dockerignore                    (N/A)      — Docker ignore rules
```
