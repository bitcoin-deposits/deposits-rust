# Release Preparation Plan

## Completed

### Quality baseline
- [x] CI (GitHub Actions: fmt, clippy, test, build)
- [x] Workspace lint config with clippy/rust allows for deferred refactors
- [x] `cargo fmt` applied, `rustfmt.toml` added
- [x] All clippy warnings resolved (468 -> 0)
- [x] All test compilation errors fixed
- [x] `cargo test --workspace` passing (53 test suites)

### Dependency cleanup
- [x] Removed nostr-sdk-performance fork (use stock nostr-sdk from crates.io)
- [x] Removed strfry-performance submodule
- [x] Removed bdk_wallet from deposits-tools (only used bitcoin type re-exports)
- [x] Removed unused bdk_file_store from deposits-node
- [x] Single BDK version (v1.0 in deposits-node only)

### Code organization
- [x] Split deposits-node/src/node.rs (14.8K lines) into 10 focused submodules
- [x] Moved deposits-node/docker to deposits-tools/docker
- [x] Moved Docker entrypoint scripts from bin/ to docker/
- [x] Removed duplicate docker/setup-4op.sh
- [x] Strfry config templates moved to deposits-tools/config/

### Conformance tracking
- [x] ConformanceViolation enum, WitnessVerifier trait, NoVerify in deposits-protocol
- [x] apply_with_verifier() and check_and_apply() on LedgerState
- [x] CoreWitnessVerifier in deposits-core (real Schnorr/ECDSA verification)
- [x] Reserve sufficiency checks after credit operations
- [x] Witness verification for InvoiceLock, InvoiceFulfill, OnchainLock, TransferLock, CollateralLock

## In Progress

### Conformance integration
- [ ] Wire check_and_apply into operator's hot path (deposits-core/ledger.rs)
- [ ] Wire apply_with_verifier into partner/watcher path (deposits-node inbound.rs)
- [ ] Move dispute state checks from ledger.rs validate_operation() into check_conformance()

### Code cleanup
- [ ] Audit for duplicate/dead/misplaced code across crates
- [ ] Tighten deposits-core public API (currently re-exports ~150 items)

## Remaining

### Testing
- [ ] Add tests for deposits-node modules (highest priority: request_handlers, operations)
- [ ] Add witness verification tests through the full apply path
- [ ] Integration tests for conformance detection in watcher scenario

### Release prep
- [ ] Audit public API surface per crate
- [ ] Top-level README with build instructions
- [ ] Version crates (0.1.0)
- [ ] Changelog
