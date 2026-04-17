# Release Preparation Plan

## Completed

### Quality baseline
- [x] CI (GitHub Actions: fmt, clippy, test, build)
- [x] Workspace lint config with deferred-refactor allows
- [x] cargo fmt + rustfmt.toml
- [x] All clippy warnings resolved (468 -> 0)
- [x] All test compilation errors fixed

### Dependency cleanup
- [x] Removed nostr-sdk-performance and strfry-performance submodules
- [x] Removed bdk_wallet from deposits-tools, bdk_file_store from deposits-node
- [x] Removed 8 unused deps from deposits-tools (warp, prost, clap, etc.)
- [x] Single BDK version (v1.0 in deposits-node only)

### Dead code removal (~11K lines removed)
- [x] Removed 3 broken binaries (deposits-admin, network-init, status)
- [x] Removed LDK-era infrastructure: handler.rs, message_handlers (7 of 9 modules),
      message_processor.rs, channel_manager_ops.rs, reserves_proposal.rs
- [x] Removed dead traits: traits.rs (13 traits), handler_traits.rs, handler_types.rs,
      quorum.rs (QuorumManager), payment_tracker.rs
- [x] Removed dead Wire codec (WireEncode/WireDecode), stray binary, duplicate scripts
- [x] Removed deprecated recovery commands

### Code organization
- [x] Split node.rs (14.8K) into 10 submodules
- [x] Split types.rs (4.3K) into 5 submodules
- [x] Split messages.rs (5.8K) into 4 submodules
- [x] Split message_handlers.rs (5.6K) into modules (kept 2 of 9)
- [x] Split deposits-node.rs (6.5K) and deposits-wallet.rs (4.4K) into CLI modules
- [x] Consolidated docker/ and bin/ scripts, moved entrypoints

### Conformance tracking
- [x] ConformanceViolation, WitnessVerifier trait, NoVerify, CoreWitnessVerifier
- [x] apply_with_verifier(), check_and_apply(), check_conformance() on LedgerState
- [x] Reserve sufficiency + witness verification for all lock operations
- [x] DepositKeyRotate: verify witness against pre-apply descriptor
- [x] Wired into operator path (commit_staged uses checked_apply)
- [x] Wired into watcher path (inbound.rs logs violations)
- [x] Documented in PROTOCOL.md

### Testing (547 tests)
- [x] Fixed all 22 ignored test stubs
- [x] 54 new deposits-node unit tests (signing data, hash chains, Nostr types)
- [x] 12 internal tests for pub(crate) signing data builders
- [x] Integration test crate (tests/) with 23 end-to-end protocol tests
      (deposit lifecycle, quorum, dispute, transfers, conformance detection)

## Remaining

### Release prep
- [ ] Top-level README with build instructions
- [ ] Version crates (0.1.0)
- [ ] Changelog
- [ ] Update MANIFEST.md to reflect current state
