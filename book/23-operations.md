# Chapter 23: Operations and Mainnet

> **Audience**: operators, integrators
> **Prereqs**: chapters 4, 7, 11, 12, 19, 20
> **DEPs**: none directly

## Why this chapter exists

Up to here the book has been about the protocol — what the rules are, how the pieces fit, where in the source code each rule lives. This chapter is about *running* it. If you intend to be an operator, you are going to spend most of your time not on the parts the previous chapters cover but on bitcoind syncs, TLS renewals, Lightning channel rebalancing, on-call rotations, and the dozen-and-one failure modes that show up only when real money is moving across a real network.

The reference deployment is `deposits-tools/bin/setup.sh`. That script's job is to give you a regtest cluster in a couple of minutes. A mainnet deployment looks superficially similar — same daemon, same wire format, same actor model — but with every operational shortcut taken back out. This chapter is the diff.

We start with what an operator actually runs, walk through the infrastructure it sits on, talk about how a cluster comes up, and then spend most of the remaining pages on the things that distinguish production from regtest: real reorgs, real fees, real Lightning channels, real key custody, real monitoring, real failure modes. The authoritative reference is [`MAINNET_DEPLOYMENT.md`](../MAINNET_DEPLOYMENT.md) at the repository root; this chapter teaches around it.

## What an operator runs

A single operator is a few cooperating processes:

- The **`deposits-node` daemon** itself. One process per operator, owning one or more ledgers, running the actor pool from [Chapter 20](20-the-daemon.md), exposing a localhost RPC and Prometheus port. This is the only piece the protocol cares about; everything else is context the daemon needs to do its job.
- A **Lightning node** alongside, if the operator offers Lightning bridging (most do — Lightning credits and withdrawals are the high-velocity operations). The reference deployment uses LDK; any compatible implementation works. The operator's daemon talks to the Lightning node over a local socket or HTTP API to issue invoices and pay them.
- A **Bitcoin Core full node** the daemon can read on-chain state from. Pruned is acceptable as long as retention covers the longest possible dispute window (102 blocks for confiscation, plus whatever the operator's longest pending obligation is — call it 1000 blocks of margin to be safe).
- An **electrs** instance (or any compatible esplora-API implementer) sitting on top of bitcoind. The daemon's BDK wallet uses esplora HTTP to sync UTXOs; bitcoind's RPC is not on the BDK code path.
- One or more **Nostr relay subscriptions** (typically two). The protocol uses Nostr as its message bus, not as a coordinator — relays just store and serve events.
- The operator's **on-chain wallet**. This is integrated into the daemon (BDK-backed, in `deposits-node/src/node/wallet.rs`). The wallet is derived from the operator's seed, syncs from electrs, and signs reserves rotations and confiscation transactions.

That's a single operator. A network is a few of these talking to each other through the relay layer. There is no central coordinator, no leader, no consensus protocol above the relay. Every operator runs its own infrastructure and discovers others through ledger advertisements (Nostr `Kind:39100`) and explicit out-of-band introductions during quorum formation.

## Recommended infrastructure

A typical mainnet operator deployment sits on roughly the following stack:

**Bitcoin Core full node.** A dedicated host with eight cores, 32 GB of RAM, and 1 TB SSD is comfortable; smaller works if you prune aggressively. Initial sync against mainnet takes one to four days depending on bandwidth. `-txindex` is required because electrs needs it. `-rpcuser` and `-rpcpassword` should be locked to your private network — never expose RPC to the internet.

**Electrs.** Mempool's `electrs` is the reference implementation; alternatives like Blockstream's electrs or romanz/electrs work too. Electrs's own initial index runs after bitcoind's IBD finishes and takes another two to four hours. The daemon talks to it as `--esplora https://esplora.example.com`. Until the index is caught up, the daemon's wallet sync sees an empty chain and the BDK-backed wallet returns zero balances.

**strfry as the Nostr relay.** The protocol uses two relays in the canonical deployment:

- A **durable ledgers relay** that retains `Kind:9100` (ledger updates), `Kind:9101` (fraud broadcasts), `Kind:9103` (cosignatures), `Kind:9106` (lottery reveals), `Kind:39100` (ledger advertisements), and `Kind:55502` (attestations) forever. This is where the audit trail lives.
- A **messaging relay** that handles ephemeral events — request/response pairs (`Kind:20100`/`Kind:20101`), cosign requests, balance queries — and drops them after sixty seconds.

Both run strfry. The split is operational, not protocol-level: you can run them on one host with two ports, or on two separate hosts. What matters is that the durable relay actually retains, the messaging relay actually drops, and both are reachable from every operator and every wallet that needs to interact with you.

For a real deployment, put strfry behind nginx with TLS termination. Wallets and Lightning attestations expect `wss://` URLs, and several mobile wallets refuse plaintext WebSocket. A typical nginx config proxies `wss://relay-ledgers.example.com` to `127.0.0.1:7777` where strfry is bound to localhost.

**Lightning node.** The reference implementation embeds an LDK regtest node for testing, but on mainnet you provision Lightning the same way any other Lightning service does: open channels with peers chosen for their reliability and inbound liquidity, fund the node with enough working capital to cover expected payment volume, and monitor for force-closes. The daemon's Lightning hooks (`InvoiceCredit`, `InvoiceLock`, `InvoiceFulfill`, `InvoiceFail`) all bottom out in calls to your Lightning node's API; the operational side of *that* node — channel management, fee policy, peer selection — is outside the deposits protocol but very much your concern.

Plan capacity per ledger. If your largest deposit is going to be 0.5 BTC and you expect Lightning withdrawals to that scale, your channel inbound liquidity needs to be at least that much, and your channel outbound liquidity needs to cover deposits coming in. Liquidity imbalance is the most common reason a deposits-node Lightning operator runs out of capacity mid-day; rebalancing tools (Loop, `lnd-manageJ`, BOS) are essentially compulsory equipment.

## Bringing a cluster up

`setup.sh` is the regtest template. It has four phases, and the order matters on mainnet too:

1. **Bitcoin and electrs.** Start bitcoind, wait for `verificationprogress > 0.999`, then start electrs and wait for its tip to match. Until both are synced the daemon will see an inconsistent chain.
2. **Relays.** Start strfry on both ports (or both hosts). Verify TLS certs are valid by connecting from outside the bastion network: `wscat -c wss://relay-ledgers.example.com` should produce the relay's `RELAY` info reply.
3. **Daemons.** One per operator. The daemon needs `--seed-file`, `--esplora`, and `--relay` flags pointing to the infrastructure above. On first start it loads no ledgers (because none exist yet); it just opens its relay subscriptions and parks.
4. **Per-ledger bootstrapping.** For each ledger you intend to operate:
   - **Fund the operator's reserves UTXO** via on-chain transaction from a separately-funded wallet. Wait for six confirmations.
   - **`deposits-node reserves create --amount-sats <total>`** — the daemon constructs a Taproot reserves output combining reserves and collateral capacity.
   - **`deposits-node ledger open --reserves-amount <r> --collateral-amount <c>`** — the daemon emits a `LedgerOpen` operation creating the ledger.
   - **`quorum add`** for each prospective member's pubkey — the operator stages members by pubkey and ledger ID. Members do not need to be online yet, but they will need to come online before the next step.
   - **`quorum begin`** — broadcasts the rotation transaction on-chain, waits for confirmations, runs the cosign round, and commits the `QuorumBegin` update. After this lands the ledger is *active* and accepting deposits.

On mainnet, doing these manually is a feature: each step is a checkpoint where you confirm the on-chain state matches your expectation before continuing. `setup.sh` automates them for regtest because regtest doesn't punish you for haste.

## Production differences from the test setup

Everything `setup.sh` skates over becomes a real concern on mainnet.

**Real network.** Relays are publicly addressable, behind TLS, exposed on registered domains. Operator daemons bind their RPC and metrics ports to localhost, behind a firewall, never to public IPs. The only surface area an operator exposes to the internet is the Nostr relays they advertise on — and those are typically run by someone else. If you operate your own relays, lock down the write side (strfry's default doesn't rate-limit; for a public-facing deployment add `dropEventsByPubkey` filtering or a write-side proxy gating on operator pubkeys).

**Real Bitcoin.** Mainnet has reorgs. Small ones — one to two blocks — are routine. The protocol's block-anchor verification (used by `UncreditedOnchainPayment` and `InactiveQuorum` fraud proofs) requires the anchor block to be in the verifier's chain, and a reorg can briefly invalidate a fraud proof. Quorum members should re-attempt verification after the new tip stabilizes; the daemon does this on its own in the verifier path, but the bug to watch for is acceptance of an anchor based on a transient tip the verifier hasn't yet seen the orphan of.

Confirmation depths must also be set against real reorg risk. Regtest confirms instantly; mainnet's twelve-block depth for confiscation TXs and 102-block window for `block_height_anchor` checks are not adjustable. Plan around them: the dispute pipeline is not fast, by design.

**Real Lightning.** Liquidity management is a continuous operational concern. Channels need to be opened, sized for expected throughput, monitored for force-closes, and periodically rebalanced. A deposits-node operator who runs a single channel with a large LSP gets simplicity at the cost of single-counterparty risk; one who runs ten smaller channels with diverse peers gets resilience at the cost of more management overhead. There is no protocol opinion here — just the same Lightning operations work any other LSP does.

**Multiple ledgers per operator.** This is the most consequential mainnet shape change. The protocol's network-level safety property — that a 49% coalition cannot profitably attack — depends on operators running *multiple ledgers* with *independent quorums*. The simulation in the whitepaper assumes 3 to 5 ledgers per operator. Running a single ledger as your only operation is supported, but it leaves money on the table and weakens your contribution to the network's overall safety.

Each ledger has its own reserves UTXO, its own collateral, its own quorum, its own ledger ID. The same operator pubkey can be the parent of all of them. Wallets discover them as separate ledgers via separate `Kind:39100` advertisements. If a fraud proof fires against one of them and the recovery pipeline takes that ledger's collateral, your other ledgers are *unaffected* — they have their own UTXOs, their own quorum members, their own histories. That is the point. A coalition that wants to compromise you economically has to compromise every one of your ledgers' quorums separately, and the multiplicative cost is what makes 49% coalitions unprofitable.

**Quorum independence.** The wallet's job is to evaluate whether the quorums backing your ledgers are actually independent. The metric the whitepaper points at is *vertex connectivity*: in the graph whose vertices are operators and whose edges represent "trusts via attestation," what is the minimum number of vertex-disjoint paths from the wallet's trusted anchors to your quorum members? If two of your ledgers share most of their members, attacking those members compromises both — the ledgers are *graph-coupled* even though they are protocol-independent.

The operator-side analog is: when you form a quorum, pick members whose own quorums don't all share members with each other. Members of *your* ledger run *their* ledgers, and *their* members are also somebody. A graph search starting from your candidate members and walking out two or three hops gives you a ballpark of how independent your effective backing is.

## Persistent state and backups

The daemon's data directory is a small set of files, every one of which the operator must back up regularly:

- **`wallet/ledgers/<ledger_id>.jsonl`**, one per ledger. The append-only signed history. This is the recovery substrate: with these files plus the operator seed, the daemon can rebuild state at startup. It is also forwardable — a quorum member can ask another member for a `<ledger_id>.jsonl` to catch up.
- **`wallet/ledgers/<ledger_id>.actor.log`**, the actor's shadow file. Best-effort, regenerable from the JSONL. Used during the actor migration (see [Chapter 20](20-the-daemon.md)) for cross-checking.
- **`wallet/reserves.json`** and **`wallet/taproot_reserves.json`**, the operator's UTXO references — outpoints, descriptors, lottery output info.
- **`confiscated_*.marker`** files, the dispute outcomes the operator has observed.

A daily tarball is enough:

```bash
0 3 * * * tar czf /backup/$(date +%Y-%m-%d)-deposits.tgz /var/lib/deposits-node/wallet/
```

Test the restore path before you need it. Bring up a clone host, restore the tarball, point the daemon at the same seed, watch it sync from the relay and reach the same `chain_tip_hash` as the live operator. If it doesn't, the gap is in your backup procedure.

The **operator seed** is more important than the data directory. Lose the data and you can rebuild from the relay (and from your members, who hold copies of every cosigned update). Lose the seed and you have lost the operator's role on every ledger you parent — the other quorum members can dispute and acquire custody, but you walk away with slashed collateral and a multi-day painful recovery. Treat the seed like the operator's BIP-39: KMS, HSM, or at minimum encrypted-at-rest with a passphrase that is not stored on the same machine.

The other state in the daemon — pending invoice maps, processed-events sets — is recoverable from chain plus relay if lost, but its loss is inconvenient. The cost of keeping it backed up is negligible, so back it up.

## Monitoring

The daemon exports Prometheus metrics on port `9100 + op_idx`. The first operator binds 9100, the second 9101, and so on; this matches `setup.sh`'s convention and lets a single Prometheus scrape the entire cluster on a small mainnet sandbox without port collisions. On real deployments the operator-index numbering doesn't apply — pick whatever local port works — but the metric names are network-independent.

The metrics that actually pay for themselves:

- **Histograms** for `commit_operation`, `request_cosign`, `sign_and_broadcast`, `handle_ledger_update`, and `persist_ledger_to_disk`. The first three tell you how long an operation takes from staging through cosign through broadcast. p95 latencies climb when members are slow to respond or when relay round-trips are degrading. p99 climbing without p50 climbing usually means a tail of slow members; both climbing means something systemic.
- **Stale-joined-ledgers gauge.** A ledger that hasn't seen an update in some threshold despite the daemon being subscribed. Climbs when the daemon's Nostr subscription has silently disconnected.
- **Cosign-timeout counter.** Increments on every cosign request that didn't reach majority within the deadline. Should be near zero in steady state.
- **Reserve balance gauge.** From the BDK wallet. Should match the reserves portion of the on-chain UTXO; divergence means the wallet's view of chain is broken.
- **Block-height lag.** Daemon's last-seen tip versus electrs's tip. Brief spikes during reorgs are normal; sustained lag means the wallet sync is degraded.

The daemon also supports per-call flamegraphs via the `TRACING_FLAME_PATH` env var. Set it to a writable file path before starting the daemon and the `tracing-flame` integration emits per-span timings. Useful for debugging a specific slow path; leave it off in steady state because it costs CPU.

For dashboards, the regtest deployment in `deposits-tools/grafana/dashboards/` covers request rates, cosign latency, ledger-update flow, and run-loop phase breakdowns. Metric names don't depend on the network, so the dashboards work unchanged on mainnet.

The alerting checklist at minimum:

- Operator daemon down (`up == 0` on the metrics endpoint for more than sixty seconds).
- Cosign timeout rate above zero.
- Relay disconnect (Nostr connection counter flatlines).
- Block-height lag above three blocks.
- Reserves UTXO unconfirmed (the operator's view of its own UTXO drops out of mempool).
- BDK wallet sync failures — the wallet logs an explicit error, scrape it.
- **DisputeArmed observation on any ledger you parent.** This is the operator's red-light alarm. If a member of one of your quorums has armed a dispute on you, you have minutes to respond before the lottery starts and the loss-of-collateral cycle begins. If you can't be online that fast, you need somebody on call who can.

## Operational threats

The protocol's threat model is in [SECURITY.md](../SECURITY.md). The operational subset — threats you address with deployment choices, not with protocol design — is shorter.

**Dispute response.** When a fraud proof against a ledger you parent arrives, the recovery pipeline starts. If you are online and the proof is wrong (false positive, or a member trying to opportunistically fork), you can defend by producing the missing evidence or a counter-proof. If you are offline or slow, the pipeline runs without you and you lose the ledger.

The deployment pattern that seems obvious — multiple daemons sharing a data directory for HA — is dangerous. The actor model (Chapter 20) makes the per-ledger actor the single writer; running two daemons against the same data directory means two actors per ledger, each thinking it's the writer, racing to commit conflicting updates. Use a *single daemon plus active failover* instead: one daemon running, hot, with monitoring; if it dies, a runbook brings up a replacement on a standby host pointed at a restored copy of the data directory. The failover window is downtime, not data loss; that's an acceptable tradeoff.

**Quorum member responsiveness.** A cosign needs ⌊Q/2⌋+1 members to succeed within the cosign deadline (`request_cosign` in `coordination.rs`). If your members are slow, your operator throughput suffers; if your members are unreachable, your operator stalls. SLAs for member responsiveness are part of the quorum-formation negotiation: how fast do you commit to cosigning, what is the maximum offline window, how is downtime announced. The protocol does not enforce these — they are social commitments — but breaches of them are the natural reason to rotate a member out (`QuorumRemoveMember`) and add another in.

**Lightning theft risk.** Covered in [Chapter 9](09-payment-channels.md). The Lightning trust boundary is not the same as the on-chain trust boundary: the on-chain side has cosigned offers and block-height anchors, so a unilateral steal is a fraud-proof pattern; the Lightning side has only cooperating-payer fraud proofs, which a rational selective attacker can avoid by only stealing from payers unlikely to cooperate. Make sure your LN node is well-funded and well-monitored, but recognize that the protocol's deterrence on Lightning is weaker than on-chain.

## Security operations

The operator key signs every update. There is no "cold key" you can isolate; the active operator is, by necessity, an online signer. What this means in practice:

- The operator key should never live in user-shell memory or on the command line. The reference deployment uses `--seed-file /run/secrets/op-seed.hex` with `chmod 0400` and a dedicated unprivileged service user. Better is a remote signer (e.g., an HSM that the daemon RPCs to for signing operations); the daemon's signing layer is structured so a remote-signer adapter is a clean addition.
- The operator key controls the BDK wallet, the Nostr identity, and the ledger-signing key. They are derived from the same seed via different BIP-32 paths. A leak of the seed leaks all three; a leak of any of the derived keys does not (yet) leak the others, but the protocol does not currently use that compartmentalization.
- File permissions on the data directory should be mode `0700` for the directory and `0600` for files. The seed file is `0400`. Backup tarballs inherit these permissions and should be stored encrypted at rest.

Read [SECURITY.md](../SECURITY.md) end-to-end before going live. The list of "likely mistakes implementors will make" in that file is the index of footguns the protocol can't or doesn't fully guard against.

The **mainnet deployment checklist**, distilled from [`MAINNET_DEPLOYMENT.md`](../MAINNET_DEPLOYMENT.md):

- Bitcoin Core synced (`verificationprogress > 0.999`).
- Electrs index caught up (`/blocks/tip/height` matches `getblockcount`).
- Both relays reachable over WSS from outside the bastion network.
- TLS certs renewed and renewal scripted (Let's Encrypt with certbot; test the renewal once before going live).
- NTP running on every operator and relay host (Nostr events are timestamped; ±15-minute drift means events get rejected).
- Operator seed in KMS or encrypted-at-rest.
- Daemon running as a systemd service with `Restart=on-failure` (the regtest setup runs daemons as backgrounded shell processes; that is a sandbox shortcut, do not carry it to mainnet).
- Metrics port firewalled to localhost.
- Backups scheduled and the restore path verified.
- Alerting wired up.
- Funding wallet ready with a small amount of real BTC for reserves UTXOs and transaction fees.

## Fee policy and economics

Operators set fees per ledger via the `FeeChange` operation, subject to the per-deposit fee schedule's `fee_change_limit_bps` cap and `fee_change_notice_blocks` notice period. Quorum members enforce a minimum-fee floor (the `quorum_policy.rs` member-minimum-fee guards) — they refuse to sign fee changes that would drop fees below their negotiated floor, on the theory that operators who undercharge eventually fail and take their members down with them.

Fee income accrues to the operator's reserves UTXO over time. Periodic *fee assessment* operations (`FeeAssessment`) move accrued per-block fees from deposit balances into the operator-controlled portion of the reserves accounting. To get fee income off-ledger and into a separately-managed treasury, use the `treasury-address` and `treasury-send` helpers from `deposits-tools`:

- `treasury-address` derives a target address (typically a cold wallet) for sweeping fees to.
- `treasury-send` constructs a withdrawal that moves an operator-controlled amount out of the reserves UTXO to that address. Members cosign because the withdrawal stays within the operator's collateral-respecting bounds.

The periodic cadence depends on volume. A high-throughput operator might sweep weekly; a small operator might sweep monthly. Sweeping more often than that wastes on-chain fees on the rotation transaction; sweeping less often concentrates fee income inside the operating UTXO where a successful dispute would forfeit it.

**Pricing intelligence** is a relay-monitoring exercise. Every operator's `Kind:39100` ledger advertisement includes their per-operation fee schedule. Subscribing to all such advertisements gives you a real-time picture of competitor pricing. The `discover` helper in `deposits-tools` is the wallet-side primitive; an operator-side dashboard that scrapes the same data is straightforward to build and well worth the day of work.

## Upgrade paths

The protocol is pre-release, and wire-format breaks have happened. The `DisputeAcquire` operation's shape changed during the collateral-in-UTXO transition; `QuorumBegin`'s txid byte-order convention has caused cosign verifier mismatches more than once (see the `project_phase4_cosign_blockers.md` memory note for the latest debug). A coordinated upgrade across a quorum is a real operational event, not a routine patch.

The discipline:

- **Operators must agree on protocol version before flipping over.** A quorum where some members have upgraded and others haven't will see cosign failures (verifier rejects what the writer produced) until everybody is on the same version.
- **Stage upgrades during low-traffic windows.** Take one operator down, upgrade, bring it back, watch its peers. Repeat. The protocol does not require a synchronous flag day; the wire format of a *given operation* is what must be agreed on, and operations land sequentially. But correlated upgrade is the conservative option.
- **Test on regtest first, on a freshly-set-up cluster, with at least one cross-version pairing.** Tier-3 tests catch wire-shape regressions; run them.
- **Hold the line on hash-chain compatibility.** A wire-format change that alters the bytes signed over for `previous_hash` or `current_hash` is a hard fork — the chain after the change cannot be validated by software that only knows the old format. Such a change should be a major version bump and should never happen silently.

## Failure modes and runbooks

The recurring shapes of "the cluster is broken, what do I do":

**"My daemon won't start."** Common causes: (1) port conflicts with the metrics port — pick a unique `--metrics-port` per operator on shared hosts. (2) The seed file isn't readable by the service user — check `chown` and `chmod`. (3) BDK wallet corruption — rare, but if the wallet's SQLite database is corrupt the daemon refuses to start; restore from backup, or in extreme cases delete the wallet directory and let it re-sync from the seed (the operator state in `wallet/ledgers/` is preserved). (4) Relay unreachable — the daemon waits for at least one relay subscription before it considers itself up; if both relays are down it logs and parks.

**"Cosign timeouts."** "Cosign timeout: 0/N cosigs in 5000ms" hides several distinct bugs. Members may not be subscribed to the operator's ledger after a recent `QuorumJoin`; check their subscription state. The txid byte-order between writer and cosign verifier may be flipped (regression source — there is a memory note tracking the Phase 4 quorum_begin variant). Members may be slow because their relay round-trip is degraded. Or they may simply be offline. Reading the per-member cosign request log on the operator side and matching it against the inbound log on the member side will localize the gap.

**"Funds appear stuck."** A deposit shows a balance but the wallet can't transfer or withdraw. Possible causes: (1) a pending operation is locking the balance — check the deposit's `locked_balance` and the list of in-flight transfers/invoices. (2) An unresolved dispute on the ledger has blocked progress — a `DisputeArmed` state freezes new operations until acquire or yield. (3) Wallet lock contention if multiple wallet processes hold the same deposit's spending authority. The diagnostic is `deposits-wallet info <deposit-id>`; the failure mode is usually visible in the response.

**"Confiscation didn't fire."** A dispute reached `DisputeArmed` but no on-chain confiscation transaction appeared. The dispute pipeline (Chapter 12) reaches `MaybeConfiscate` but stalls; usually a missing UTXO descriptor (the daemon doesn't know how to spend the lottery output because the rotation phase didn't complete its descriptor write) or a block-height stamp issue (`block_height_anchor` in the dispute record doesn't match a block in the daemon's chain view). Check the daemon's dispute log, find the stalled stage, and read the cause out of the error message — they're explicit.

## Cost model

Rough order-of-magnitude operator costs:

**On-chain.** Reserves rotation is the dominant expense. A rotation tx is large (Taproot inputs and outputs, sometimes multi-input); at 50 sat/vB during normal-load periods, a typical rotation runs 20,000–40,000 sats. An operator running five ledgers and rotating each quarterly might spend a few hundred dollars a year on-chain. Confiscation TXs are exceptional but expensive when they fire — the loser eats the fee.

**Lightning maintenance.** Channel open/close fees plus periodic balancing. Numbers depend entirely on volume and channel topology; a small operator running ten channels with quarterly rebalancing might spend a few thousand dollars a year on Lightning ops.

**Relay hosting.** Marginal. Strfry on a small VPS handles any non-enormous deployment.

**Server hosting.** A single mid-tier VPS handles many operators' worth of daemon traffic. Bitcoin Core is the heavy workload, not the deposits daemon. Most operators co-locate the daemon with electrs and a slim relay alongside bitcoind, or on a sibling VPS in the same datacenter.

Total operating cost for a small mainnet operator running three ledgers comes in around $50–$200 per month, dominated by the bitcoind-host server. Fee income from a few-percent retainer on deposit and transfer activity covers this comfortably at any non-trivial volume.

## Discovery setup

For wallets to find you, you need to advertise. The mechanism is `Kind:39100` (ledger advertisement) — a parameterized replaceable Nostr event tagged with the operator's pubkey, the ledger ID, the reserves and collateral values, the fee schedule, and the relay set on which this operator reads requests. Wallets subscribe to `Kind:39100` events on whichever relays they trust and filter by parameters they care about.

To publish:

```bash
deposits-node ledger advertise \
    --name op-alpha \
    --advertise-relay wss://relay-ledgers.example.com
```

This walks the operator's ledgers and emits one `Kind:39100` per ledger. Re-advertise whenever the fee schedule or quorum changes. The replaceable-event model means the latest-published version is what wallets see.

Linking attestations is a separate step. The attestation service (Chapter 17) issues `Kind:55502` events binding a real-world identifier (DNS, Lightning address, social handle) to your operator pubkey. Wallets that find your `Kind:39100` advertisement can then look up your `Kind:55502` attestations as a separate query and gain confidence that the npub they're depositing to corresponds to a verifiable identity. Operators are not required to attest; running anonymously is permitted. But early-stage networks benefit from at least some operators being attested, because attestations are the bootstrap path into the web-of-trust scheme ([Chapter 18](18-ring-signatures.md)).

How wallets find you in practice: they speak to a discovery relay (one of the relays they're configured with), filter `Kind:39100` events on parameters they care about (network, minimum collateral, geography, attestation status), evaluate the resulting set against their independence metric (vertex connectivity to trusted anchors), and pick. The operator's job is to make sure the advertisement is accurate, current, and visible on relays the wallet population subscribes to.

## What stays in your head

Production deposits operations is mostly Bitcoin operations and Lightning operations under a thin protocol-specific layer. Most of the things that go wrong on mainnet are things that go wrong on any custodial Bitcoin service: bitcoind drift, Lightning illiquidity, channel force-closes, certificate expiry, NTP skew, bandwidth saturation, cron job failures. The deposits-specific concerns — quorum cosign timing, dispute response time, fee-change governance — sit on top of that base of standard Bitcoin operations work.

The two pieces of operational discipline that *are* deposits-specific:

1. **Be online when fraud proofs arrive.** The dispute pipeline does not wait. The DisputeArmed alarm has to wake somebody up. If your deployment can't guarantee that, you should be running with smaller per-ledger reserves and accepting more frequent custody changes as a cost of doing business.
2. **Run multiple ledgers with independent quorums.** Single-ledger operators are accepted by the protocol but contribute weakly to the network's safety. Three to five ledgers per operator with disjoint quorums is the deployment shape the simulation analyses assume.

Everything else is downstream of those two.

## Where this leads

The reference material lives in the appendices. [Appendix B](appendix-b-wire-format.md) is the wire-format reference, [Appendix C](appendix-c-error-codes.md) is the error-code catalog, and [Appendix D](appendix-d-configuration.md) is the configuration reference for `deposits-node`. For day-to-day operations, [`MAINNET_DEPLOYMENT.md`](../MAINNET_DEPLOYMENT.md) is the canonical step-by-step. For the threat model, [`SECURITY.md`](../SECURITY.md). For the protocol underneath, the DEPs.
