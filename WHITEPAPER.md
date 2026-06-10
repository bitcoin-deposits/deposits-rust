# bitcoin deposits
## abstract

an ideal peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another quickly and with minimal preparation. the lightning network provides part of the solution, but the essential benefits are lost if a trusted third party is required to manage state on your behalf. we propose a solution to this problem using verifiable ledgers and a web of collateral. operators broadcast ledger updates, each co-signed by a majority of an attesting quorum, creating an auditable record of accounts. wallets broadcast evidence of dishonesty to those peers, who ensure that the ledger maintains an honest operator. unilateral exit is replaced by the guarantee that funds remain available so long as the network does. we arrive at a network that delegates liquidity maintenance, avoids setup fees, is capable of receiving payments offline, and scales independently of the base layer

## introduction

bitcoin deposits aims to provide fast and scalable key controlled funds off-chain, secured by economic deterrence rather than unilateral exit. on-chain activity scales with the number of ledgers and frequency of reserves rotation. throughput scales slightly above linearly with the number of ledgers in the network, making millions of transactions per second across trillions of wallets plausible

there are explicit tradeoffs:
- no unilateral exit: when operators fail funds stay in the network
- no privacy: verification requires transparency
- intermittent availability: a deposit is only as available as the operator. wallets should spread out funds to increase availability
- liveness is part of the security model: safety against a misbehaving operator assumes a quorum majority that acts within fixed block windows

we expect the wallet experience to be similar to a fast base layer, having payment economics similar to the lightning network

## ledgers

a ledger is an immutable chain of updates, containing the hash of the previous update and signed by the ledger's operator. different types of update have different rules governing when and how they can be used. ledgers are self descriptive, their updates publicly available and non-repudiable, allowing anyone to evaluate conformance

once a quorum is established, every update must carry co-signatures from a strict majority of its members. each co-signer independently validates the operation against its own replica of the ledger state and verifies continuity from its own tip before signing. no two conflicting updates at the same height can both gather a majority — at least one member of any majority has already signed the other — so the co-signature rule is what makes the chain canonical, not the operator's signature alone

ledgers have a single active operator, but are cooperatively maintained by the mesh. any operator can create one, but should they disappear or become dishonest a different operator will be assigned, along with reserves. the currently active operator is identified by the pubkey that was used to sign the most recent co-signed update

## deposits

a deposit is a stable account that can send and receive funds, controlled by a dep-16 descriptor — a calculus generalizing miniscript to ledger-aware authorization. at opening a fee schedule is established, as well as whether receiving funds requires a wallet signed request. an operator must allow transfers between deposits on the same ledger as well as on-chain exits

it is in the operator's discretion to create on-chain funding offers on behalf of a deposit. if they do, these should be co-signed by a quorum member, and the wallet should verify this signature. offers and invoices are not part of the ledger, so it is the wallet's responsibility to verify signatures and retain them as evidence

## fees

transfers between deposits, on-chain, and through lightning have fees paid to the ledger's operator. there are also fees periodically applied to balances with a specified period. all are negotiated when a new deposit is opened. fees can be changed after a specified number of blocks, given a specified block notice and within a per-adjustment percentage limit negotiated at opening. lock-then-resolve operations charge the fixed portion of their fee even when the resolution is a failure, since the operator did real work holding the lock. the quorum may refuse to co-sign updates that create unprofitable circumstances that they could ultimately be responsible for

## transfers

the basic form of transfer is a two phased operation between two deposits on the same ledger: a deposit issues a request to send funds. if there are sufficient funds available, a lock on the funds with a spending condition is appended to the ledger. if the spending condition is fulfilled before a timeout, funds move from the sender to recipient minus the operator's fee. if the timeout is reached, the lock is released, minus a smaller operator fee. with dep-16 spending conditions, this is sufficient to allow any deposit to provide bridges and liquidity services to other deposits on the same ledger

## lightning

lightning connectivity is a bridging service, not an operator privilege. any deposit holder with a lightning node can bridge, using the same locks that move funds between deposits

to receive, the wallet generates a preimage and gives the bridge only its hash. the bridge issues a lightning invoice against that hash through its own node. arriving htlcs park there, unclaimable — the bridge does not know the preimage. the bridge then locks funds from its own deposit to the wallet's deposit, with the hash as the completion condition and a timeout safely earlier than the htlc's expiry. the wallet claims the lock by revealing the preimage on the ledger; the bridge reads the preimage from the ledger and settles upstream. the bridge cannot collect upstream before the wallet's credit is claimable, so theft is structurally impossible. if the wallet never reveals, both locks expire and the payer is refunded; the residual misbehavior is refusing service, which costs the bridge fees and reputation but costs no one funds

to send, the wallet locks funds to the bridge's deposit with the payee's invoice hash as the completion condition. the bridge pays the invoice, learns the preimage from the route, and completes the lock. the same timeout ordering protects both sides

bridges price their service as a spread on the bridged amount, like couriers. the ledger's ordinary transfer fee on each lock is paid to the operator as usual — bridging stacks a market-priced service fee on top of protocol fees, it does not replace them

these flows require the wallet to be online within the htlc window. for offline receive, an operator may run a lightning sidecar and hold preimages on the wallet's behalf, crediting deposits as payments arrive, with each invoice co-signed by a quorum member as evidence of the commitment. this service requires trust, so it is allocated to the one party the protocol can punish: the operator, whose collateral backs it (see economic deterrence). the general rule: atomic services may be performed by anyone; services requiring trust are performed by the party with slashable collateral

when the payer and payee are deposits on the same operator, the operator may settle internally without routing through lightning, crediting and debiting the respective deposits directly. this avoids routing fees and failure modes while maintaining the same accounting guarantees

## couriers

transfers move funds between deposits on the same ledger. to move funds across ledgers, wallets use couriers — services that hold deposits on multiple ledgers and carry transfers between them. a courier advertises its capacity and per-ledger directional fees on the relay. when a wallet wants to send from ledger A to ledger B, it requests a route from a courier bridging both, then locks funds to the courier's deposit on A with a hash lock. the courier locks funds from its deposit on B to the wallet's deposit on B with the same hash. the wallet reveals the preimage on B, claiming the funds; the courier observes the preimage and completes on A

this is a standard hash time-locked contract pattern. the courier's outbound timeout is strictly earlier than the inbound, ensuring that if the wallet never reveals, both locks expire and neither party loses funds. no trust is required beyond the timeout guarantees already enforced by operators. lightning is simply another domain in the courier graph: the pattern that carries transfers between ledgers is the same one that bridges them to lightning. completion conditions are expressed in the dep-16 descriptor calculus; point-based completion conditions are available today, opt-in per operator capability

couriers set per-ledger fees: fee_in (margin for receiving) and fee_out (operator transfer fee plus margin for sending). a wallet estimates route cost as fee_out on the source plus fee_in on the destination. couriers may vary fees by ledger based on available liquidity, naturally rebalancing their positions. wallets discover couriers through their advertisements on the relay and select based on fee, capacity, or coverage

## communication

all communication between wallets and operators, and between operators, uses nostr relays. ledger updates are published as durable events that relays retain, creating a permanent auditable record. requests and responses between wallets and operators are ephemeral events with a short relay TTL. operators advertise their terms as replaceable events, allowing wallets to discover and compare operators without a centralized directory

this architecture means wallets need no persistent connections -- they can go offline indefinitely and catch up by replaying events from any relay that has them. operators can be reached through any relay they monitor, and the choice of relay is a deployment decision, not a protocol constraint

## reserves and collateral

an operator's utxo is split into reserves and collateral, both held in the same taproot output controlled by the quorum. the reserves portion is the deposit capacity — wallets can deposit up to this amount. the collateral portion is the operator's security bond — it cannot be used for deposits and is forfeited if the operator misbehaves

obligations are enforced when creating new funding offers or invoices. the operator cannot create offers or invoices that would push the ledger's total obligations above the reserves amount. co-signers verify that reserves plus collateral equals the on-chain utxo value, and refuse to sign operations that would reduce either

each rotation of the reserves utxo commits the ledger's tip hash on-chain, giving wallets a checkpoint they can verify without trusting any relay, and a single place to watch for changes in custody

the taproot output's script tree contains escalating recovery paths: a quorum majority can spend immediately, and progressively smaller subsets can spend after increasing timelocks, ending in a single-party path after the longest window. these paths guarantee that funds remain recoverable no matter which participants disappear. they also put a clock on everyone: the operator must rotate the utxo before the first window opens, and safety against a misbehaving operator assumes a quorum majority that acts within the shortest window. liveness is measured in blocks, not goodwill

operators should run multiple ledgers with independent quorums. this provides probabilistic safety: an attacker must compromise all quorums simultaneously to avoid losing collateral on the others. with a 40/60 reserves/collateral split and 5 independent ledgers, simulation shows the protocol is safe against a single coalition controlling up to 49% of the network. simulation parameters and the adversary model are published alongside the specification

## quorum

operators request other operators to join their quorum. the member's terms include minimum fee schedules that deposits on the ledger must meet, and timing parameters that bound the member's own obligations to respond. the operator cannot open deposits with fees below the strictest member's minimums, protecting members from inheriting unprofitable obligations after a custody transfer. members are compensated with a negotiated share of the operator's collected fees

once quorum is established, reserves are rotated into a new taproot multisig utxo. members co-sign valid updates and participate in recovery if the operator signs non-conforming ones. quorum membership is a capital commitment, not a courtesy: members must keep collateral at stake on their own ledgers — misbehavior as a co-signer is slashable there — and a member who disputes a failed ledger must declare, in advance and verifiably on-chain, replacement collateral sufficient to fully recapitalize the ledger should they win custody. members are underwriters of the ledgers they sign for. larger quorums increase communication overhead but reduce operator risk, increase availability, and make collusion more difficult and expensive. wallets should prefer larger quorums

## economic deterrence

the protocol replaces unilateral exit with economic deterrence. quorum members are not neutral validators — they are incentivized auditors with standing to act. a member earns a share of fees during normal operation. when an operator is proven non-conforming, the confiscated value — the operator's collateral plus reserves in excess of obligations — is divided equally among the disputants who armed for the lottery and revealed their secrets. a member who never arms earns nothing. a member who arms but fails to reveal within the window forfeits their share, which is swept back pro-rata to the revealers. the reward is gated on participation: to earn a share a member must have stood ready to take custody — replacement collateral declared and verifiable on-chain — and must have seen the dispute through. the member selected to take over the ledger inherits its obligations and posts that declared collateral; operating a recovered ledger is a service commitment, not a windfall. the participation gate keeps every active member's incentive uniform, removes any incentive to manufacture disputes, prevents freeloading on the vigilance of others, and makes withholding a reveal cost the withholder their share

when a wallet suspects censorship, it escalates the request to quorum members via certified delivery: the member embeds the request hash in their own ledger for a small fee, creating causally anchored evidence. if the operator fails to process the request, the member has both the evidence and the economic incentive to initiate a dispute. the wallet's escalation is effectively a bounty

with bridged lightning, sends and online receives are atomic and require no trust. the residual trust boundary is offline receive through an operator's sidecar: the operator knows whether a preimage was received, but an offline wallet does not. any payer might later provide the preimage to the wallet. one confirmed theft triggers dispute, reserves seizure, collateral confiscation, and slashing on the operator's other ledgers. the upside of stealing a single payment is bounded; the downside is existential. exposure is limited to payments received while the wallet was offline, and wallets bound it further by limiting outstanding uncredited invoices

the only failure mode for both censorship and lightning deterrence is collusion by a quorum majority. the protocol cannot protect against a majority that cooperates to steal — but the collateral web ensures that collusion costs more than it gains, and the network's transparency allows wallets to evaluate quorum structures before depositing funds

## time

absolute time is measured against the base layer. tolerances should not exceed a reasonable number of confirmations in order to maintain stability during chain reorganizations

when higher tolerances are required, we instead rely on causal ordering. a cryptographic ledger is a merkle chain. each update proves it was created after all updates before it, but provides no guarantees about information outside the chain. in order to construct a distributed ordering, we require that co-signatures include the latest update hash from the co-signer's ledger. that hash is then incorporated into the current update's hash, becoming part of the chain as well as part of all other chains that the ledger operator co-signs for, creating a web of causality. this is unable to prove time explicitly, but is able to prove that certain pieces of information were created in a specific order

## fraud proofs

we can then prove various types of fraud by exposing information which has been created in the wrong order. when the information is not included by normal network operations, it can be smuggled in by creating activity that includes a hash of the evidence. once incorporated into an update signed by the operator, the evidence is revealed as having been created at a non-conforming place in the ordering:

- an operator, having offered to credit a deposit with funds sent on-chain to a specific address, signs a ledger update that does not contain the appropriate credit, but does contain a chain revealing some block hash exceeding the number of confirmations allowed before credit

- an operator, having created a lightning invoice on a deposit's behalf, signs a ledger update that has not credited the deposit despite the pre-image being revealed in the chain

- a co-signature that declares the current ledger hash to be one that precedes their own later hash in the chain

- a member of the quorum of a contested ledger who was active but did not act in accordance with proof of fraud within a number of blocks

- a lottery winner whose claim transaction deviates from the replacement collateral declared when arming

- signing or co-signing non-conforming ledger updates

a fraud proof consists of the evidence and a causal chain connecting the embedded hash to the accused operator's ledger. the chain is a sequence of co-signed updates, each including a member_ledger_hash from the previous link's ledger. verifiers walk the chain without searching, confirming each link is a signed update, and that the proof hash matches the embedded data

## recovery

once a ledger has become unavailable or non-conforming, quorum members may fork the ledger from the last conforming update and enter a dispute. each disputant arms within a fixed block window, committing to a secret value and declaring the replacement collateral they will post if they win. the remaining quorum then spends the reserves utxo into a lottery output whose tapscript enforces the selection: once the disputants reveal their secrets, the script admits only the signature of the selected winner, so bitcoin itself adjudicates the outcome. fallback paths with longer timelocks handle missing reveals. the winner claims on-chain, committing their declared collateral in the same transaction, appends an acquisition update to their fork, and the others yield

wallets continue to address the same ledger, accepting only majority co-signed replies. when co-signatures stop or fail verification, the wallet queries the network, replays ledger updates to identify the last valid sequence, and waits for the lottery claim transaction to confirm before accepting the new custodian — the claim transaction itself is the proof of who won. the anchor written at each rotation gives wallets a relay-independent place to detect that custody changed

when a ledger has become unavailable for a certain number of blocks without proof of fraud, the change in custody must be respectful: only the amount of reserves required to cover the ledger's obligations is sent to the lottery, and change including collateral is sent back to the operator's pubkey. when proof of non-conformance is provided, the full utxo goes to the lottery: the winner inherits deposit obligations and posts replacement collateral, and the confiscated value — collateral plus excess reserves — is split equally among the armers who revealed. shares of armers who fail to reveal are forfeited and swept pro-rata to those who did. if the operator runs multiple ledgers, proof of non-conformance on one ledger can be presented to the other ledgers' quorums, triggering slashing there as well

## network health

one straightforward attack is to form islands of colluding operators. after building substantial obligations across their ledgers, they coordinate to exit, stealing funds that exceed the collateral lost. simulation shows that with a 40/60 reserves/collateral split and multiple ledgers per operator with independent quorums, this attack is unprofitable for coalitions controlling up to 49% of the network. the key mechanism: each colluding operator whose own quorum retains honest majority loses their collateral, and with independent quorums the probability of escaping all of them drops exponentially with the number of ledgers

wallets cannot prove quorum independence; they can only price it. the useful signals are mechanical: collateral verifiably at stake, tenure readable from ledger histories, capital provably locked over time, and correlation observable in the public record — members that sign, fail, or go silent in lockstep reveal shared control or shared infrastructure. correlated operation is equivalent to collusion for safety purposes, and should be priced as if the correlated members were one

## conclusion

we propose a collateral network that requires collusion to steal, but collusion increases the collateral at risk faster than it increases the value to be stolen. each operator's utxo contains both reserves and collateral, controlled by their quorum, with every ledger update co-signed by a quorum majority. multiple ledgers with independent quorums make simultaneous compromise exponentially unlikely. confiscation is shared among the disputants who see the lottery through, and custody succession is enforced on-chain, so vigilance pays and takeover is never a windfall. we use this network to secure cryptographic ledgers backed by full reserves. these ledgers service accounts on behalf of offline wallets in exchange for pre-negotiated fees. ledger primitives support spending conditions in the dep-16 calculus — generalizing miniscript with hash- and point-based locks — sufficient for basic smart contracts, including trustless bridging to the lightning network by any deposit holder. the network scales close to linearly, allowing a large network to provide billions of wallets and transaction volume in excess of traditional payment networks
