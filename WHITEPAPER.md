# bitcoin deposits
## abstract

an ideal peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another quickly and with minimal preparation. the lightning network provides part of the solution, but the essential benefits are lost if a trusted third party is required to manage state on your behalf. we propose a solution to this problem using verifiable ledgers and a web of collateral. operators broadcast ledger updates to their peers, creating an auditable record of accounts. wallets broadcast evidence of dishonesty to those peers, who ensure that the ledger maintains an honest operator. unilateral exit is replaced by the guarantee that funds remain available so long as the network does. we arrive at a network that delegates liquidity maintenance, avoids setup fees, is capable of receiving payments offline, and scales independently of the base layer

## introduction

bitcoin deposits aims to provide fast and scalable key controlled funds, trustlessly, off-chain. on-chain activity scales with the number of ledgers and frequency of reserves rotation. throughput scales slightly above linearly with the number of ledgers in the network, making millions of transactions per second across trillions of wallets plausible

there are explicit tradeoffs:
- no unilateral exit: when operators fail funds stay in the network
- no privacy: verification requires transparency
- intermittent availability: a deposit is only as available as the operator. wallets should spread out funds to increase availability

we expect the wallet experience to be similar to a fast base layer, having payment economics similar to the lightning network

## ledgers

a ledger is an immutable chain of updates, containing the hash of the previous update and signed by the ledger's operator. different types of update have different rules governing when and how they can be used. ledgers are self descriptive, their updates publicly available and non-repudiable, allowing anyone to evaluate conformance

ledgers have a single active operator, but are cooperatively maintained by the mesh. any operator can create one, but should they disappear or become dishonest a different operator will be assigned, along with reserves. the currently active operator is identified by the pubkey that was used to sign to most recent co-signed update

## deposits

a deposit is a stable account that can send and receive funds, controlled by miniscript. at opening a fee schedule is established, as well as whether receiving funds requires a wallet signed request. an operator must allow transfers between deposits on the same ledger as well as on-chain exits. they should allow deposits to pay lightning invoices

it is in the operator's discretion to create on-chain funding offers or lightning invoices on behalf of a deposit. if they do, these should be co-signed by a quorum member, and the wallet should verify this signature. offers and invoices are not part of the ledger, so it is the wallet's responsibility to verify signatures and retain them as evidence

## fees

transfers between deposits, on-chain, and through lightning have fees paid to the ledger's operator. there are also fees periodically applied to balances with a specified period. all are negotiated when a new deposit is opened. fees can be changed after a specified number of blocks, given a specified block notice and within a per-adjustment percentage limit negotiated at opening. the quorum may refuse to co-sign updates that create unprofitable circumstances that they could ultimately be responsible for

## transfers

the basic form of transfer is a two phased operation between two deposits on the same ledger: a deposit issues a request to send funds. if there are sufficient funds available, a lock on the funds with a spending condition is appended to the ledger. if the spending condition is fulfilled before a timeout, funds move from the sender to recipient minus the operator's fee. if the timeout is reached, the lock is released, minus a smaller operator fee. with miniscript spending conditions, this is sufficient to allow any deposit to provide bridges and liquidity services to other deposits on the same ledger

## lightning

operators may run a lightning sidecar alongside their deposits node, allowing deposits to send and receive over the lightning network. when a deposit requests a lightning invoice, the operator creates one through their lightning node, co-signed by a quorum member to prove the operator committed to credit the deposit upon payment. the wallet retains this cosigned invoice as evidence. when a deposit pays a lightning invoice, the operator routes the payment through their lightning node and debits the deposit upon confirmation of the preimage

when the payer and payee are deposits on the same operator, the operator may settle internally without routing through lightning, crediting and debiting the respective deposits directly. this avoids routing fees and failure modes while maintaining the same accounting guarantees

## couriers

transfers move funds between deposits on the same ledger. to move funds across ledgers, wallets use couriers — services that hold deposits on multiple ledgers and carry transfers between them. a courier advertises its capacity and per-ledger directional fees on the relay. when a wallet wants to send from ledger A to ledger B, it requests a route from a courier bridging both, then locks funds to the courier's deposit on A with a hash lock. the courier locks funds from its deposit on B to the wallet's deposit on B with the same hash. the wallet reveals the preimage on B, claiming the funds; the courier observes the preimage and completes on A

this is a standard hash time-locked contract pattern. the courier's outbound timeout is strictly earlier than the inbound, ensuring that if the wallet never reveals, both locks expire and neither party loses funds. no trust is required beyond the timeout guarantees already enforced by operators

couriers set per-ledger fees: fee_in (margin for receiving) and fee_out (operator transfer fee plus margin for sending). a wallet estimates route cost as fee_out on the source plus fee_in on the destination. couriers may vary fees by ledger based on available liquidity, naturally rebalancing their positions. wallets discover couriers through their advertisements on the relay and select based on fee, capacity, or coverage

## communication

all communication between wallets and operators, and between operators, uses nostr relays. ledger updates are published as durable events that relays retain, creating a permanent auditable record. requests and responses between wallets and operators are ephemeral events with a short relay TTL. operators advertise their terms as replaceable events, allowing wallets to discover and compare operators without a centralized directory

this architecture means wallets need no persistent connections -- they can go offline indefinitely and catch up by replaying events from any relay that has them. operators can be reached through any relay they monitor, and the choice of relay is a deployment decision, not a protocol constraint

## reserves and collateral

an operator's utxo is split into reserves and collateral, both held in the same taproot output controlled by the quorum. the reserves portion is the deposit capacity — wallets can deposit up to this amount. the collateral portion is the operator's security bond — it cannot be used for deposits and is forfeited if the operator misbehaves

obligations are enforced when creating new funding offers or invoices. the operator cannot create offers or invoices that would push the ledger's total obligations above the reserves amount. co-signers verify that reserves plus collateral equals the on-chain utxo value, and refuse to sign operations that would reduce either

operators should run multiple ledgers with independent quorums. this provides probabilistic safety: an attacker must compromise all quorums simultaneously to avoid losing collateral on the others. with a 40/60 reserves/collateral split and 5 independent ledgers, simulation shows the protocol is safe against a single coalition controlling up to 49% of the network

## quorum

operators request other operators to join their quorum. the member's terms include minimum fee schedules that deposits on the ledger must meet. to serve as a quorum member, an operator must have collateral at stake on their own ledger — misbehavior as a quorum member (co-signing a non-conforming update) can result in slashing on the member's own ledger. members specify limits on fee schedules during their quorum membership — the operator cannot open deposits with fees below the strictest member's minimums, protecting members from inheriting unprofitable obligations after a custody transfer

once quorum is established, reserves are rotated into a new taproot multisig utxo. members co-sign valid updates and participate in recovery if the operator signs non-conforming ones. quorum membership is lightweight — it requires no separate capital, only that the member has collateral at stake on their own ledger and is willing to monitor. larger quorums increase communication overhead but reduce operator risk, increase availability, and make collusion more difficult and expensive. wallets should prefer larger quorums

## economic deterrence

the protocol replaces unilateral exit with economic deterrence. quorum members are not neutral validators — they are incentivized predators. a member earns basis points on co-signing fees during normal operation, but stands to take over the operator's ledger and its collateral if the operator misbehaves. this asymmetry — steady small income versus a one-time windfall — ensures that members actively monitor operators without requiring protocol-level enforcement

when a wallet suspects censorship, it escalates the request to quorum members via certified delivery: the member embeds the request hash in their own ledger for a small fee, creating causally anchored evidence. if the operator fails to process the request, the member has both the evidence and the economic incentive to initiate a dispute. the wallet's escalation is effectively a bounty

lightning invoice fraud follows the same deterrence pattern. the operator's lightning node is a trust boundary that the protocol cannot fully bridge — the operator knows whether a preimage was received, but the wallet does not. however, any payer might provide the preimage to the wallet. one confirmed theft triggers dispute, reserves seizure, and collateral confiscation. the upside of stealing a single payment is bounded; the downside is existential. this makes lightning theft economically irrational despite being formally unprovable without third party cooperation

the only failure mode for both censorship and lightning deterrence is unanimous quorum collusion. the protocol cannot protect against a quorum that cooperates to steal — but the collateral web ensures that collusion costs more than it gains, and the network's transparency allows wallets and discovery markets to identify suspicious quorum structures before depositing funds

## time

absolute time is measured against the base layer. tolerances should not exceed a reasonable number of confirmations in order to maintain stability during chain reorganizations

when higher tolerances are required, we instead rely on causal ordering. a cryptographic ledger is a merkle chain. each update proves it was created after all updates before it, but provides no guarantees about information outside the chain. in order to construct a distributed ordering, we require that co-signatures include the latest update hash from the co-signer's ledger. that hash is then incorporated into the current update's hash, becoming part of the chain as well as part of all other chains that the ledger operator co-signs for, creating a web of causality. this is unable to prove time explicitly, but is able to prove that certain pieces of information were created in a specific order

## fraud proofs

we can then prove various types of fraud by exposing information which has been created in the wrong order. when the information is not included by normal network operations, it can be smuggled in by creating activity that includes a hash of the evidence. once incorporated into an update signed by the operator, the evidence is revealed as having been created at a non-conforming place in the ordering:

- an operator, having offered to credit a deposit with funds sent on-chain to a specific address, signs a ledger update that does not contain the appropriate credit, but does contain a chain revealing some block hash exceeding the number of confirmations allowed before credit

- an operator, having created a lightning invoice on a deposit's behalf, signs a ledger update that has not credited the deposit despite the pre-image being revealed in the chain

- a co-signature that declares the current ledger hash to be one that precedes their own later hash in the chain

- a member of the quorum of a contested ledger who was active but did not act in accordance with proof of fraud within a number of blocks

- signing or co-signing non-conforming ledger updates

a fraud proof consists of the evidence and a causal chain connecting the embedded hash to the accused operator's ledger. the chain is a sequence of co-signed updates, each including a member_ledger_hash from the previous link's ledger. verifiers walk the chain without searching, confirming each link is a signed update, and that the proof hash matches the embedded data

## recovery

once a ledger has become unavailable or non-conforming, quorum members may create their own continuation of the ledger from the last conforming update. they must establish a new quorum. members then coordinate to spend the previous reserves output to a lottery of the potential next chains. the winner of this lottery appends an acquisition update to their chain, and the others append a yield. wallets continue to address the same ledger, accepting only replies co-signed by the quorum. periodically, and when no replies have the expected co-signature, the wallet should query the network and replay ledger updates to identify changes in custody

when a ledger has become unavailable for a certain number of blocks, a change in custody must be respectful: only the amount of reserves required to cover the ledger's obligations is sent to the lottery, and change including collateral sent back to the operator's pubkey. when proof of non-conformance is provided, the full utxo goes to the lottery winner. the winner inherits deposit obligations and retains the collateral as compensation. if the operator runs multiple ledgers, proof of non-conformance on one ledger can be presented to the other ledgers' quorums, triggering slashing there as well

## network health

one straightforward attack is to form islands of colluding operators. after building substantial obligations across their ledgers, they coordinate to exit, stealing funds that exceed the collateral lost. simulation shows that with a 40/60 reserves/collateral split and multiple ledgers per operator with independent quorums, this attack is unprofitable for coalitions controlling up to 49% of the network. the key mechanism: each colluding operator whose own quorum retains honest majority loses their collateral, and with independent quorums the probability of escaping all of them drops exponentially with the number of ledgers. wallets can verify quorum independence through graph metrics such as quorum-mincut — the collective vertex connectivity from a quorum's members to the wallet's trusted anchors

## conclusion

we propose a collateral network that requires collusion to steal, but collusion increases the collateral at risk faster than it increases the value to be stolen. each operator's utxo contains both reserves and collateral, controlled by their quorum. multiple ledgers with independent quorums make simultaneous compromise exponentially unlikely. we use this network to secure cryptographic ledgers backed by full reserves. these ledgers service accounts on behalf of offline wallets in exchange for pre-negotiated fees. ledger primitives support miniscript spending conditions sufficient for basic smart contracts. the network scales close to linearly, allowing a large network to provide billions of wallets and transaction volume in excess of traditional payment networks
