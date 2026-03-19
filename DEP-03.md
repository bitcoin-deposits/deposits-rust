# DEP-03: On-Chain Transaction Formats

## Abstract

This document specifies the on-chain transaction formats used by Bitcoin Deposits: the reserves UTXO, tapscript multisig construction, reserves rotation transactions, and the lottery mechanism for contested custody transfers.

## Status

Placeholder -- to be extracted from the reference implementation.

## Scope

- Reserves UTXO structure (operator + quorum multisig with operator fallback timelock)
- Tapscript tree construction for quorum spending
- Reserves rotation transaction (old UTXO → new multisig)
- Lottery output for contested custody (preimage-based winner selection)
- Respectful custody: obligation-only amount to lottery, change to operator

## Related DEPs

- [DEP-02](DEP-02.md): Ledger State Model (ReservesRotate operation)
- [DEP-05](DEP-05.md): Quorum and Collateral (membership determines multisig participants)
- [DEP-06](DEP-06.md): Fraud Proofs and Recovery (lottery triggered by dispute)
