# DEP-01: DEP Purpose and Guidelines

## Abstract

A DEP (Deposits Enhancement Proposal) is a design document for the Bitcoin Deposits protocol. DEPs describe protocol mechanics, wire formats, on-chain transactions, and operational requirements. This document defines the DEP process itself.

## DEP Types

- **Standard**: changes to the protocol wire format, state model, on-chain transactions, or peer messaging. These require implementation and testing before acceptance.
- **Informational**: design rationale, best practices, or ecosystem guidelines. These do not require implementation.

## DEP Lifecycle

1. **Draft**: initial proposal. May be incomplete.
2. **Proposed**: complete specification with reference implementation and tests.
3. **Accepted**: reviewed and adopted by implementers.
4. **Superseded**: replaced by a later DEP.

## DEP Format

Each DEP should include:

- **Title**: `DEP-NN: Short Title`
- **Abstract**: one paragraph summary
- **Specification**: normative technical content
- **Related DEPs**: cross-references
- **References**: external specifications (BIPs, BOLTs, NIPs)

Specifications use the conventions from BOLT #0: MUST, SHOULD, MAY for requirement levels. All multi-byte integers are big-endian unless stated otherwise. Amounts are in millisatoshis unless stated otherwise.

## Current DEPs

| DEP | Title | Status |
|---|---|---|
| [DEP-01](DEP-01.md) | DEP Purpose and Guidelines | Accepted |
| [DEP-02](DEP-02.md) | Wire Format | Draft |
| [DEP-03](DEP-03.md) | On-Chain Transactions | Draft |
| [DEP-04](DEP-04.md) | Peer Messaging | Draft |
| [DEP-05](DEP-05.md) | Quorum and Collateral | Draft |
| [DEP-06](DEP-06.md) | Fraud Proofs and Recovery | Draft |
| [DEP-07](DEP-07.md) | Fee Schedules | Draft |
| [DEP-08](DEP-08.md) | Deposits | Draft |
| [DEP-09](DEP-09.md) | Transfers | Draft |
| [DEP-10](DEP-10.md) | Payment Channels | Draft |
| [DEP-11](DEP-11.md) | Time Obligations | Draft |
| [DEP-12](DEP-12.md) | Delivery Escalation | Draft |
| [DEP-13](DEP-13.md) | Couriers | Draft |
