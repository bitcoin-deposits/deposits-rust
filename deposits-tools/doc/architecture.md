# LDK Node Architecture

LDK Node is a **ready-to-go Lightning node library** built using the Lightning Development Kit (LDK) and Bitcoin Development Kit (BDK). It provides a simple, self-custodial Lightning node with integrated on-chain wallet functionality.

## Core Design Philosophy

- **Minimalism**: Small, simple, straightforward interface
- **Self-custodial**: Users maintain full control of their funds
- **Modular**: Configurable for various use cases
- **Library-first**: Designed as a library rather than a standalone application

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Node (Main API)                         │
├─────────────────────────────────────────────────────────────────┤
│  Builder Pattern Configuration  │  Payment Handlers            │
│  • Network Settings            │  • BOLT 11 (invoices)        │
│  • Chain Sources              │  • BOLT 12 (offers)          │
│  • Storage Backends           │  • Spontaneous (keysend)     │
│  • Gossip Sources             │  • On-chain                  │
│  • Entropy Sources            │  • Unified QR (BIP 21)       │
├─────────────────────────────────────────────────────────────────┤
│                    Core Lightning Components                    │
│  ChannelManager  │  ChainMonitor  │  PeerManager │ KeysManager │
├─────────────────────────────────────────────────────────────────┤
│                    Network & Communication                      │
│  ConnectionManager │ MessageHandler │ GossipSource │ Runtime    │
├─────────────────────────────────────────────────────────────────┤
│                      Storage Layer                             │
│  DataStore │ PeerStore │ PaymentStore │ WalletPersist │ KVStore │
├─────────────────────────────────────────────────────────────────┤
│                      Chain Sources                             │
│  Bitcoin Core RPC    │    Electrum    │    Esplora            │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Node (`src/lib.rs:180`)

The `Node` struct is the central abstraction containing:

- **Runtime**: Tokio async runtime management
- **Wallet**: Integrated BDK on-chain wallet  
- **Channel Manager**: LDK Lightning channel management
- **Chain Monitor**: On-chain transaction monitoring
- **Peer Manager**: P2P network connection handling
- **Event System**: Asynchronous event processing
- **Storage**: Persistent data management

### 2. Storage & Persistence Layer

#### Storage Abstraction (`src/data_store.rs`)

The generic `DataStore<SO, L>` provides a template for persistent storage of any serializable objects:

- **Key-Value Store**: Uses `DynStore` trait for pluggable storage backends
- **SQLite Support**: Primary persistence backend via `src/io/sqlite_store/`
- **VSS Support**: Alternative storage via Versioned Storage Service
- **Namespace Organization**: Uses primary/secondary namespace structure

#### Specialized Storage Components

- **PeerStore** (`src/peer_store.rs:25`): Manages known peer information and connection details
- **PaymentStore** (`src/payment/store.rs`): Tracks payment history and status  
- **WalletPersist** (`src/wallet/persist.rs`): BDK wallet state management

### 3. Network Messaging & Communication

#### P2P Networking

- **ConnectionManager** (`src/connection.rs:22`): Handles outbound peer connections with deduplication
- **MessageHandler** (`src/message_handler.rs:23`): Routes custom messages, particularly for liquidity services
- **Peer Management**: Built on LDK's networking stack with automatic reconnection

#### Chain Data Sources (`src/chain/`)

Multiple blockchain data source implementations:

- **Bitcoin Core RPC** (`src/chain/bitcoind.rs`): Direct node connection
- **Electrum** (`src/chain/electrum.rs`): SPV-style blockchain access  
- **Esplora** (`src/chain/esplora.rs`): REST API blockchain explorer interface

### 4. Payment System (`src/payment/`)

Multi-protocol payment support:

- **BOLT 11** (`src/payment/bolt11.rs`): Traditional Lightning invoices
- **BOLT 12** (`src/payment/bolt12.rs`): Offers and refunds  
- **Spontaneous** (`src/payment/spontaneous.rs`): Keysend payments
- **On-chain** (`src/payment/onchain.rs`): Bitcoin transactions
- **Unified QR** (`src/payment/unified_qr.rs`): Multi-protocol BIP 21 URIs

### 5. Builder Pattern (`src/builder.rs`)

Comprehensive configuration system allowing users to set:

- Network (mainnet, testnet, regtest)
- Chain data sources (RPC, Electrum, Esplora)
- Storage backends (SQLite, filesystem, custom)
- Gossip sources (P2P, Rapid Gossip Sync)
- Entropy sources (random, BIP39 mnemonic)
- Network listening addresses
- Channel and fee configurations

## Key Architectural Patterns

### 1. Async Background Processing

- Multiple tokio tasks handle different concerns (chain sync, gossip sync, connection management)
- Event-driven architecture with `EventQueue` for handling Lightning events
- Background processor manages LDK's core processing loop

### 2. Layered Abstraction

- **High-level API**: Simple methods like `node.start()`, `node.open_channel()`
- **LDK Integration**: Wraps LDK's lower-level Lightning protocol handling  
- **BDK Integration**: Handles on-chain wallet operations seamlessly

### 3. Configurable Modularity

- Chain sources are pluggable (RPC vs Electrum vs Esplora)
- Storage backends can be swapped (SQLite vs VSS vs custom)
- Gossip can use P2P networking or RGS for faster sync

### 4. Thread-Safe Design

- Extensive use of `Arc<T>` and `Mutex<T>` for shared state
- All major components designed for concurrent access
- Runtime detection avoids stacking Tokio contexts

## Data Flow

### Node Startup Sequence

1. **Builder Configuration**: User configures network, storage, chain sources
2. **Component Initialization**: Create LDK/BDK components, load persisted state
3. **Background Task Spawn**: Start chain sync, gossip sync, connection management
4. **Event Processing**: Initialize event handlers and processing loops
5. **Network Listening**: Optionally bind to listening addresses for incoming connections

### Payment Flow (Outbound)

1. **Payment Initiation**: User calls payment handler (BOLT11, BOLT12, etc.)
2. **Route Finding**: LDK router finds path through Lightning network
3. **HTLC Management**: Channel manager sends HTLCs along route
4. **Settlement**: Payment settles or times out, events generated
5. **State Updates**: Payment store updated, events delivered to user

### Channel Management

1. **Peer Connection**: ConnectionManager establishes outbound connections
2. **Channel Opening**: User initiates channel via `open_channel()`
3. **Funding**: On-chain transaction created and broadcast
4. **Channel Ready**: Channel becomes operational after confirmations
5. **Ongoing Management**: Background tasks handle channel state updates

## Extension Points

### Custom Storage Backends

Implement the `DynStore` trait to support custom storage:

```rust
pub trait KVStore: Send + Sync {
    fn read(&self, primary: &str, secondary: &str, key: &str) -> Result<Vec<u8>, io::Error>;
    fn write(&self, primary: &str, secondary: &str, key: &str, buf: &[u8]) -> Result<(), io::Error>;
    fn remove(&self, primary: &str, secondary: &str, key: &str, lazy: bool) -> Result<(), io::Error>;
    fn list(&self, primary: &str, secondary: &str) -> Result<Vec<String>, io::Error>;
}
```

### Custom Message Handling

Extend the `CustomMessageHandler` for protocol extensions:

```rust
impl CustomMessageHandler for MyCustomHandler {
    fn handle_custom_message(&self, msg: Self::CustomMessage, sender_node_id: PublicKey) 
        -> Result<(), LightningError>;
    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)>;
}
```

### Event Handling

Process Lightning events through the event queue:

```rust
let event = node.wait_next_event();
match event {
    Event::PaymentSuccessful { payment_id, .. } => { /* handle success */ },
    Event::PaymentFailed { payment_id, .. } => { /* handle failure */ },
    // ... other events
}
node.event_handled();
```

## Dependencies

### Core Lightning Infrastructure

- **lightning**: Core Lightning protocol implementation
- **lightning-net-tokio**: Tokio-based networking
- **lightning-background-processor**: Event processing
- **lightning-transaction-sync**: Chain synchronization

### Bitcoin Infrastructure  

- **bdk_wallet**: On-chain wallet functionality
- **bdk_chain**: Chain data handling
- **bdk_esplora**: Esplora client integration
- **bitcoin**: Bitcoin protocol types

### Storage & Serialization

- **rusqlite**: SQLite database interface
- **serde**: Serialization framework
- **lightning persistence**: LDK persistence traits

## Performance Considerations

### Memory Usage

- Event queue size affects memory footprint
- Channel monitoring data grows with number of channels
- Payment history accumulates over time

### Network Efficiency  

- RGS (Rapid Gossip Sync) reduces bandwidth for gossip data
- Connection deduplication prevents redundant network requests
- Background sync intervals balance freshness vs resource usage

### Storage Optimization

- SQLite WAL mode for better concurrent access
- Namespace organization for efficient data access
- Lazy removal for better performance