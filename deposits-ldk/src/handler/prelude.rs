//! Handler Prelude
//!
//! Re-exports all commonly used types for handler modules.
//! Use `use super::prelude::*;` at the top of handler files.

// Re-export from deposits-core
pub use deposits_core::{
    // Error types
    DepositsError, DepositsResult,

    // Ledger types
    Ledger, LedgerRole, LedgerUpdate, LedgerManager, LedgerValidator,
    LedgerState, SignedLedgerUpdate, SignedLedgerUpdateLog,

    // Message types (V2 LedgerOperation only - DepositsMessage comes from local module)
    LedgerOperation,

    // Protocol types
    Deposit, FeeStructure, Invoice, ReservesOutput, PendingInvoice,
    DepositInfo, InvoiceInfo, ReservesStatus, CollateralAttestation,

    // Recovery types
    RecoveryManager, RecoveryPhase,

    // Handler traits (from deposits-core)
    handler_traits::{
        CollateralOperations as CollateralOperationsTrait,
        DepositOperations as DepositOperationsTrait,
        PaymentTracking as PaymentTrackingTrait,
        ReservesQueryOps,
        LedgerOperations as LedgerOperationsTrait,
    },

    // Handler types
    handler_types::{
        CosignedInvoice, VoteRoundState, ProtocolStats,
        LedgerSummary, ReservesSummary, CollateralPartnerInfo, CollateralInfo,
        PendingPayment,
    },

    // Tapscript reserves
    TapscriptReservesBuilder, VoterSet, TaprootReservesOutput,

    // Signature utilities
    signature_utils::{
        create_deposit_guarantee_signature,
        verify_deposit_guarantee_signature,
        create_payment_authorization_signature,
    },

    // Validation
    ValidationRules, OperationValidator, LedgerConformanceValidator,

    // Time utilities
    now_unix_timestamp, is_expired,

    // Adapter traits (for generic handler)
    traits::{
        Storage, StorageError, EventEmitter, ProtocolEvent,
        ChannelOperations, ReservesOperations, ChannelInfo,
        Broadcaster, ChainSource, SignatureProvider, Logger, LogLevel,
    },
};

// Re-export quorum types from module path
pub use deposits_core::quorum::QuorumManager;

// Re-export from lightning
pub use lightning::util::logger::Logger as LdkLogger;
pub use lightning::ln::peer_handler::CustomMessageHandler;
pub use lightning::ln::wire::CustomMessageReader;
pub use lightning::ln::msgs::{DecodeError, LightningError, ErrorAction};
pub use lightning_types::features::{InitFeatures, NodeFeatures};
pub use lightning::util::ser::{Readable, Writeable};
pub use lightning::io;

// Re-export bitcoin types
pub use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
pub use bitcoin::{Network, ScriptBuf, Transaction, Txid};
pub use bitcoin::hashes::{Hash, sha256};

// Re-export tokio types
pub use tokio::sync::oneshot;

// Re-export std types commonly used
pub use std::collections::HashMap;
pub use std::ops::Deref;
pub use std::sync::{Arc, Mutex, RwLock};

// Re-export local adapters
pub use crate::events::{CallbackEventEmitter, MemoryEventEmitter, NullEventEmitter};
pub use crate::storage::LdkStorage;
pub use crate::channels::{LdkChannelRegistry, LdkChannelOperations, LdkReservesOperations};

// Re-export DepositsMessage from local messages module (with LDK traits)
pub use super::messages::DepositsMessage;

// Re-export ledger extension traits
pub use super::ledger_ext::{LedgerExt, SignedLedgerUpdateExt, SignedLedgerUpdateLogExt};

// Logger macros - re-export from deposits_core (tracing-backed)
pub use deposits_core::{log_error, log_warn, log_info, log_debug, log_trace};

// Base64 encoding (used in some handlers)
pub use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
