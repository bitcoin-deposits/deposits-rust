// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Node implementation that ties together wallet, nostr, and lightning

use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
use bitcoin::Network;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::handler::{DepositsHandler, OutboundMessage};
use crate::lightning::LightningClient;
use crate::nostr::{InboundMessage, NostrTransport};
use crate::wallet::Wallet;
use crate::Error;

/// Configuration for the deposits-bdk node
pub struct NodeConfig {
    /// Seed for wallet/identity (32 bytes)
    pub seed: [u8; 32],

    /// Bitcoin network
    pub network: Network,

    /// Electrum server URL
    pub electrum_url: String,

    /// Nostr relay URLs
    pub relays: Vec<String>,

    /// NWC connection string (optional - for Lightning operations)
    pub nwc_uri: Option<String>,

    /// Data directory
    pub data_dir: PathBuf,
}

/// A deposits-bdk node
pub struct Node {
    /// Our node ID (secp256k1 pubkey)
    pub node_id: PublicKey,

    /// The wallet for on-chain operations
    pub wallet: Arc<Wallet>,

    /// Nostr transport for peer messaging
    pub nostr: NostrTransport,

    /// Lightning client (optional)
    pub lightning: Option<LightningClient>,

    /// The protocol handler
    pub handler: Arc<DepositsHandler>,

    /// Outbound message receiver (for async sending via nostr)
    outbound_rx: mpsc::UnboundedReceiver<OutboundMessage>,
}

impl Node {
    /// Create a new node
    pub async fn new(config: NodeConfig) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        // Create wallet
        let wallet = Arc::new(Wallet::new(
            config.seed,
            config.network,
            config.data_dir.join("wallet"),
            config.electrum_url,
        )?);

        let secret_key = wallet.operator_secret();
        let node_id = PublicKey::from_secret_key(&secp, &secret_key);

        // Create nostr transport
        let nostr = NostrTransport::new(secret_key, config.relays).await?;

        // Create lightning client if NWC URI provided
        let lightning = if let Some(uri) = &config.nwc_uri {
            Some(LightningClient::new(uri).await?)
        } else {
            None
        };

        // Create handler
        let (handler, outbound_rx) = DepositsHandler::new(secret_key, wallet.clone());

        tracing::info!("Node created with ID: {}", node_id);

        Ok(Self {
            node_id,
            wallet,
            nostr,
            lightning,
            handler: Arc::new(handler),
            outbound_rx,
        })
    }

    /// Sync the wallet with the blockchain
    pub fn sync_wallet(&self) -> Result<(), Error> {
        self.wallet.sync()
    }

    /// Start listening for messages
    pub async fn start(&mut self) -> Result<(), Error> {
        self.nostr.start_listening().await?;
        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                // Process inbound messages from nostr
                _ = self.nostr.process_events() => {
                    while let Some(inbound) = self.nostr.try_recv() {
                        self.handle_inbound(inbound);
                    }
                }

                // Send outbound messages via nostr
                Some(outbound) = self.outbound_rx.recv() => {
                    if let Err(e) = self.nostr.send_message(outbound.peer, outbound.message).await {
                        tracing::error!("Failed to send message: {}", e);
                    }
                }

                // Periodic tasks
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                    // Sync wallet periodically
                    if let Err(e) = self.sync_wallet() {
                        tracing::warn!("Wallet sync failed: {}", e);
                    }

                    // Drain and log events
                    let events = self.handler.drain_events();
                    for event in events {
                        tracing::info!("Protocol event: {:?}", event);
                    }
                }
            }
        }
    }

    /// Handle an inbound message
    fn handle_inbound(&self, inbound: InboundMessage) {
        tracing::debug!("Received message from {}", inbound.sender);
        if let Err(e) = self.handler.handle_message(inbound.message, inbound.sender) {
            tracing::error!("Failed to handle message: {}", e);
        }
    }

    /// Get the wallet balance
    pub fn wallet_balance(&self) -> Result<u64, Error> {
        self.wallet.get_wallet_balance()
    }

    /// Get the reserves balance
    pub fn reserves_balance(&self) -> Result<u64, Error> {
        self.wallet.get_reserves_balance()
    }

    /// Get a new address
    pub fn new_address(&self) -> Result<bitcoin::Address, Error> {
        self.wallet.get_new_address()
    }

    /// Create a reserves output
    pub fn create_reserves(
        &self,
        amount_sats: u64,
        partners: Vec<PublicKey>,
        threshold: usize,
    ) -> Result<crate::wallet::ReservesOutput, Error> {
        self.wallet.create_reserves_output(amount_sats, partners, threshold)
    }
}
