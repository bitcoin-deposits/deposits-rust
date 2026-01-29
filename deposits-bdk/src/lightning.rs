// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Lightning integration via NWC (Nostr Wallet Connect)
//!
//! Provides Lightning invoice creation and payment via NWC protocol.

use nostr_sdk::nips::nip47::NostrWalletConnectURI;
use nostr_sdk::nwc::NWC;

use crate::Error;

/// Lightning client using NWC
pub struct LightningClient {
    /// The NWC client
    client: NWC,

    /// Connection URI
    _uri: NostrWalletConnectURI,
}

impl LightningClient {
    /// Create a new Lightning client from an NWC connection string
    ///
    /// The connection string format is:
    /// `nostr+walletconnect://pubkey?relay=wss://...&secret=...`
    pub async fn new(nwc_uri: &str) -> Result<Self, Error> {
        let uri = NostrWalletConnectURI::parse(nwc_uri)
            .map_err(|e| Error::Nwc(format!("Invalid NWC URI: {}", e)))?;

        let client = NWC::new(uri.clone());

        Ok(Self { client, _uri: uri })
    }

    /// Get the wallet's balance in millisatoshis
    pub async fn get_balance(&self) -> Result<u64, Error> {
        self.client
            .get_balance()
            .await
            .map_err(|e| Error::Nwc(format!("get_balance failed: {}", e)))
    }

    /// Create a Lightning invoice
    ///
    /// Returns the BOLT11 invoice string.
    pub async fn make_invoice(
        &self,
        amount_msats: u64,
        description: &str,
        expiry_secs: Option<u64>,
    ) -> Result<String, Error> {
        use nostr_sdk::nips::nip47::MakeInvoiceRequest;

        let request = MakeInvoiceRequest {
            amount: amount_msats,
            description: Some(description.to_string()),
            description_hash: None,
            expiry: expiry_secs,
        };

        let response = self
            .client
            .make_invoice(request)
            .await
            .map_err(|e| Error::Nwc(format!("make_invoice failed: {}", e)))?;

        Ok(response.invoice)
    }

    /// Pay a Lightning invoice
    ///
    /// Returns the preimage on success.
    pub async fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        use nostr_sdk::nips::nip47::PayInvoiceRequest;

        let request = PayInvoiceRequest::new(invoice.to_string());

        let response = self
            .client
            .pay_invoice(request)
            .await
            .map_err(|e| Error::Nwc(format!("pay_invoice failed: {}", e)))?;

        Ok(response.preimage)
    }

    /// Lookup an invoice by payment hash
    pub async fn lookup_invoice(&self, payment_hash: &str) -> Result<InvoiceStatus, Error> {
        use nostr_sdk::nips::nip47::LookupInvoiceRequest;

        let request = LookupInvoiceRequest {
            payment_hash: Some(payment_hash.to_string()),
            invoice: None,
        };

        let response = self
            .client
            .lookup_invoice(request)
            .await
            .map_err(|e| Error::Nwc(format!("lookup_invoice failed: {}", e)))?;

        Ok(InvoiceStatus {
            paid: response.settled_at.is_some(),
            preimage: response.preimage,
            settled_at: response.settled_at.map(|t| t.as_u64()),
        })
    }
}

/// Status of an invoice lookup
#[derive(Debug, Clone)]
pub struct InvoiceStatus {
    /// Whether the invoice has been paid
    pub paid: bool,
    /// The preimage (if paid)
    pub preimage: Option<String>,
    /// When it was settled (if paid)
    pub settled_at: Option<u64>,
}

/// Builder for LightningClient
pub struct LightningClientBuilder {
    uri: String,
}

impl LightningClientBuilder {
    pub fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }

    pub async fn build(self) -> Result<LightningClient, Error> {
        LightningClient::new(&self.uri).await
    }
}
