# Bitcoin Deposits NWC Integration Guide

## Part 1: Wallet Integration

The integration is simple: send a DM to the operator's node, receive a scoped NWC connection string, and from there everything is standard NWC. That's the whole thing.

The connection string you get back only works for your deposit—it can't touch other deposits or node funds. You can hand it to any NIP-47 library and call `get_balance`, `make_invoice`, `pay_invoice` as usual. The deposit-specific logic lives entirely in that initial DM exchange.

### Creating a Deposit

You need the operator's NWC pubkey and relay URL. First, generate a deposit keypair locally—the private key never leaves your device:

```python
# Generate deposit keypair locally - private key stays with you
deposit_keypair = generate_secp256k1_keypair()
deposit_pubkey = deposit_keypair.public_key.serialize()  # 33 bytes compressed
deposit_pubkey_hex = hex_encode(deposit_pubkey)          # e.g., "02abc123..."
```

Send a DM to the operator with the deposit pubkey:

```
To: <operator_nwc_pubkey>
Content: "init-deposit 02abc123..."
```

The format is `init-deposit <deposit_pubkey> [channel_id]`. The channel_id is optional.

The node responds with JSON:

```json
{
  "deposit_pubkey": "02abc123...",
  "channel_id": "def456...",
  "balance_sat": 0,
  "nwc_connection_string": "nostr+walletconnect://xyz789...?relay=wss://relay.example.com&secret=secret123...",
  "nwc_private_key": "secret123..."
}
```

**Important**: The `deposit_pubkey` in the response should match what you sent. You have two keypairs now:
- **Deposit keypair** (yours): Used for signing payment authorizations. The private key never touches the server.
- **NWC keypair** (from server): Used for NWC protocol authentication. Server derives this and shares it with you.

The `nwc_connection_string` is what you pass to your NWC library. The NWC key is scoped—attempts to access other deposits will fail.

Why a DM instead of a NIP-47 method? Deposit creation establishes a new trust relationship. The node needs to register the deposit pubkey, derive a scoped NWC key, and return it. That's a side-effecting operation that doesn't fit NIP-47's request/response model, which assumes an existing authenticated session. The DM is the bootstrap.

### Using the Deposit

Once you have the connection string, standard NWC works:

```javascript
const nwc = new NWC(deposit.nwc_connection_string);

const balance = await nwc.getBalance();
const invoice = await nwc.makeInvoice({ amount: 10000 });
await nwc.payInvoice({ invoice: "lnbc1..." });
```

Invoices created through this connection credit your deposit when paid. Payments debit from your deposit balance. The scoping is enforced server-side—the key itself encodes which deposit it can access.

### Deposit-Specific Methods

Beyond standard NIP-47, there are a few deposit-specific methods. Most NWC libraries let you send custom methods.

**`get_deposit_balance`** returns detailed balance info including pending amounts:

```json
{
  "method": "get_deposit_balance",
  "params": { "deposit_pubkey": "02abc123..." }
}
```

**`make_deposit_invoice`** and **`pay_deposit_invoice`** are explicit versions that take a `deposit_pubkey` parameter. Use these if you're working with a node-level key that has access to multiple deposits.

**`submit_fraud_proof`** lets you prove a payment was made if the operator claims otherwise. You submit the preimage; the system verifies `SHA256(preimage) == payment_hash` and broadcasts to auditors. This is the cryptographic escape hatch—if you have the preimage, you can prove you paid.

### Privacy with Gift-Wrapped DMs

For deposit creation, consider using NIP-17 gift-wrapped DMs instead of plain DMs. The structure is:

```
Kind 1059 (Gift Wrap) - signed by ephemeral key
  └─ Encrypted: Kind 13 (Seal) - signed by your key
       └─ Encrypted: Kind 14 (Rumor) - unsigned, "init-deposit"
```

The outer layer uses a throwaway key, so relay operators can't see who's creating deposits. Timestamps are randomized. The inner content is unsigned for deniability.

Why bother? Plain DMs (kind 4) leak metadata—the relay sees your pubkey talking to the operator's pubkey. If you're building a wallet where users might want privacy from the relay operator, gift wrapping matters. If you control the relay or don't care, plain DMs work fine.

### Complete Example

Here's the full flow in pseudocode:

```python
# 1. Generate deposit keypair locally - private key NEVER leaves client
deposit_keypair = generate_secp256k1_keypair()
deposit_pubkey_hex = hex_encode(deposit_keypair.public_key.serialize())

# 2. Create deposit via gift-wrapped DM
dm = nostr.create_gift_wrap(
    sender=wallet_key,
    recipient=OPERATOR_NWC_PUBKEY,
    content=f"init-deposit {deposit_pubkey_hex}"  # Send pubkey in DM
)
relay.publish(dm)

# 3. Wait for response
response = relay.wait_for_dm(from_pubkey=OPERATOR_NWC_PUBKEY)
deposit = json.loads(response.content)

# 4. Verify server echoed back our pubkey
assert deposit["deposit_pubkey"] == deposit_pubkey_hex

# 5. Save BOTH keys:
#    - deposit_keypair: For signing payment authorizations (never sent to server)
#    - nwc_connection_string: For NWC protocol authentication (from server)
wallet.save_deposit(
    deposit_pubkey=deposit_pubkey_hex,
    deposit_secret=deposit_keypair.private_key,  # Keep locally!
    nwc_connection=deposit["nwc_connection_string"]
)

# 6. Use standard NWC from here
nwc = NWCClient(deposit["nwc_connection_string"])
balance = nwc.get_balance()
invoice = nwc.make_invoice(amount_msat=100000)
nwc.pay_invoice(some_invoice)
```

---

## Part 2: Internal Implementation

This section is for developers working on the node software.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ldk-server                              │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │   HTTP API      │  │         NWC Service              │  │
│  │  /deposits/*    │  │  - Relay Connection (WebSocket)  │  │
│  │  /bitcoin/*     │  │  - Access Registry               │  │
│  │  /channels/*    │  │  - Message Handlers              │  │
│  └────────┬────────┘  └──────────────┬───────────────────┘  │
│           │                          │                       │
│           ▼                          ▼                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Bitcoin Deposits Handler                   ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   Nostr Relay    │
                    └──────────────────┘
```

Key files: `src/nwc_service.rs` (main service), `src/nip44.rs` (encryption), `src/bin/nwc-client.rs` (test client).

### Access Control

Every NWC key maps to an access level:

```rust
pub enum NWCAccessLevel {
    Node,                    // Full access to all operations
    Deposit(PublicKey),      // Scoped to single deposit
}
```

The node-level key is registered at startup. Deposit keys are registered when deposits are created. Unregistered keys are silently ignored—deny by default.

When a request comes in, the service checks the signing key against the registry. For deposit-scoped keys, it verifies the requested deposit matches the key's scope. This is why the scoping works: the key itself determines what it can access.

### Key Derivation

Deposit NWC keys are derived deterministically from the NWC service's private key using HKDF:

```rust
fn generate_deposit_nwc_keypair(&self, deposit_pubkey: PublicKey) -> (Keypair, XOnlyPublicKey) {
    // Derive from NWC service's secret key using HKDF
    let nwc_secret = self.keypair.secret_bytes();

    // HKDF: salt provides domain separation, info is the deposit identifier
    let hk = Hkdf::<Sha256>::new(Some(b"nwc-deposit-key-v1"), &nwc_secret);
    let mut secret_bytes = [0u8; 32];
    hk.expand(&deposit_pubkey.serialize(), &mut secret_bytes)
        .expect("HKDF expand");

    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    Keypair::from_secret_key(&self.secp, &secret_key)
}
```

Why deterministic? The node can regenerate any deposit's NWC key from just the deposit pubkey and the NWC service's secret key. No need to persist deposit secrets separately. After a restart, the node rebuilds the access registry by iterating stored deposits and re-deriving their keys.

Why HKDF from the private key? Security requires that only the node operator can derive NWC keys. Using the deposit pubkey directly would be insecure—anyone who knows the pubkey could derive the same secret. HKDF ensures the derivation requires the node's secret key while producing unique keys for each deposit.

### NIP-44 Encryption

NIP-44 uses ECDH to derive a conversation key, then XChaCha20-Poly1305 for encryption:

```rust
pub fn get_conversation_key(our_secret: &SecretKey, their_pubkey: &XOnlyPublicKey) -> [u8; 32] {
    // ECDH - x-coordinate only, NOT hashed
    let shared = their_pubkey.public_key(Parity::Even)
        .mul_tweak(&Scalar::from(our_secret));
    let x_bytes = shared.x_only_public_key().0.serialize();

    // HKDF with NIP-44 salt
    let hk = Hkdf::<Sha256>::new(Some(b"nip44-v2"), &x_bytes);
    let mut conv_key = [0u8; 32];
    hk.expand(&[], &mut conv_key);
    conv_key
}

pub fn encrypt(conv_key: &[u8; 32], plaintext: &str) -> String {
    let padded = pad_plaintext(plaintext.as_bytes());  // Power of 2 padding
    let nonce: [u8; 32] = rand::random();

    let cipher = XChaCha20Poly1305::new(conv_key.into());
    let ciphertext = cipher.encrypt(&nonce.into(), padded.as_ref()).unwrap();

    // Format: version(1) || nonce(32) || ciphertext
    let mut output = vec![2u8];
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    base64::encode(&output)
}
```

### Gift Wrap Creation

Three-layer structure for NIP-17:

```rust
fn create_gift_wrap(sender: &Keypair, recipient: &XOnlyPublicKey, content: &str) -> Event {
    // Layer 1: Rumor (unsigned)
    let rumor = json!({
        "kind": 14,
        "pubkey": sender.x_only_public_key().0.to_string(),
        "created_at": randomized_timestamp(),  // 0-48h in past
        "tags": [["p", recipient.to_string()]],
        "content": content
    });

    // Layer 2: Seal (encrypts rumor, signed by sender)
    let seal_key = get_conversation_key(&sender.secret_key(), recipient);
    let encrypted_rumor = encrypt(&seal_key, &rumor.to_string());
    let seal = sign_event(sender, 13, encrypted_rumor, vec![]);

    // Layer 3: Gift wrap (encrypts seal, signed by ephemeral key)
    let ephemeral = Keypair::new_random();
    let wrap_key = get_conversation_key(&ephemeral.secret_key(), recipient);
    let encrypted_seal = encrypt(&wrap_key, &seal.to_string());
    sign_event(&ephemeral, 1059, encrypted_seal, vec![["p", recipient.to_string()]])
}
```

### Event Loop

The service subscribes to DMs, gift-wraps, and NIP-47 requests addressed to any registered key:

```rust
impl NWCService {
    pub async fn run(&self) {
        loop {
            let ws = connect_relay(&self.relay_url).await;

            ws.send(json!(["REQ", "nwc", {
                "kinds": [4, 1059, 23194],
                "#p": self.get_all_registered_pubkeys()
            }])).await;

            while let Some(msg) = ws.next().await {
                let event = parse_event(&msg);
                if self.processed_events.contains(&event.id) { continue; }
                self.processed_events.insert(event.id.clone());

                match event.kind {
                    4 => self.handle_dm(event, false).await,
                    1059 => self.handle_dm(event, true).await,
                    23194 => self.handle_nip47_request(event).await,
                    _ => {}
                }
            }
        }
    }
}
```

### Deposit Creation Handler

```rust
async fn process_deposit_dm(&self, sender: &str, content: &str, use_gift_wrap: bool) {
    // Format: "init-deposit <deposit_pubkey> [channel_id]"
    // Client MUST provide the deposit_pubkey - we don't generate it
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "init-deposit" {
        return self.send_error(sender, "Format: init-deposit <deposit_pubkey> [channel_id]");
    }

    let deposit_pubkey_str = parts[1];
    let channel_id = parts.get(2).map(|s| *s);

    // Parse the client-provided deposit pubkey
    let deposit_pubkey = match parse_pubkey(deposit_pubkey_str) {
        Ok(pk) => pk,
        Err(e) => return self.send_error(sender, &format!("Invalid deposit_pubkey: {}", e)),
    };

    // Find available channel or use specified one
    let channel_id = self.resolve_channel_id(channel_id).await;

    // Create deposit entry with the client's pubkey
    self.create_deposit(channel_id, deposit_pubkey).await;

    // Derive NWC key deterministically from our secret + deposit pubkey
    // This is safe: only we can derive this, and client needs it for NWC auth
    let nwc_key = derive_deposit_nwc_key(&deposit_pubkey, &self.node_keypair);
    self.access_registry.insert(nwc_key.public_key(), NWCAccessLevel::Deposit(deposit_pubkey));

    // Respond with the NWC credentials (NOT the deposit private key - client has that)
    let response = json!({
        "deposit_pubkey": deposit_pubkey_str,  // Echo back what client sent
        "channel_id": channel_id.to_string(),
        "balance_sat": 0,
        "nwc_connection_string": format!(
            "nostr+walletconnect://{}?relay={}&secret={}",
            nwc_key.public_key(), self.relay_url, nwc_key.display_secret()
        ),
        "nwc_private_key": nwc_key.display_secret().to_string()
    });

    if use_gift_wrap {
        self.send_gift_wrap(sender, &response.to_string()).await;
    } else {
        self.send_dm(sender, &response.to_string()).await;
    }
}
```

### Testing

The `nwc-client` binary exercises the full flow:

```bash
./target/release/nwc-client -w wallet.json init-node
./target/release/nwc-client -w wallet.json init-deposit
./target/release/nwc-client -w wallet.json deposit-balance <pubkey>
./target/release/nwc-client -w wallet.json make-deposit-invoice --deposit <pubkey> --amount 10000
./target/release/nwc-client -w wallet.json pay-deposit-invoice --deposit <pubkey> --invoice lnbc1...
```

---

## Reference

### Error Codes

| Code | Meaning |
|------|---------|
| `UNAUTHORIZED` | Key not registered or wrong scope |
| `INSUFFICIENT_BALANCE` | Not enough funds |
| `INVALID_DEPOSIT` | Deposit not found |
| `PAYMENT_FAILED` | Lightning payment failed |
| `INVALID_INVOICE` | Malformed invoice |

### Timeouts

| Operation | Timeout |
|-----------|---------|
| Standard requests | 30s |
| Payments | 90s |
| DM responses | 30s |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NOSTR_RELAY_URL` | `ws://localhost:7777` | Relay endpoint |
| `NWC_PRIVATE_KEY` | (derived) | Override node NWC key |
| `LDK_DATA_DIR` | `/tmp/ldk` | Data persistence |
