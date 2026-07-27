//! `deposits-ringsig link` — anonymous web-of-trust attestation request (NIP-XX).
//!
//! Standalone version of the flow that used to live as
//! `deposits-wallet ringsig-link`. Drives the first-contact handshake
//! against a verifier whose Kind 35500 cover lists the wallet's
//! identity npub:
//!
//!   1. Fetch the verifier's cover (kind 35500) from the relay,
//!      keyed on `(author = verifier_npub, #d = cover_d_tag)`.
//!   2. Find a ring whose members include the wallet's own xonly
//!      pubkey. Bail if none — the wallet's npub isn't in this
//!      verifier's web of trust, and ring membership can't be
//!      conjured up locally.
//!   3. Generate a fresh BIP-340 bound key `(sk_P, P)`. This is the
//!      identity that will eventually open deposits against an
//!      operator; the wallet's long-term seed-derived key never
//!      gets exposed to the operator.
//!   4. Compute the canonical event digest (with the `ringsig` and
//!      `binding` tags excluded), produce a bLSAG ring signature
//!      under the wallet's identity key, and produce a Schnorr
//!      binding proof tying `P` to that ring sig.
//!   5. Publish the kind 25502 first-contact event signed by `P`,
//!      wait for the verifier's kind 25503 reply.
//!   6. On `Accepted { attestation_event_id }`: persist `sk_P` to
//!      the data dir under a user-chosen alias and append a record
//!      to `ringsig.json`. The user can then open deposits with
//!      `deposits-wallet open <ledger> --nsec-file <alias>.nsec`.
//!
//! Usage:
//!
//!   deposits-ringsig link <verifier_npub> \
//!       --nsec-file <path>          # wallet's identity nsec
//!       --relay <wss://...>         # repeatable
//!       [--cover-d <id>]            # default: "default"
//!       [--alias <name>]            # default: "ringsig-<8-char-bound>"
//!       [--data-dir <path>]         # default: ~/.deposits-wallet

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{All, PublicKey as SecpPubKey, Secp256k1, SecretKey as SecpSk};
use deposits_ringsig::wire::{
    binding_to_hex, canonical_event_digest, ringsig_to_hex, Cover, RingsigRequest, RingsigResponse,
    KIND_RINGSIG_COVER, KIND_RINGSIG_REQUEST, KIND_RINGSIG_RESPONSE,
};
use deposits_ringsig::{binding, blsag, hash_point, presentation_nullifier};
use nostr_sdk::prelude::*;
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut iter = args.iter().skip(1);
    let subcmd = match iter.next() {
        Some(s) => s.as_str(),
        None => {
            print_usage(&args[0]);
            return Ok(());
        }
    };

    match subcmd {
        "link" => {
            let rest: Vec<String> = iter.cloned().collect();
            link(&rest).await
        }
        "-h" | "--help" | "help" => {
            print_usage(&args[0]);
            Ok(())
        }
        other => {
            eprintln!("Unknown subcommand: {}", other);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("deposits-ringsig — anonymous web-of-trust attestation");
    eprintln!();
    eprintln!("Usage: {} link <verifier_npub> [options]", prog);
    eprintln!();
    eprintln!("Required:");
    eprintln!("  --nsec-file <path>   Path to wallet identity nsec (hex or nsec1…)");
    eprintln!("  --relay <url>        Nostr relay URL (repeatable)");
    eprintln!();
    eprintln!("Optional:");
    eprintln!("  --cover-d <id>       Verifier cover d-tag (default: \"default\")");
    eprintln!("  --alias <name>       Local alias for the bound nsec");
    eprintln!("                       (default: \"ringsig-<8-char-bound>\")");
    eprintln!("  --data-dir <path>    Where to persist bound nsec + ringsig.json");
    eprintln!("                       (default: ~/.deposits-wallet)");
    eprintln!();
    eprintln!("Example:");
    eprintln!(
        "  {} link npub1... --nsec-file ~/.deposits-wallet/wallet.nsec \\",
        prog
    );
    eprintln!("        --relay wss://relay.bitcoindeposits.net");
}

async fn link(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // ── arg parsing ─────────────────────────────────────────────────
    let mut verifier_arg: Option<String> = None;
    let mut nsec_path: Option<PathBuf> = None;
    let mut relays: Vec<String> = Vec::new();
    let mut cover_d_tag = String::from("default");
    let mut alias_arg: Option<String> = None;
    let mut data_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--nsec-file" if i + 1 < args.len() => {
                nsec_path = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--relay" if i + 1 < args.len() => {
                relays.push(args[i + 1].clone());
                i += 1;
            }
            "--cover-d" if i + 1 < args.len() => {
                cover_d_tag = args[i + 1].clone();
                i += 1;
            }
            "--alias" if i + 1 < args.len() => {
                alias_arg = Some(args[i + 1].clone());
                i += 1;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option: {}", s).into());
            }
            _ => {
                if verifier_arg.is_none() {
                    verifier_arg = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let verifier_arg = verifier_arg
        .ok_or("Usage: deposits-ringsig link <verifier_npub> --nsec-file <path> --relay <url>")?;
    let verifier_xonly = parse_xonly_arg(&verifier_arg)?;
    let nsec_path = nsec_path.ok_or("--nsec-file is required")?;
    if relays.is_empty() {
        return Err("at least one --relay is required".into());
    }
    let data_dir = data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".deposits-wallet")
    });

    println!("ringsig-link");
    println!("  verifier: {}…", &verifier_xonly[..16]);
    println!("  cover:    {}", cover_d_tag);

    // ── wallet identity → BIP-340 even-y ───────────────────────────
    //
    // The wallet's stored nsec may produce an odd-y pubkey, but the
    // cover stores members as 32-byte xonly hex. Lifting those back
    // to a curve point assumes even-y; if our key has odd-y the
    // lifted point is the negation of our true pubkey and the ring
    // signature won't verify. Normalize once up front.
    let secp = Secp256k1::new();
    let our_sk_raw = load_nsec_file(&nsec_path)?;
    let (our_sk, our_pk) = to_bip340(&secp, our_sk_raw);
    let our_xonly = hex::encode(&our_pk.serialize()[1..]);
    println!("  our npub: {}…", &our_xonly[..16]);

    // ── connect, fetch cover ───────────────────────────────────────
    let our_keys = Keys::new(SecretKey::from_slice(&our_sk.secret_bytes())?);
    let client = Client::new(our_keys.clone());
    for r in &relays {
        client.add_relay(r).await?;
    }
    client.connect().await;

    let verifier_pk_nostr = PublicKey::from_hex(&verifier_xonly)?;
    // Relay subscriptions take a moment to settle after `connect()`,
    // and a freshly-published parameterized-replaceable can occasionally
    // be missed by an immediate fetch. Retry a few times before giving up.
    //
    // We deliberately don't include `author` or `#d` in the relay-side
    // filter — strfry has been observed to occasionally withhold
    // parameterized-replaceable events from queries that combine kind
    // with those filters when the event was very recently rewritten.
    // Pull all kind:35500 (small set in practice) and filter
    // application-side for `(author == verifier, d == cover_d_tag)`.
    let cover_filter = Filter::new()
        .kind(Kind::Custom(KIND_RINGSIG_COVER))
        .limit(50);
    let mut cover_event = None;
    for attempt in 0..5 {
        let events = client
            .fetch_events(vec![cover_filter.clone()], Some(Duration::from_secs(5)))
            .await?;
        let mut filtered: Vec<_> = events
            .into_iter()
            .filter(|e| {
                e.pubkey == verifier_pk_nostr
                    && e.tags.iter().any(|t| {
                        let v = t.clone().to_vec();
                        v.first().map(String::as_str) == Some("d")
                            && v.get(1).map(String::as_str) == Some(cover_d_tag.as_str())
                    })
            })
            .collect();
        if let Some(latest) = filtered.drain(..).max_by_key(|e| e.created_at.as_u64()) {
            cover_event = Some(latest);
            break;
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    let cover_event =
        cover_event.ok_or_else(|| format!("cover `{}` not found on relay", cover_d_tag))?;
    let cover_event_id = cover_event.id.to_hex();
    let cover_tag_rows: Vec<Vec<String>> = cover_event
        .tags
        .iter()
        .map(|t| t.clone().to_vec())
        .collect();
    let cover = Cover::from_tags(&cover_tag_rows).map_err(|e| format!("malformed cover: {}", e))?;

    // ── find a ring containing our pubkey ──────────────────────────
    let our_ring = cover
        .rings
        .iter()
        .find(|r| r.members.iter().any(|m| m.eq_ignore_ascii_case(&our_xonly)))
        .ok_or(
            "your npub is not in any ring of this verifier's cover. \
             Ask the cover anchor to follow you, or pick a verifier whose web of trust includes you.",
        )?;
    println!(
        "  ring:     {} ({} members)",
        our_ring.id,
        our_ring.members.len()
    );

    // Lift each member to an even-y SecpPubKey for bLSAG.
    let mut ring_pks: Vec<SecpPubKey> = Vec::with_capacity(our_ring.members.len());
    for m in &our_ring.members {
        ring_pks.push(lift_xonly(m)?);
    }
    let signer_index = our_ring
        .members
        .iter()
        .position(|m| m.eq_ignore_ascii_case(&our_xonly))
        .expect("ring membership confirmed above");

    // ── generate bound key ─────────────────────────────────────────
    let (bound_sk, bound_pk) = to_bip340(&secp, SecpSk::new(&mut OsRng));
    let bound_xonly = hex::encode(&bound_pk.serialize()[1..]);
    println!("  bound:    {}…", &bound_xonly[..16]);

    // ── construct + sign the first-contact event ───────────────────
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Precompute key image so the presentation nullifier can land in
    // the digest tags. `blsag::sign` will recompute the same I from
    // (sk, P_π) and we'd see a mismatch later if these diverged, but
    // they don't: I depends only on the signer's secret and pubkey.
    let h_signer = hash_point(&our_pk.serialize());
    let key_image = h_signer.mul_tweak(
        &secp,
        &bitcoin::secp256k1::Scalar::from_be_bytes(our_sk.secret_bytes())?,
    )?;
    let ctx = format!("{}/{}", verifier_xonly, cover.d_tag);
    let nullifier_bytes = presentation_nullifier(&key_image, ctx.as_bytes());

    let content_json = serde_json::to_string(&RingsigRequest::FirstContact {
        payload: serde_json::json!({}),
    })?;

    let digest_tags: Vec<Vec<String>> = vec![
        vec!["p".to_string(), verifier_xonly.clone()],
        vec![
            "cover".to_string(),
            cover_d_tag.clone(),
            cover_event_id.clone(),
        ],
        vec!["ring".to_string(), our_ring.id.clone()],
        vec!["nullifier".to_string(), hex::encode(nullifier_bytes)],
    ];

    let digest = canonical_event_digest(
        &bound_xonly,
        created_at,
        KIND_RINGSIG_REQUEST,
        &digest_tags,
        &content_json,
    );

    let ring_sig = blsag::sign(&secp, &ring_pks, signer_index, &our_sk, &digest, &mut OsRng)
        .map_err(|e| format!("ring sign: {:?}", e))?;
    let binding_proof = binding::prove(&secp, &bound_sk, &ring_sig, &mut OsRng)
        .map_err(|e| format!("binding prove: {:?}", e))?;

    let mut final_rows = digest_tags.clone();
    final_rows.push(vec!["ringsig".to_string(), ringsig_to_hex(&ring_sig)]);
    final_rows.push(vec!["binding".to_string(), binding_to_hex(&binding_proof)]);
    let final_tags: Vec<Tag> = final_rows
        .into_iter()
        .map(|row| {
            let kind = TagKind::Custom(row[0].clone().into());
            let values: Vec<String> = row.into_iter().skip(1).collect();
            Tag::custom(kind, values)
        })
        .collect();

    let bound_keys = Keys::new(SecretKey::from_slice(&bound_sk.secret_bytes())?);
    let first_contact = EventBuilder::new(Kind::Custom(KIND_RINGSIG_REQUEST), &content_json)
        .tags(final_tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(&bound_keys)?;
    let req_id = first_contact.id.to_hex();

    // Use a separate Client signed as the bound key — this is what
    // sends + receives the response. Subscribing on this client lets
    // the relay route the kind 25503 to us via #p=bound_xonly.
    let bound_client = Client::new(bound_keys.clone());
    for r in &relays {
        bound_client.add_relay(r).await?;
    }
    bound_client.connect().await;

    let resp_filter = Filter::new()
        .kind(Kind::Custom(KIND_RINGSIG_RESPONSE))
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            [bound_xonly.as_str()],
        )
        .since(Timestamp::now());
    bound_client.subscribe(vec![resp_filter], None).await?;

    bound_client.send_event(first_contact).await?;
    println!("Sent first-contact event {}…", &req_id[..16]);
    println!("Waiting for verifier response (up to 30s)…");

    let mut rx = bound_client.notifications();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut response: Option<RingsigResponse> = None;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let recv = tokio::time::timeout(remaining, rx.recv()).await;
        let notif = match recv {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if let RelayPoolNotification::Event { event, .. } = notif {
            if event.kind.as_u16() != KIND_RINGSIG_RESPONSE {
                continue;
            }
            let matches = event.tags.iter().any(|t| {
                let v = t.clone().to_vec();
                v.first().map(String::as_str) == Some("e")
                    && v.get(1).map(String::as_str) == Some(req_id.as_str())
            });
            if !matches {
                continue;
            }
            if let Ok(r) = serde_json::from_str::<RingsigResponse>(&event.content) {
                response = Some(r);
                break;
            }
        }
    }
    let resp = response.ok_or("verifier did not respond within 30s")?;
    let attestation_id = match resp {
        RingsigResponse::Accepted {
            attestation_event_id,
            ..
        } => attestation_event_id.unwrap_or_else(|| "(none)".to_string()),
        RingsigResponse::Rejected { code, message } => {
            return Err(format!("verifier rejected: code={} message={:?}", code, message).into());
        }
    };

    // ── persist bound key + metadata ───────────────────────────────
    let alias = alias_arg.unwrap_or_else(|| format!("ringsig-{}", &bound_xonly[..8]));
    std::fs::create_dir_all(&data_dir)?;
    let bound_path = data_dir.join(format!("{}.nsec", alias));
    std::fs::write(&bound_path, hex::encode(bound_sk.secret_bytes()))?;

    let meta_path = data_dir.join("ringsig.json");
    let mut meta: serde_json::Value = std::fs::read_to_string(&meta_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!([]));
    if let Some(arr) = meta.as_array_mut() {
        arr.push(serde_json::json!({
            "alias": alias,
            "bound_xonly": bound_xonly,
            "verifier": verifier_xonly,
            "cover_d_tag": cover_d_tag,
            "cover_event_id": cover_event_id,
            "ring_id": our_ring.id,
            "attestation_event_id": attestation_id,
            "created_at": created_at,
        }));
    }
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;

    println!();
    println!("Verified.");
    println!(
        "  attestation: {}…",
        &attestation_id[..16.min(attestation_id.len())]
    );
    println!("  bound nsec:  {}", bound_path.display());
    println!();
    println!("Use this identity for deposits with:");
    println!(
        "  deposits-wallet open <ledger_id> --alias <name> --nsec-file {}",
        bound_path.display()
    );

    Ok(())
}

// ─── helpers ────────────────────────────────────────────────────────────

fn to_bip340(secp: &Secp256k1<All>, sk: SecpSk) -> (SecpSk, SecpPubKey) {
    let pk = sk.public_key(secp);
    if pk.serialize()[0] == 0x02 {
        (sk, pk)
    } else {
        let sk_neg = sk.negate();
        let pk_neg = sk_neg.public_key(secp);
        debug_assert_eq!(pk_neg.serialize()[0], 0x02);
        (sk_neg, pk_neg)
    }
}

fn lift_xonly(xonly_hex: &str) -> Result<SecpPubKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(xonly_hex.trim())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte xonly pubkey, got {} bytes", bytes.len()).into());
    }
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&bytes);
    Ok(SecpPubKey::from_slice(&compressed)?)
}

fn parse_xonly_arg(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.starts_with("npub1") {
        let pk = PublicKey::parse(s).map_err(|e| format!("invalid npub: {}", e))?;
        return Ok(pk.to_hex());
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s.to_lowercase());
    }
    if s.len() == 66 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s[2..].to_lowercase());
    }
    Err(format!("expected npub1… or 64-char hex pubkey, got {:?}", s).into())
}

fn load_nsec_file(path: &std::path::Path) -> Result<SecpSk, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("--nsec-file {}: {}", path.display(), e))?;
    let trimmed = raw.trim();
    let bytes = if trimmed.starts_with("nsec1") {
        // Bech32 nsec — let nostr_sdk decode.
        let key = SecretKey::from_bech32(trimmed).map_err(|e| {
            format!(
                "--nsec-file {}: invalid nsec1 bech32: {}",
                path.display(),
                e
            )
        })?;
        key.as_secret_bytes().to_vec()
    } else {
        hex::decode(trimmed)
            .map_err(|e| format!("--nsec-file {}: invalid hex: {}", path.display(), e))?
    };
    if bytes.len() != 32 {
        return Err(format!(
            "--nsec-file {}: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
        .into());
    }
    SecpSk::from_slice(&bytes).map_err(|e| format!("--nsec-file {}: {}", path.display(), e).into())
}
