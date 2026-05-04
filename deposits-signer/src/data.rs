//! On-disk state for a `deposits-signer` instance.
//!
//! Layout under `--data-dir`:
//!
//! ```text
//!   transport_secret   — 32-byte hex, 0600. Never logged.
//!   transport_pubkey   — 33-byte hex (compressed), 0644. For human reference
//!                        + paste into the daemon's --signer-pubkey arg.
//!   seed               — 32-byte hex, 0600. The operator/identity seed.
//!   allowlist          — newline-separated 33-byte hex node pubkeys, 0644.
//! ```
//!
//! All files are simple plain-text: trivially inspectable and easily
//! handled by config-management tools. The signer enforces 0600 on
//! `transport_secret` and `seed` at write time; permissions are not
//! re-checked on every load (the runtime depends on filesystem ACLs).

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex parse: {0}")]
    Hex(String),
    #[error("malformed key: {0}")]
    Key(String),
    #[error("data-dir already initialized at {0}")]
    AlreadyInitialized(PathBuf),
    #[error("data-dir not initialized at {0}; run `deposits-signer init` first")]
    NotInitialized(PathBuf),
}

pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn transport_secret_path(&self) -> PathBuf {
        self.root.join("transport_secret")
    }
    pub fn transport_pubkey_path(&self) -> PathBuf {
        self.root.join("transport_pubkey")
    }
    pub fn seed_path(&self) -> PathBuf {
        self.root.join("seed")
    }
    pub fn allowlist_path(&self) -> PathBuf {
        self.root.join("allowlist")
    }
    pub fn policy_path(&self) -> PathBuf {
        self.root.join("anti_equivocation.json")
    }

    /// True if the data dir already has a transport keypair. We use this
    /// as the init/not-init signal — `seed` is optional (the operator may
    /// later import it via a separate command), but a transport key is
    /// always present after init.
    pub fn is_initialized(&self) -> bool {
        self.transport_secret_path().exists()
    }

    /// Generate a new transport keypair and write the data-dir scaffolding.
    /// Optionally seed-import in the same call.
    pub fn init(&self, seed: Option<&[u8; 32]>) -> Result<TransportKey, DataError> {
        if self.is_initialized() {
            return Err(DataError::AlreadyInitialized(self.root.clone()));
        }

        if !self.root.exists() {
            fs::create_dir_all(&self.root)?;
        }

        let transport = TransportKey::random();
        write_secret(&self.transport_secret_path(), &hex::encode(transport.secret_bytes()))?;
        write_public(
            &self.transport_pubkey_path(),
            &hex::encode(transport.public.serialize()),
        )?;
        // Empty allowlist by default; admin must `trust add` a node.
        write_public(&self.allowlist_path(), "")?;

        if let Some(seed_bytes) = seed {
            write_secret(&self.seed_path(), &hex::encode(seed_bytes))?;
        }

        Ok(transport)
    }

    pub fn load_transport(&self) -> Result<TransportKey, DataError> {
        if !self.is_initialized() {
            return Err(DataError::NotInitialized(self.root.clone()));
        }
        let hexstr = fs::read_to_string(self.transport_secret_path())?;
        let secret = parse_secret(hexstr.trim())?;
        Ok(TransportKey::from_secret(secret))
    }

    pub fn load_seed(&self) -> Result<Option<[u8; 32]>, DataError> {
        let path = self.seed_path();
        if !path.exists() {
            return Ok(None);
        }
        let hexstr = fs::read_to_string(&path)?;
        let bytes = hex::decode(hexstr.trim())
            .map_err(|e| DataError::Hex(format!("seed: {}", e)))?;
        if bytes.len() != 32 {
            return Err(DataError::Key(format!(
                "seed must be 32 bytes hex, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// Set or replace the seed file.
    pub fn write_seed(&self, seed: &[u8; 32]) -> Result<(), DataError> {
        if !self.is_initialized() {
            return Err(DataError::NotInitialized(self.root.clone()));
        }
        write_secret(&self.seed_path(), &hex::encode(seed))?;
        Ok(())
    }

    pub fn load_allowlist(&self) -> Result<Vec<PublicKey>, DataError> {
        if !self.is_initialized() {
            return Err(DataError::NotInitialized(self.root.clone()));
        }
        let raw = fs::read_to_string(self.allowlist_path()).unwrap_or_default();
        let mut out = Vec::new();
        for (lineno, line) in raw.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let bytes = hex::decode(trimmed)
                .map_err(|e| DataError::Hex(format!("allowlist line {}: {}", lineno + 1, e)))?;
            let pk = PublicKey::from_slice(&bytes).map_err(|e| {
                DataError::Key(format!("allowlist line {}: {}", lineno + 1, e))
            })?;
            out.push(pk);
        }
        Ok(out)
    }

    pub fn add_allowlist(&self, pk: &PublicKey) -> Result<bool, DataError> {
        let mut current = self.load_allowlist()?;
        if current.iter().any(|existing| existing == pk) {
            return Ok(false);
        }
        current.push(*pk);
        let body = current
            .iter()
            .map(|p| hex::encode(p.serialize()))
            .collect::<Vec<_>>()
            .join("\n");
        write_public(&self.allowlist_path(), &(body + "\n"))?;
        Ok(true)
    }
}

#[derive(Debug)]
pub struct TransportKey {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl TransportKey {
    pub fn random() -> Self {
        use secp256k1::rand::rngs::OsRng;
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let (sk_local, _) = secp.generate_keypair(&mut OsRng);
        let secret = SecretKey::from_slice(&sk_local.secret_bytes())
            .expect("secp256k1 keygen produced a valid secret");
        Self::from_secret(secret)
    }

    pub fn from_secret(secret: SecretKey) -> Self {
        let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
        let public = PublicKey::from_secret_key(&secp, &secret);
        Self { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }
}

fn write_secret(path: &Path, body: &str) -> Result<(), DataError> {
    let mut f = fs::File::create(path)?;
    f.write_all(body.as_bytes())?;
    f.write_all(b"\n")?;
    let mut perms = f.metadata()?.permissions();
    perms.set_mode(0o600);
    f.set_permissions(perms)?;
    Ok(())
}

fn write_public(path: &Path, body: &str) -> Result<(), DataError> {
    let mut f = fs::File::create(path)?;
    f.write_all(body.as_bytes())?;
    if !body.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    let mut perms = f.metadata()?.permissions();
    perms.set_mode(0o644);
    f.set_permissions(perms)?;
    Ok(())
}

fn parse_secret(hexstr: &str) -> Result<SecretKey, DataError> {
    let bytes = hex::decode(hexstr).map_err(|e| DataError::Hex(format!("secret: {}", e)))?;
    SecretKey::from_slice(&bytes).map_err(|e| DataError::Key(format!("secret: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tempdir() -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("deposits-signer-test-{}", rand_suffix()));
        p
    }

    fn rand_suffix() -> String {
        use secp256k1::rand::rngs::OsRng;
        use secp256k1::rand::RngCore;
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    #[test]
    fn init_round_trips_transport_key() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        assert!(!dd.is_initialized());
        let key1 = dd.init(None).unwrap();
        assert!(dd.is_initialized());
        let key2 = dd.load_transport().unwrap();
        assert_eq!(key1.public, key2.public);
        assert_eq!(key1.secret_bytes(), key2.secret_bytes());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_writes_secret_with_0600() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        dd.init(None).unwrap();
        let perms = fs::metadata(dd.transport_secret_path())
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_refuses_already_initialized() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        dd.init(None).unwrap();
        let err = dd.init(None).unwrap_err();
        assert!(matches!(err, DataError::AlreadyInitialized(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_add_and_load() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        dd.init(None).unwrap();
        let pk1 = TransportKey::random().public;
        let pk2 = TransportKey::random().public;
        assert!(dd.load_allowlist().unwrap().is_empty());
        assert!(dd.add_allowlist(&pk1).unwrap());
        assert!(dd.add_allowlist(&pk2).unwrap());
        assert!(!dd.add_allowlist(&pk1).unwrap()); // dup → false
        let listed = dd.load_allowlist().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&pk1));
        assert!(listed.contains(&pk2));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_round_trip() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        let seed = [0xAB; 32];
        dd.init(Some(&seed)).unwrap();
        let loaded = dd.load_seed().unwrap();
        assert_eq!(loaded, Some(seed));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_seed_after_init() {
        let dir = tempdir();
        let dd = DataDir::new(&dir);
        dd.init(None).unwrap();
        assert_eq!(dd.load_seed().unwrap(), None);
        let seed = [0x99; 32];
        dd.write_seed(&seed).unwrap();
        assert_eq!(dd.load_seed().unwrap(), Some(seed));
        let _ = fs::remove_dir_all(&dir);
    }
}
