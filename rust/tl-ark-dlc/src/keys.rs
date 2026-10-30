//! Key provider boundary. Only a **synthetic** (test) provider is implemented.
//!
//! Source: `vtxo-loan-system/src/keys/key-provider.ts`. The legacy local / GCP / AWS providers
//! fetch or hold a BIP-39 mnemonic; real-key custody is deliberately not ported (BIP-39 is not in
//! the allowed dependency set and secrets belong behind a reviewed adapter). The legacy derivation
//! paths are kept so a real adapter can implement [`KeyProvider`] later.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

use crate::error::{Error, Result};
use crate::hash::sha256_bytes;

/// Source of private keys by BIP-32 path.
pub trait KeyProvider {
    /// Derive the 32-byte private key at `path`.
    fn derive_key(&self, path: &str) -> Result<[u8; 32]>;
    /// Label for logging.
    fn provider_type(&self) -> &'static str;
}

/// Deterministic provider for tests: the BIP-32 seed is `sha256("TL-ARK-DLC-SYNTHETIC" || label)`.
pub struct SyntheticKeyProvider {
    root: Xpriv,
}

impl SyntheticKeyProvider {
    /// Build from a label. NOT FOR REAL FUNDS: the seed is public knowledge given the label.
    pub fn from_label(label: &str) -> Result<Self> {
        let mut input = b"TL-ARK-DLC-SYNTHETIC".to_vec();
        input.extend_from_slice(label.as_bytes());
        let seed = sha256_bytes(&input);
        let root = Xpriv::new_master(Network::Regtest, &seed)
            .map_err(|_| Error::Crypto("master key"))?;
        Ok(SyntheticKeyProvider { root })
    }
}

impl KeyProvider for SyntheticKeyProvider {
    fn derive_key(&self, path: &str) -> Result<[u8; 32]> {
        let p = DerivationPath::from_str(path).map_err(|_| Error::Malformed("derivation path"))?;
        let secp = Secp256k1::new();
        let k = self
            .root
            .derive_priv(&secp, &p)
            .map_err(|_| Error::Crypto("derivation"))?;
        Ok(k.private_key.secret_bytes())
    }
    fn provider_type(&self) -> &'static str {
        "synthetic"
    }
}

/// Legacy oracle key path: `m/48'/{coinType}'/0'/0'/0` (coin type 0 mainnet, 1 otherwise).
pub fn oracle_key_path(coin_type: u32) -> String {
    format!("m/48'/{coin_type}'/0'/0'/0")
}

/// Derive the oracle secret from a provider.
pub fn oracle_secret(p: &dyn KeyProvider, coin_type: u32) -> Result<[u8; 32]> {
    p.derive_key(&oracle_key_path(coin_type))
}
