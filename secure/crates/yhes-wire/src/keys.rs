//! Public keys, key identifiers and digests. All cryptography is delegated to
//! `ed25519-dalek`, `p256` and `sha2`.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::error::Error;

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// Ed25519; 32-byte public key, 64-byte signature.
    Ed25519,
    /// ECDSA P-256 with SHA-256; 65-byte uncompressed SEC1 key, 64-byte `r||s`.
    P256Sha256,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ed25519",
            Algorithm::P256Sha256 => "p256-sha256",
        }
    }

    pub fn parse(s: &str) -> Result<Algorithm, Error> {
        match s {
            "ed25519" => Ok(Algorithm::Ed25519),
            "p256-sha256" => Ok(Algorithm::P256Sha256),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Digest {
        Digest(Sha256::digest(bytes).into())
    }

    /// Parses exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Result<Digest, Error> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return Err(Error::Schema("digest is not 64 lowercase hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, pair) in b.chunks_exact(2).enumerate() {
            out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Digest(out))
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

fn nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::Schema("digest is not 64 lowercase hex characters")),
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(TABLE[(b >> 4) as usize] as char);
        s.push(TABLE[(b & 15) as usize] as char);
    }
    s
}

/// Key identifier: `k_` followed by 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn parse(s: &str) -> Result<KeyId, Error> {
        let hex_part = s.strip_prefix("k_").ok_or(Error::InvalidId("key_id"))?;
        Digest::from_hex(hex_part).map_err(|_| Error::InvalidId("key_id"))?;
        Ok(KeyId(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated raw public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: Algorithm,
    raw: Vec<u8>,
}

impl PublicKey {
    /// Accepts a 32-byte Ed25519 key or a 65-byte uncompressed SEC1 P-256 point.
    /// Small-order Ed25519 keys and points off the curve are rejected.
    pub fn new(algorithm: Algorithm, raw: &[u8]) -> Result<PublicKey, Error> {
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519(raw)?;
            }
            Algorithm::P256Sha256 => {
                p256_key(raw)?;
            }
        }
        Ok(PublicKey {
            algorithm,
            raw: raw.to_vec(),
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// `k_` + SHA-256(`"agent-yhes/key/v1\0"` + algorithm + `"\0"` + raw key).
    pub fn key_id(&self) -> KeyId {
        let mut h = Sha256::new();
        h.update(b"agent-yhes/key/v1\0");
        h.update(self.algorithm.as_str().as_bytes());
        h.update(b"\0");
        h.update(&self.raw);
        let digest: [u8; 32] = h.finalize().into();
        KeyId(format!("k_{}", hex(&digest)))
    }

    /// Verifies a 64-byte signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
        match self.algorithm {
            Algorithm::Ed25519 => {
                let key = ed25519(&self.raw)?;
                let sig = ed25519_dalek::Signature::from_bytes(signature);
                key.verify_strict(message, &sig)
                    .map_err(|_| Error::BadSignature)
            }
            Algorithm::P256Sha256 => {
                use p256::ecdsa::signature::Verifier as _;
                let key = p256_key(&self.raw)?;
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::BadSignature)?;
                key.verify(message, &sig).map_err(|_| Error::BadSignature)
            }
        }
    }
}

fn ed25519(raw: &[u8]) -> Result<ed25519_dalek::VerifyingKey, Error> {
    let bytes: &[u8; 32] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Error::InvalidKey)?;
    if key.is_weak() {
        return Err(Error::InvalidKey);
    }
    Ok(key)
}

fn p256_key(raw: &[u8]) -> Result<p256::ecdsa::VerifyingKey, Error> {
    if raw.len() != 65 || raw[0] != 0x04 {
        return Err(Error::InvalidKey);
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| Error::InvalidKey)
}
