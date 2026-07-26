//! SHA-256, Ed25519 and SLIP-0010 — `spec/01-canonicalization-and-crypto.md` §1, §4, §6.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Result, err};

/// Length of a SHA-256 digest in octets.
pub const DIGEST_LEN: usize = 32;
/// Length of an Ed25519 public key in octets.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in octets.
pub const SIGNATURE_LEN: usize = 64;

/// SHA-256, lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256, raw digest.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    Sha256::digest(data).into()
}

/// Sign `message` with an Ed25519 secret key (the 32-octet RFC 8032 seed).
///
/// Pure Ed25519 over the message octets; Ed25519ph MUST NOT be used (§01 §5.1).
#[must_use]
pub fn sign(secret_key: &[u8; 32], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    SigningKey::from_bytes(secret_key).sign(message).to_bytes()
}

/// The public key corresponding to a secret key.
#[must_use]
pub fn public_key_of(secret_key: &[u8; 32]) -> [u8; PUBLIC_KEY_LEN] {
    SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

/// Strictly verify an Ed25519 signature.
///
/// Strict verification rejects small-order public keys and non-canonically encoded scalars, which
/// is required by §01 §4: permissive verifiers admit signature malleability and repudiation.
#[must_use]
pub fn verify_strict(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    if verifying_key.is_weak() {
        return false;
    }
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Decode a lowercase-hex octet string of exactly `N` octets.
///
/// # Errors
///
/// `encoding-not-lowercase-hex` if the input is not exactly `2 * N` lowercase hex digits.
pub fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err!(
            "encoding-not-lowercase-hex",
            "expected {} lowercase hex digits, got {s:?}",
            N * 2
        ));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|e| err!("encoding-not-lowercase-hex", "{e}"))?;
    Ok(out)
}

/// True if `s` is exactly 64 lowercase hex digits (a SHA-256 digest).
#[must_use]
pub fn is_digest_hex(s: &str) -> bool {
    s.len() == DIGEST_LEN * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// SLIP-0010 hardened derivation for the `ed25519` curve — §01 §6.
pub mod slip10 {
    use super::{Hmac, KeyInit, Mac, Sha512, err};
    use crate::error::Result;

    /// The hardened-index offset (2^31).
    pub const HARDENED: u32 = 0x8000_0000;

    /// A derived node: private key and chain code.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Node {
        /// The 32-octet ed25519 private key.
        pub private_key: [u8; 32],
        /// The 32-octet chain code.
        pub chain_code: [u8; 32],
    }

    fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn split(i: [u8; 64]) -> Node {
        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);
        Node {
            private_key,
            chain_code,
        }
    }

    /// The master node for a seed: `HMAC-SHA512("ed25519 seed", seed)`.
    ///
    /// # Errors
    ///
    /// `slip10-bad-seed-length` if the seed is not 16–64 octets.
    pub fn master(seed: &[u8]) -> Result<Node> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(err!(
                "slip10-bad-seed-length",
                "seed is {} octets, expected 16..=64",
                seed.len()
            ));
        }
        Ok(split(hmac_sha512(b"ed25519 seed", seed)))
    }

    /// A hardened child node.
    ///
    /// # Errors
    ///
    /// `slip10-non-hardened-index` — non-hardened derivation is undefined for ed25519.
    pub fn child(parent: &Node, index: u32) -> Result<Node> {
        if index < HARDENED {
            return Err(err!(
                "slip10-non-hardened-index",
                "index {index} is not hardened"
            ));
        }
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&parent.private_key);
        data[33..].copy_from_slice(&index.to_be_bytes());
        Ok(split(hmac_sha512(&parent.chain_code, &data)))
    }

    /// Derive a path such as `m/1054'/1'/0'`. Every component MUST be hardened.
    ///
    /// # Errors
    ///
    /// `slip10-bad-path`, `slip10-non-hardened-index`, or `slip10-bad-seed-length`.
    pub fn derive(seed: &[u8], path: &str) -> Result<Node> {
        let path = path.trim();
        let mut parts = path.split('/');
        if parts.next() != Some("m") {
            return Err(err!("slip10-bad-path", "path {path:?} must start with 'm'"));
        }
        let mut node = master(seed)?;
        for part in parts {
            let digits = part.strip_suffix('\'').ok_or_else(|| {
                err!(
                    "slip10-non-hardened-index",
                    "component {part:?} is not hardened"
                )
            })?;
            let index: u32 = digits
                .parse()
                .map_err(|_| err!("slip10-bad-path", "component {part:?} is not a number"))?;
            if index >= HARDENED {
                return Err(err!(
                    "slip10-bad-path",
                    "index {index} overflows the hardened range"
                ));
            }
            node = child(&node, index + HARDENED)?;
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rfc8032_test1() {
        let sk =
            decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let pk = public_key_of(&sk);
        assert_eq!(
            hex::encode(pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sign(&sk, b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify_strict(&pk, b"", &sig));
    }

    #[test]
    fn small_order_public_key_is_rejected() {
        let pk =
            decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert!(!verify_strict(&pk, b"anything", &[0u8; 64]));
    }

    #[test]
    fn slip10_master_matches_published_vector() {
        let seed = decode_hex::<16>("000102030405060708090a0b0c0d0e0f").unwrap();
        let node = slip10::master(&seed).unwrap();
        assert_eq!(
            hex::encode(node.chain_code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
    }

    #[test]
    fn non_hardened_derivation_is_refused() {
        let seed = [7u8; 32];
        assert_eq!(
            slip10::derive(&seed, "m/0").unwrap_err().code(),
            "slip10-non-hardened-index"
        );
    }

    #[test]
    fn uppercase_hex_is_refused() {
        assert_eq!(
            decode_hex::<32>(&"AB".repeat(32)).unwrap_err().code(),
            "encoding-not-lowercase-hex"
        );
    }
}
