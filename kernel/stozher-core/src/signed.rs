//! Key identifiers and the signed-object pattern — `spec/01-canonicalization-and-crypto.md` §4–§5.

use std::fmt;

use serde_json::{Map, Value};

use crate::crypto::{PUBLIC_KEY_LEN, SIGNATURE_LEN, decode_hex, verify_strict};
use crate::error::{Result, err};
use crate::jcs;

/// The prefix of every key identifier in `stozher/0.1`.
pub const KEY_ID_PREFIX: &str = "ed25519:";
/// The exact length of a key identifier: `"ed25519:"` plus 64 hex digits.
pub const KEY_ID_LEN: usize = KEY_ID_PREFIX.len() + PUBLIC_KEY_LEN * 2;

/// A key identifier: `"ed25519:" || lowercase_hex(public key)`.
///
/// The identifier *is* the key, so verification never needs a registry lookup (§01 §4). What the
/// key belongs to, and whether it is an enrolled human root, is a separate organization-local fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Parse and validate a key identifier.
    ///
    /// # Errors
    ///
    /// `key-id-malformed` if it does not match `^ed25519:[0-9a-f]{64}$`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != KEY_ID_LEN || !s.starts_with(KEY_ID_PREFIX) {
            return Err(err!(
                "key-id-malformed",
                "{s:?} is not an ed25519 key identifier"
            ));
        }
        decode_hex::<PUBLIC_KEY_LEN>(&s[KEY_ID_PREFIX.len()..]).map_err(|_| {
            err!(
                "key-id-malformed",
                "{s:?} does not carry 64 lowercase hex digits"
            )
        })?;
        Ok(Self(s.to_owned()))
    }

    /// Build a key identifier from raw public key octets.
    #[must_use]
    pub fn from_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self(format!("{KEY_ID_PREFIX}{}", hex::encode(public_key)))
    }

    /// The raw public key octets.
    ///
    /// # Errors
    ///
    /// `key-id-malformed` if the identifier is not decodable (unreachable for parsed values).
    pub fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN]> {
        decode_hex::<PUBLIC_KEY_LEN>(&self.0[KEY_ID_PREFIX.len()..])
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `signing-input(S)` — the canonical form of a signed object with `sig` removed (§01 §5).
///
/// # Errors
///
/// `schema-type-mismatch` if the value is not a JSON object; otherwise propagates canonicalization.
pub fn signing_input(object: &Value) -> Result<String> {
    let map = object.as_object().ok_or_else(|| {
        err!(
            "schema-type-mismatch",
            "a signed object must be a JSON object"
        )
    })?;
    let body: Map<String, Value> = map
        .iter()
        .filter(|(k, _)| k.as_str() != "sig")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    jcs::canonicalize(&Value::Object(body))
}

/// `id(S)` — `object-hash` over the complete signed object, `sig` included (§01 §5).
///
/// # Errors
///
/// Propagates canonicalization.
pub fn object_id(object: &Value) -> Result<String> {
    jcs::object_hash(object)
}

/// The `sig` member's declared signer, without verifying anything.
///
/// # Errors
///
/// `schema-missing-member` if `sig` or `sig.key` is absent, `schema-type-mismatch` if `sig` is not
/// an object, `crypto-unsupported-alg` if `sig.alg` is not `ed25519`, `key-id-malformed` otherwise.
pub fn declared_signer(object: &Value) -> Result<KeyId> {
    let sig = object
        .get("sig")
        .ok_or_else(|| err!("schema-missing-member", "sig"))?
        .as_object()
        .ok_or_else(|| err!("schema-type-mismatch", "sig must be an object"))?;
    match sig.get("alg").and_then(Value::as_str) {
        Some("ed25519") => {}
        Some(other) => return Err(err!("crypto-unsupported-alg", "sig.alg {other:?}")),
        None => return Err(err!("schema-missing-member", "sig.alg")),
    }
    let key = sig
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "sig.key"))?;
    KeyId::parse(key)
}

/// Verify a signed object and return its signer.
///
/// # Errors
///
/// `sig-invalid` if the signature is absent, malformed, or does not verify strictly. Structural
/// problems in `sig` itself surface through [`declared_signer`].
pub fn verify_signed_object(object: &Value) -> Result<KeyId> {
    let key = declared_signer(object)?;
    let value = object
        .get("sig")
        .and_then(|s| s.get("value"))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("sig-invalid", "sig.value is missing"))?;
    let signature = decode_hex::<SIGNATURE_LEN>(value)
        .map_err(|e| err!("sig-invalid", "sig.value: {}", e.detail()))?;
    let public_key = key
        .public_key()
        .map_err(|e| err!("sig-invalid", "{}", e.detail()))?;
    let message = signing_input(object)?;
    if verify_strict(&public_key, message.as_bytes(), &signature) {
        Ok(key)
    } else {
        Err(err!("sig-invalid", "signature does not verify for {key}"))
    }
}

/// Sign an object: canonicalize it without `sig`, sign those bytes, and insert `sig`.
///
/// Provided for tests, fixtures and the bootstrap ceremony. Production signing paths hold key
/// material elsewhere.
///
/// # Errors
///
/// `schema-type-mismatch` if the value is not a JSON object.
pub fn sign_object(object: &Value, secret_key: &[u8; 32]) -> Result<Value> {
    let mut map = object
        .as_object()
        .ok_or_else(|| {
            err!(
                "schema-type-mismatch",
                "a signed object must be a JSON object"
            )
        })?
        .clone();
    map.remove("sig");
    let message = jcs::canonicalize(&Value::Object(map.clone()))?;
    let signature = crate::crypto::sign(secret_key, message.as_bytes());
    let key = KeyId::from_public_key(&crate::crypto::public_key_of(secret_key));
    map.insert(
        "sig".to_owned(),
        serde_json::json!({ "alg": "ed25519", "key": key.as_str(), "value": hex::encode(signature) }),
    );
    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let secret = [3u8; 32];
        let object = serde_json::json!({ "b": 2, "a": 1 });
        let signed = sign_object(&object, &secret).unwrap();
        assert_eq!(
            verify_signed_object(&signed).unwrap().public_key().unwrap(),
            crate::crypto::public_key_of(&secret)
        );
    }

    #[test]
    fn tampering_after_signing_invalidates() {
        let secret = [3u8; 32];
        let signed = sign_object(&serde_json::json!({ "a": 1 }), &secret).unwrap();
        let mut tampered = signed.as_object().unwrap().clone();
        tampered.insert("a".to_owned(), Value::from(2));
        assert_eq!(
            verify_signed_object(&Value::Object(tampered))
                .unwrap_err()
                .code(),
            "sig-invalid"
        );
    }

    #[test]
    fn signing_input_excludes_only_sig() {
        let secret = [4u8; 32];
        let object = serde_json::json!({ "a": 1, "z": 2 });
        let signed = sign_object(&object, &secret).unwrap();
        assert_eq!(
            signing_input(&signed).unwrap(),
            jcs::canonicalize(&object).unwrap()
        );
        // The id covers sig; the signing input does not.
        assert_ne!(
            object_id(&signed).unwrap(),
            jcs::object_hash(&object).unwrap()
        );
    }

    #[test]
    fn member_insertion_order_is_irrelevant() {
        let a: Value = jcs::parse("{\"a\":1,\"b\":2}").unwrap();
        let b: Value = jcs::parse("{\"b\":2,\"a\":1}").unwrap();
        assert_eq!(object_id(&a).unwrap(), object_id(&b).unwrap());
    }
}
