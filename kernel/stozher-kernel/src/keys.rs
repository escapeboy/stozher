//! Kernel key material — `spec/09-threat-model.md` §8, `spec/01-canonicalization-and-crypto.md` §6.
//!
//! Two rules govern everything here, and both are refusals rather than warnings:
//!
//! 1. **The kernel refuses to start if its seed file is readable by anyone but its owner**
//!    (`key-file-permissions`). Root on the host is not defended against; a group-readable private
//!    key is a different and entirely avoidable failure.
//! 2. **Key material never reaches a log, an error message, or a response body.** [`Seed`] has a
//!    hand-written [`Debug`] that prints a placeholder, no `Display`, and no accessor that returns
//!    the octets — callers get derived signing capability, not bytes.

use std::fs;
use std::path::Path;

use stozher_core::crypto::{self, slip10};
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;

/// SLIP-0010 role for the kernel's checkpoint key (§01 §6).
pub const ROLE_KERNEL_CHECKPOINT: u32 = 3;
/// The registered derivation prefix. `1054` has no external significance; it is fixed so key
/// recovery is interoperable between implementations.
pub const DERIVATION_PREFIX: u32 = 1054;

/// A 32-octet high-entropy seed from which subject keys are derived.
///
/// Deliberately not `Clone`, not `Display`, and not convertible back to bytes.
pub struct Seed([u8; 32]);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        // Best-effort hygiene. Not a defence against a host-level adversary (§09 §8), just a
        // refusal to leave the seed lying in a freed allocation.
        self.0.fill(0);
    }
}

impl Seed {
    /// Generate a fresh seed from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// `kernel-entropy-unavailable` if the platform RNG fails.
    pub fn generate() -> Result<Self> {
        let mut octets = [0u8; 32];
        getrandom::fill(&mut octets)
            .map_err(|e| Error::new("kernel-entropy-unavailable", e.to_string()))?;
        Ok(Self(octets))
    }

    /// Read a seed from a file, refusing to proceed if the file is not owner-only.
    ///
    /// # Errors
    ///
    /// `key-file-permissions` if the mode grants any group or other access, `key-file-unreadable`
    /// if the file cannot be read, `key-file-malformed` if the contents are not 64 lowercase hex
    /// digits.
    pub fn load(path: &Path) -> Result<Self> {
        require_owner_only(path)?;
        let text = fs::read_to_string(path)
            .map_err(|e| Error::new("key-file-unreadable", format!("{}: {e}", path.display())))?;
        let text = text.trim();
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Error::new(
                "key-file-malformed",
                "a seed file must hold lowercase hex",
            ));
        }
        let octets = crypto::decode_hex::<32>(text).map_err(|_| {
            Error::new(
                "key-file-malformed",
                format!("{} does not hold 64 hex digits", path.display()),
            )
        })?;
        Ok(Self(octets))
    }

    /// Write the seed to a new file created with owner-only permissions.
    ///
    /// Refuses to overwrite: silently replacing a seed would orphan every signature made under it.
    ///
    /// # Errors
    ///
    /// `key-file-exists` if the path is taken, `key-file-unwritable` on any I/O failure.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        if path.exists() {
            return Err(Error::new(
                "key-file-exists",
                format!("{} already exists", path.display()),
            ));
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    "key-file-unwritable",
                    format!("{}: {e}", parent.display()),
                )
            })?;
        }
        create_owner_only(path, hex::encode(self.0).as_bytes())?;
        Ok(())
    }

    /// Derive the signing key for a role and index at `m/1054'/<role>'/<index>'`.
    ///
    /// # Errors
    ///
    /// Propagates SLIP-0010 derivation failures.
    pub fn derive(&self, role: u32, index: u32) -> Result<SigningKey> {
        let node = slip10::derive(&self.0, &format!("m/{DERIVATION_PREFIX}'/{role}'/{index}'"))?;
        Ok(SigningKey {
            secret: node.private_key,
            id: KeyId::from_public_key(&crypto::public_key_of(&node.private_key)),
        })
    }
}

/// A derived signing key. Signs; does not expose its secret.
pub struct SigningKey {
    secret: [u8; 32],
    id: KeyId,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The public identifier is public by definition; the secret is not printed.
        write!(f, "SigningKey({}, secret=<redacted>)", self.id)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

impl SigningKey {
    /// The public key identifier.
    #[must_use]
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// Sign a JSON object per the signed-object pattern (§01 §5).
    ///
    /// # Errors
    ///
    /// Propagates canonicalization.
    pub fn sign(&self, object: &serde_json::Value) -> Result<serde_json::Value> {
        stozher_core::signed::sign_object(object, &self.secret)
    }
}

/// Refuse a key file that anyone but its owner can read (§09 §8).
///
/// # Errors
///
/// `key-file-permissions`, or `key-file-unreadable` if the metadata cannot be read.
pub fn require_owner_only(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .map_err(|e| Error::new("key-file-unreadable", format!("{}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::new(
                "key-file-permissions",
                format!(
                    "{} is mode {mode:04o}; key material must be owner-only (0600)",
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
    }
    Ok(())
}

#[cfg(unix)]
fn create_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::new("key-file-unwritable", format!("{}: {e}", path.display())))?;
    file.write_all(contents)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::new("key-file-unwritable", format!("{}: {e}", path.display())))
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)
        .map_err(|e| Error::new("key-file-unwritable", format!("{}: {e}", path.display())))
}

/// Generate a seed at `path` and report the checkpoint key identifier it yields.
///
/// # Errors
///
/// Any of the `key-file-*` codes, or `kernel-entropy-unavailable`.
pub fn keygen(path: &Path) -> Result<KeyId> {
    let seed = Seed::generate()?;
    seed.write_new(path)?;
    Ok(seed.derive(ROLE_KERNEL_CHECKPOINT, 0)?.id().clone())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stozher-keys-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("kernel.seed")
    }

    #[test]
    fn a_generated_seed_is_owner_only_and_derives_a_stable_key() {
        let path = scratch("generated");
        let _ = fs::remove_file(&path);
        let id = keygen(&path).unwrap();
        require_owner_only(&path).unwrap();
        let reloaded = Seed::load(&path).unwrap();
        assert_eq!(
            reloaded.derive(ROLE_KERNEL_CHECKPOINT, 0).unwrap().id(),
            &id
        );
        // Refusing to overwrite is the point: a replaced seed orphans every past signature.
        assert_eq!(
            Seed::generate().unwrap().write_new(&path).unwrap_err().code(),
            "key-file-exists"
        );
        fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_seed_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch("permissive");
        let _ = fs::remove_file(&path);
        keygen(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            Seed::load(&path).unwrap_err().code(),
            "key-file-permissions"
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn key_material_is_not_in_the_debug_output() {
        let seed = Seed::generate().unwrap();
        let key = seed.derive(ROLE_KERNEL_CHECKPOINT, 0).unwrap();
        assert_eq!(format!("{seed:?}"), "Seed(<redacted>)");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains(key.id().as_str()));
    }
}
