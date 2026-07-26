//! `stozher-kernel` — the append-only hash-chained event store, the validating ingest API, and
//! versioned policy distribution.
//!
//! The normative specification is in `spec/` at the repository root. `stozher-core` is the reference
//! implementation of the primitives (canonicalization, signatures, envelope schema, mandate chain,
//! chain rule, gate algorithm); this crate is the store and the service around them, and it
//! reimplements none of them.
//!
//! # Module map
//!
//! | Module | Specification section |
//! |---|---|
//! | [`store`] | 04 — append-only chained store, payload store, checkpoints, rejections |
//! | [`ingest`] | 02 §9.2, 03, 05 §3, 06 §2, 07 — the one validating write path |
//! | [`policy`] | 05 — policy document, evaluation order, retention ceiling |
//! | [`manifest`] | 08 — extension manifest and durable-object transitions |
//! | [`checkpoint`] | 04 §4–§5 — checkpoint emission, payload decay |
//! | [`http`] | 05 §2.2, 04 §6 — ingest, policy pull, audit query, the revocation feed |
//! | [`console`] | `docs/design/console.md` — the read-only console, `get` routes only |
//! | [`keys`] | 01 §6, 09 §8 — SLIP-0010 derivation, owner-only key files |
//! | [`clock`] | 01 §2.3–§2.4 — the one timestamp form, duration arithmetic, injectable clock |
//! | [`codes`] | the small set of refusals the specification requires but does not name |
//!
//! # The three properties this crate exists to hold
//!
//! **Append-only is enforced by the storage engine.** `BEFORE UPDATE` / `BEFORE DELETE` triggers on
//! every chain-bearing table abort the statement. No application flag consults them and no method
//! issues such a statement.
//!
//! **Chain integrity does not depend on payload presence.** Payload decay deletes rows in `payloads`,
//! a table with no chain-bearing column. Verification reads `envelopes` only, so erasing evidence
//! for GDPR purposes cannot alter — and cannot be detected by — the chain.
//!
//! **Authorization is a signature, never a flag.** [`ingest::Ingest::submit`] is the only path to
//! [`store::Store::append`], which is crate-private. There is no header, parameter, environment
//! variable, trusted-component list, state binding or administrative route that satisfies a gate rule
//! without a verified Ed25519 signature over the exact action (§06 §2). `tests/no_ambient_approval.rs`
//! attempts it, as §06 §2 requires the conformance harness to.

use std::sync::Arc;

use stozher_core::error::Result;

pub mod checkpoint;
pub mod clock;
pub mod codes;
pub mod config;
pub mod console;
pub mod gatequeue;
pub mod http;
pub mod ingest;
pub mod keys;
pub mod manifest;
pub mod notify;
pub mod policy;
pub mod store;

pub use config::Config;
pub use ingest::{Ingest, IngestConfig, Outcome};
pub use store::Store;

/// A running kernel: configuration plus the one ingest pipeline.
#[derive(Debug)]
pub struct Kernel {
    /// The deployment's configuration.
    pub config: Config,
    /// The ingest pipeline, which owns the store.
    pub ingest: Ingest,
    /// The approver ping — the only outbound this product owns (ADR-0002).
    pub notifier: notify::Notifier,
    /// Per-process entropy behind the console's CSRF tokens. Regenerated on every start, so a
    /// token cannot outlive the process that issued it, and never leaves the process itself.
    console_nonce: [u8; 32],
}

impl Kernel {
    /// Open the store, load key material, seed the configured root set, and assemble the pipeline.
    ///
    /// # Errors
    ///
    /// `key-file-permissions` if the seed file is not owner-only, any `key-file-*` code, or
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn open(config: Config) -> Result<Self> {
        let seed = keys::Seed::load(&config.kernel_seed)?;
        let kernel_key = seed.derive(keys::ROLE_KERNEL_CHECKPOINT, 0)?;
        let store = Store::open(&config.database, &config.rejection_stream).await?;
        let notifier = config.notifier();
        let mut kernel =
            Self::assemble(config, store, kernel_key, Arc::new(clock::SystemClock)).await?;
        kernel.notifier = notifier;
        Ok(kernel)
    }

    /// Assemble a kernel around an already-open store and key — the seam tests use.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn assemble(
        config: Config,
        store: Store,
        kernel_key: keys::SigningKey,
        clock: clock::SharedClock,
    ) -> Result<Self> {
        for root in &config.roots {
            store
                .seed_configured_root(&root.key, &root.subject, &root.enrolled_at)
                .await?;
        }
        let ingest = Ingest::new(
            store,
            clock,
            Arc::new(kernel_key),
            IngestConfig {
                policy_key: config.policy_key.clone(),
                max_future_skew_seconds: config.max_future_skew_seconds,
                kernel_core_stream: config.kernel_core_stream.clone(),
            },
        );
        let mut console_nonce = [0u8; 32];
        getrandom::fill(&mut console_nonce).map_err(|e| {
            stozher_core::error::Error::new("kernel-entropy-unavailable", e.to_string())
        })?;
        Ok(Self {
            config,
            ingest,
            notifier: notify::Notifier::default(),
            console_nonce,
        })
    }

    /// The CSRF token for one caller and one pending request.
    ///
    /// The console authenticates with a `Bearer` credential, which a browser cannot attach
    /// cross-site — but ADR-0008 records that reaching the console from a browser today needs a
    /// header-injecting reverse proxy, and an injected header *is* an ambient credential. This binds
    /// the mutating form to (this process, this caller, this request), so a page a caller never
    /// fetched cannot produce a token that a decision route accepts.
    #[must_use]
    pub fn csrf_token(&self, caller: &str, request_hash: &str) -> String {
        let mut material = Vec::with_capacity(64 + caller.len() + request_hash.len());
        material.extend_from_slice(&self.console_nonce);
        material.extend_from_slice(caller.as_bytes());
        material.push(0);
        material.extend_from_slice(request_hash.as_bytes());
        stozher_core::crypto::sha256_hex(&material)
    }

    /// Whether a presented CSRF token is the one this process would have issued.
    #[must_use]
    pub fn csrf_ok(&self, caller: &str, request_hash: &str, presented: &str) -> bool {
        let expected = self.csrf_token(caller, request_hash);
        let (a, b) = (expected.as_bytes(), presented.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut difference = 0u8;
        for (x, y) in a.iter().zip(b) {
            difference |= x ^ y;
        }
        difference == 0
    }
}
