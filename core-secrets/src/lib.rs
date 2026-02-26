//! Encrypted secret storage with platform keyring KEK management.
//!
//! Architecture (ADR-SEC-001, ADR-SEC-002):
//! - Individual secrets stored in an encrypted local store (SQLCipher via rusqlite)
//! - Platform keyrings (Secret Service, Keychain, Credential Manager) store ONLY
//!   a key-encrypting-key (KEK) that protects the master key at rest
//! - Cross-profile isolation is cryptographic: different BLAKE3-derived vault keys
//!   per profile, not namespace-based
//!
//! Key hierarchy:
//!   User password → Argon2id → Master Key → BLAKE3 → per-profile vault key → SQLCipher
//!
//! This crate contains NO platform-specific code. Platform keyring integration
//! is behind the `KeyLocker` trait, implemented in platform-* crates.
#![forbid(unsafe_code)]

pub mod store;
pub mod sqlcipher;
pub mod compliance;
mod key_locker;
mod jit;

pub use store::{SecretsStore, InMemoryStore};
pub use sqlcipher::SqlCipherStore;
pub use key_locker::KeyLocker;
pub use jit::JitDelivery;
