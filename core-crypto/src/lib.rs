//! Cryptographic primitives for PDS.
//!
//! Provides AES-256-GCM encryption, Argon2id key derivation, and SecureBytes
//! (mlock + zeroize + MADV_DONTDUMP).
//!
//! # Safety
//!
//! This crate uses `unsafe` for `mlock`/`munlock`/`madvise` syscalls on Unix
//! to prevent secret memory pages from being swapped to disk or included in
//! core dumps. All unsafe blocks are documented inline with justification.

mod secure_bytes;
mod encryption;
mod kdf;

pub use secure_bytes::SecureBytes;
pub use encryption::EncryptionKey;
pub use kdf::derive_key_argon2;
