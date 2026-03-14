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
mod secure_vec;
mod encryption;
mod kdf;
pub mod hkdf;

pub use secure_bytes::SecureBytes;
pub use secure_vec::SecureVec;
pub use encryption::EncryptionKey;
pub use kdf::{derive_key_argon2, derive_key_pbkdf2, derive_key_kdf};
pub use hkdf::{
    derive_vault_key, derive_clipboard_key, derive_ipc_auth_token, derive_ipc_encryption_key, derive_kek, derive_key,
    derive_vault_key_with_algorithm, derive_clipboard_key_with_algorithm,
    derive_ipc_auth_token_with_algorithm, derive_ipc_encryption_key_with_algorithm,
    derive_key_with_algorithm,
};
