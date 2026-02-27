//! daemon-secrets: Secrets broker daemon.
//!
//! Manages encrypted per-profile secret vaults with JIT caching and IPC-based
//! request handling. Connects to the IPC bus as a client, waits for master
//! password unlock, then serves SecretGet/Set/Delete/List requests against
//! SQLCipher-backed stores keyed with BLAKE3-derived per-profile vault keys.
//!
//! # Startup sequence
//!
//! 1. Parse CLI, init logging, load config
//! 2. Apply Landlock + seccomp sandbox
//! 3. Connect to IPC bus as client
//! 4. Wait for `UnlockRequest` with master password
//! 5. Derive master key via Argon2id, persist salt to config dir
//! 6. Enter IPC event loop — vaults opened lazily on first access per profile
//!
//! Multiple profiles may have open vaults concurrently. Every secret RPC
//! carries a `profile` field identifying which vault to query.
//!
//! # Security constraints
//!
//! - Landlock: config dir (read), runtime dir (read/write), D-Bus socket (read/write)
//! - seccomp: restricted syscall set (no network, no ptrace)
//! - systemd: `PrivateNetwork=yes` (no network access)
//! - Master password required at first unlock per session (ADR-SEC-003)
//!
//! # Key hierarchy (ADR-SEC-002)
//!
//! ```text
//! Master password → Argon2id → Master Key → BLAKE3 derive_key → per-profile vault keys
//! ```

#[cfg(target_os = "linux")]
mod key_locker_linux;

mod acl;
mod rate_limit;

use acl::{audit_secret_access, check_secret_access, check_secret_list_access, check_secret_requester};
use rate_limit::SecretRateLimiter;

use anyhow::Context;
use clap::Parser;
use core_crypto::SecureBytes;
use core_ipc::{BusClient, Message};
use core_secrets::{JitDelivery, SecretsStore, SqlCipherStore};
use core_types::{DaemonId, EventKind, SecurityLevel, SensitiveBytes, TrustProfileName};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// PDS secrets broker daemon.
#[derive(Parser, Debug)]
#[command(name = "daemon-secrets", about = "PDS secrets broker")]
struct Cli {
    /// Config directory override.
    #[arg(long, env = "PDS_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// JIT cache TTL in seconds.
    #[arg(long, default_value = "300", env = "PDS_SECRET_TTL")]
    ttl: u64,

    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

/// Runtime state for the secrets daemon after unlock.
struct UnlockedState {
    /// Master key (mlock'd, zeroize-on-drop).
    master_key: SecureBytes,
    /// Trust profile name -> JitDelivery wrapping SqlCipherStore.
    /// Multiple vaults may be open concurrently.
    vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    /// JIT TTL from CLI.
    ttl: Duration,
    /// Config directory for vault DB storage.
    config_dir: PathBuf,
}

impl UnlockedState {
    /// Get or lazily open a vault for the given trust profile.
    fn vault_for(&mut self, profile: &TrustProfileName) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
        if !self.vaults.contains_key(profile) {
            let vault_key = core_crypto::derive_vault_key(self.master_key.as_bytes(), profile);
            let db_path = self.config_dir.join("vaults").join(format!("{profile}.db"));

            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    core_types::Error::Secrets(format!(
                        "failed to create vault directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            let store = SqlCipherStore::open(&db_path, &vault_key)?;
            let jit = JitDelivery::new(store, self.ttl);
            self.vaults.insert(profile.clone(), jit);
            tracing::info!(profile = %profile, path = %db_path.display(), "vault opened");
        }
        Ok(self.vaults.get(profile).expect("just inserted"))
    }

    /// Deactivate a trust profile: flush its JIT cache and close the vault.
    async fn deactivate_profile(&mut self, profile: &TrustProfileName) -> core_types::Result<()> {
        if let Some(vault) = self.vaults.remove(profile) {
            vault.flush().await;
            // SqlCipherStore closes DB connection on drop.
            drop(vault);
            tracing::info!(profile = %profile, "vault deactivated");
            Ok(())
        } else {
            Err(core_types::Error::NotFound(format!(
                "profile '{profile}' is not active"
            )))
        }
    }

    /// Names of all trust profiles with open vaults.
    fn active_profiles(&self) -> Vec<TrustProfileName> {
        self.vaults.keys().cloned().collect()
    }

    /// Get the per-profile IPC encryption key (ADR-SEC-006, defense-in-depth).
    ///
    /// Used to encrypt secret values before placing them on the IPC bus,
    /// providing per-field encryption on top of Noise transport encryption.
    /// Per-field IPC encryption (ADR-SEC-006, feature-gated).
    ///
    /// Defense-in-depth: AES-256-GCM per secret value on the IPC bus, layered
    /// on top of Noise IK transport encryption. Gated behind `ipc-field-encryption`
    /// feature because:
    /// - The Noise transport is already the security boundary (matching
    ///   ssh-agent, 1Password, Vault, gpg-agent precedent)
    /// - CLI clients lack the master key needed for per-field encryption
    /// - The per-field key derives from the same master key that transits
    ///   inside the Noise channel (not an independent trust root)
    ///
    /// Enable for research into daemon-to-daemon relay defense-in-depth.
    #[cfg(feature = "ipc-field-encryption")]
    fn ipc_encryption_key(&self, profile: &TrustProfileName) -> core_types::Result<core_crypto::EncryptionKey> {
        let key_bytes = core_crypto::derive_ipc_encryption_key(
            self.master_key.as_bytes(),
            profile,
        );
        let key_array: &[u8; 32] = key_bytes.as_bytes().try_into().map_err(|_| {
            core_types::Error::Crypto("IPC encryption key is not 32 bytes".into())
        })?;
        core_crypto::EncryptionKey::from_bytes(key_array)
    }

    #[cfg(feature = "ipc-field-encryption")]
    fn encrypt_for_ipc(&self, profile: &TrustProfileName, plaintext: &[u8]) -> core_types::Result<Vec<u8>> {
        let enc_key = self.ipc_encryption_key(profile)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| {
            core_types::Error::Crypto(format!("nonce generation failed: {e}"))
        })?;
        let ciphertext = enc_key.encrypt(&nonce, plaintext)?;
        let mut wire = Vec::with_capacity(12 + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend(ciphertext);
        Ok(wire)
    }

    #[cfg(feature = "ipc-field-encryption")]
    fn decrypt_from_ipc(&self, profile: &TrustProfileName, wire: &[u8]) -> core_types::Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(core_types::Error::Crypto(
                "IPC-encrypted value too short (missing nonce)".into(),
            ));
        }
        let nonce: [u8; 12] = wire[..12].try_into().map_err(|_| {
            core_types::Error::Crypto("nonce extraction failed".into())
        })?;
        let ciphertext = &wire[12..];
        let enc_key = self.ipc_encryption_key(profile)?;
        let plaintext = enc_key.decrypt(&nonce, ciphertext)?;
        Ok(plaintext.as_bytes().to_vec())
    }
}

// ============================================================================
// H-013: Secret access audit trail (NIST AU-2, AU-3, AU-12)
// H-014: Anomaly detection (NIST SI-4, AU-6)
// H-016: Rate limiting (NIST SC-5, AC-10)
// H-020: Per-secret access control (NIST AC-3, AC-6)
//
// Implementations extracted to `acl` and `rate_limit` modules for testability.
// ============================================================================

/// Salt file path within the config directory.
fn salt_path(config_dir: &Path) -> PathBuf {
    config_dir.join("secrets.salt")
}

/// Derive the master key from password + salt via Argon2id.
fn derive_master_key(password: &[u8], salt: &[u8; 16]) -> core_types::Result<SecureBytes> {
    core_crypto::derive_key_argon2(password, salt)
}

/// First-run: generate salt, derive master key, store salt to disk.
fn first_run_derive(password: &[u8], config_dir: &Path) -> core_types::Result<SecureBytes> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| {
        core_types::Error::Crypto(format!("getrandom failed: {e}"))
    })?;

    // Persist salt.
    let sp = salt_path(config_dir);
    if let Some(parent) = sp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            core_types::Error::Config(format!("failed to create config dir: {e}"))
        })?;
    }
    std::fs::write(&sp, salt).map_err(|e| {
        core_types::Error::Config(format!("failed to write salt: {e}"))
    })?;
    tracing::info!(path = %sp.display(), "salt generated and stored");

    derive_master_key(password, &salt)
}

/// Subsequent run: load salt from disk, derive master key.
fn subsequent_run_derive(password: &[u8], config_dir: &Path) -> core_types::Result<SecureBytes> {
    let sp = salt_path(config_dir);
    let salt_bytes = std::fs::read(&sp).map_err(|e| {
        core_types::Error::Config(format!("failed to read salt from {}: {e}", sp.display()))
    })?;
    let salt: [u8; 16] = salt_bytes.try_into().map_err(|_| {
        core_types::Error::Config("salt file is not 16 bytes".into())
    })?;
    derive_master_key(password, &salt)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // -- Logging --
    init_logging(&cli.log_format)?;

    tracing::info!("daemon-secrets starting");

    // -- Process hardening (NIST SC-4, SI-11) --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    // -- Config --
    let config = core_config::load_config(None)
        .context("failed to load config")?;
    tracing::debug!(?config, "config loaded");

    // Config hot-reload (M-6).
    let config_paths_for_watch = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, _config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths_for_watch,
        config.clone(),
        Some(Box::new(move || { let _ = reload_tx.blocking_send(()); })),
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    let config_dir = core_config::config_dir();
    let default_profile: TrustProfileName = config.global.default_profile.clone();

    // -- IPC bus connection: read keypair BEFORE sandbox (keypair files need to be open) --
    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    tracing::info!(path = %socket_path.display(), "connecting to IPC bus");

    let daemon_id = DaemonId::new();
    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("failed to read bus server public key")?;

    // Connect with keypair retry (H-019: daemon-profile may regenerate on crash-restart).
    // First attempt reads keypair; sandbox applied after successful read.
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-secrets", daemon_id, &socket_path, &server_pub, 5, Duration::from_millis(500),
    ).await.context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // -- Sandbox (Linux) -- applied AFTER keypair read, BEFORE IPC traffic.
    // Per-daemon Landlock key file isolation (H-017, NIST AC-6).
    #[cfg(target_os = "linux")]
    apply_sandbox();

    tracing::info!("connected to IPC bus (Noise IK encrypted)");

    // -- Announce startup --
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["secrets".into(), "keylocker".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .context("failed to announce startup")?;

    // -- Platform readiness --
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-secrets ready (locked, awaiting UnlockRequest)");

    // -- Watchdog timer: half the WatchdogSec=30 interval --
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -- Main event loop: locked phase then unlocked phase --
    let mut unlocked_state: Option<UnlockedState> = None;
    let mut rate_limiter = SecretRateLimiter::new();

    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            msg = client.recv() => {
                let Some(msg) = msg else {
                    tracing::error!("IPC bus disconnected");
                    break;
                };

                let mut ctx = MessageContext {
                    client: &mut client,
                    unlocked_state: &mut unlocked_state,
                    config_dir: &config_dir,
                    default_profile: &default_profile,
                    ttl: cli.ttl,
                    daemon_id,
                    rate_limiter: &mut rate_limiter,
                    config: &config,
                    socket_path: &socket_path,
                    server_pub: &server_pub,
                };
                match handle_message(&msg, &mut ctx).await {
                    Ok(should_continue) => {
                        if !should_continue {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "message handler failed");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reloaded");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["secrets".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received");
                break;
            }
        }
    }

    // Graceful shutdown: zeroize master key, close all open vaults, clear keyring.
    // SecureBytes zeroizes on drop. SqlCipherStore closes DB connections on drop.
    if let Some(state) = unlocked_state.take() {
        let count = state.vaults.len();
        drop(state);
        #[cfg(target_os = "linux")]
        keyring_delete().await;
        tracing::info!(vault_count = count, "master key zeroized, all vaults closed");
    }

    client
        .publish(
            EventKind::DaemonStopped {
                daemon_id,
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await
        .ok(); // Best-effort on shutdown.

    tracing::info!("daemon-secrets shutting down");
    Ok(())
}

/// Grouped context for `handle_message` to avoid parameter explosion.
struct MessageContext<'a> {
    client: &'a mut BusClient,
    unlocked_state: &'a mut Option<UnlockedState>,
    config_dir: &'a Path,
    default_profile: &'a TrustProfileName,
    ttl: u64,
    daemon_id: DaemonId,
    rate_limiter: &'a mut SecretRateLimiter,
    config: &'a core_config::Config,
    socket_path: &'a Path,
    server_pub: &'a [u8; 32],
}

/// Handle a single inbound IPC message. Returns false if the daemon should exit.
#[allow(clippy::too_many_lines)]
async fn handle_message(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
) -> anyhow::Result<bool> {
    let response_event = match &msg.payload {
        // Daemon announcements — no longer tracked locally (R-009).
        // Verified identity comes from msg.verified_sender_name stamped by bus server.
        EventKind::DaemonStarted { .. } => None,

        // H-018: Key rotation — reconnect with new keypair (R-006: shared handler).
        EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
            if daemon_name == "daemon-secrets" =>
        {
            tracing::info!(grace_period_s, "key rotation pending, will reconnect with new keypair");
            match BusClient::handle_key_rotation(
                "daemon-secrets", ctx.daemon_id, ctx.socket_path, ctx.server_pub, new_pubkey,
                vec!["secrets".into(), "keylocker".into()], env!("CARGO_PKG_VERSION"),
            ).await {
                Ok(new_client) => {
                    *ctx.client = new_client;
                    tracing::info!("reconnected with rotated keypair");
                }
                Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
            }
            None
        }

        // -- Unlock --
        EventKind::UnlockRequest { password } => {
            let outcome = if ctx.unlocked_state.is_some() {
                tracing::warn!("unlock requested but already unlocked");
                "already-unlocked"
            } else {
                match unlock(password.as_bytes(), ctx.config_dir, ctx.ttl).await {
                    Ok(state) => {
                        tracing::info!("secrets unlocked");
                        *ctx.unlocked_state = Some(state);
                        "success"
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "unlock failed");
                        "failed"
                    }
                }
            };
            audit_secret_access("unlock", msg.sender, "-", None, outcome);
            Some(EventKind::UnlockResponse { success: outcome != "failed" })
        }

        // -- Lock --
        EventKind::LockRequest => {
            if let Some(state) = ctx.unlocked_state.take() {
                drop(state); // SecureBytes zeroizes on drop.
                // ADR-SEC-001: remove master key from platform keyring.
                #[cfg(target_os = "linux")]
                keyring_delete().await;
                tracing::info!("secrets locked, master key zeroized");
            }
            audit_secret_access("lock", msg.sender, "-", None, "success");
            Some(EventKind::LockResponse { success: true })
        }

        // -- Status --
        EventKind::StatusRequest => {
            let locked = ctx.unlocked_state.is_none();
            let active_profiles = ctx.unlocked_state
                .as_ref()
                .map_or_else(Vec::new, |s| s.active_profiles());
            Some(EventKind::StatusResponse {
                active_profiles,
                default_profile: ctx.default_profile.clone(),
                daemon_uptimes_ms: vec![(ctx.daemon_id, 0)],
                locked,
            })
        }

        // -- Secret Get (profile-scoped) --
        EventKind::SecretGet { profile, key } => {
            // R-008/R-009: Use server-verified sender name (NIST IA-9, AC-3).
            // This is stamped by route_frame from the Noise IK registry — NOT self-declared.
            let requester_name = msg.verified_sender_name.as_deref();

            // H-014: anomaly detection using verified identity.
            check_secret_requester(msg.sender, requester_name);
            // H-016: rate limiting.
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                tracing::warn!(
                    audit = "rate-limit",
                    requester = %msg.sender,
                    profile = %profile,
                    key,
                    "secret request rate limit exceeded"
                );
                audit_secret_access("get", msg.sender, profile, Some(key), "rate-limited");
                return send_response(ctx.client, msg, EventKind::SecretGetResponse {
                    key: key.clone(),
                    value: SensitiveBytes::new(vec![]),
                }, ctx.daemon_id).await;
            }

            // H-020: Per-secret access control (NIST AC-3, AC-6).
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("get", msg.sender, profile, Some(key), "denied-acl");
                return send_response(ctx.client, msg, EventKind::SecretGetResponse {
                    key: key.clone(),
                    value: SensitiveBytes::new(vec![]),
                }, ctx.daemon_id).await;
            }

            let Some(state) = ctx.unlocked_state.as_mut() else {
                audit_secret_access("get", msg.sender, profile, Some(key), "denied-locked");
                return send_response(ctx.client, msg, EventKind::SecretGetResponse {
                    key: key.clone(),
                    value: SensitiveBytes::new(vec![]),
                }, ctx.daemon_id).await;
            };
            match state.vault_for(profile) {
                Ok(vault) => match vault.resolve(key).await {
                    Ok(secret) => {
                        #[cfg(feature = "ipc-field-encryption")]
                        let value = match state.encrypt_for_ipc(profile, secret.as_bytes()) {
                            Ok(v) => SensitiveBytes::new(v),
                            Err(e) => {
                                tracing::error!(profile = %profile, key, error = %e, "IPC encryption failed");
                                SensitiveBytes::new(vec![])
                            }
                        };
                        #[cfg(not(feature = "ipc-field-encryption"))]
                        let value = SensitiveBytes::new(secret.as_bytes().to_vec());

                        audit_secret_access("get", msg.sender, profile, Some(key), "success");
                        Some(EventKind::SecretGetResponse {
                            key: key.clone(),
                            value,
                        })
                    }
                    Err(e) => {
                        tracing::warn!(profile = %profile, key, error = %e, "secret get failed");
                        audit_secret_access("get", msg.sender, profile, Some(key), "not-found");
                        Some(EventKind::SecretGetResponse {
                            key: key.clone(),
                            value: SensitiveBytes::new(vec![]),
                        })
                    }
                },
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    audit_secret_access("get", msg.sender, profile, Some(key), "vault-error");
                    Some(EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                    })
                }
            }
        }

        // -- Secret Set (profile-scoped) --
        EventKind::SecretSet { profile, key, value } => {
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                tracing::warn!(
                    audit = "rate-limit",
                    requester = %msg.sender,
                    profile = %profile,
                    key,
                    "secret request rate limit exceeded"
                );
                audit_secret_access("set", msg.sender, profile, Some(key), "rate-limited");
                return send_response(ctx.client, msg, EventKind::SecretSetResponse { success: false }, ctx.daemon_id).await;
            }

            // H-020: Per-secret access control (NIST AC-3, AC-6).
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("set", msg.sender, profile, Some(key), "denied-acl");
                return send_response(ctx.client, msg, EventKind::SecretSetResponse { success: false }, ctx.daemon_id).await;
            }

            let Some(state) = ctx.unlocked_state.as_mut() else {
                audit_secret_access("set", msg.sender, profile, Some(key), "denied-locked");
                return send_response(ctx.client, msg, EventKind::SecretSetResponse { success: false }, ctx.daemon_id).await;
            };
            #[cfg(feature = "ipc-field-encryption")]
            let store_value = match state.decrypt_from_ipc(profile, value.as_bytes()) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::error!(profile = %profile, key, error = %e, "IPC decryption of secret value failed");
                    audit_secret_access("set", msg.sender, profile, Some(key), "decrypt-error");
                    return send_response(ctx.client, msg, EventKind::SecretSetResponse { success: false }, ctx.daemon_id).await;
                }
            };
            #[cfg(not(feature = "ipc-field-encryption"))]
            let store_value = value.as_bytes().to_vec();

            let success = match state.vault_for(profile) {
                Ok(vault) => {
                    match vault.store().set(key, &store_value).await {
                        Ok(()) => {
                            vault.flush().await;
                            true
                        }
                        Err(e) => {
                            tracing::error!(profile = %profile, key, error = %e, "secret set failed");
                            false
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    false
                }
            };
            let outcome = if success { "success" } else { "failed" };
            audit_secret_access("set", msg.sender, profile, Some(key), outcome);
            Some(EventKind::SecretSetResponse { success })
        }

        // -- Secret Delete (profile-scoped) --
        EventKind::SecretDelete { profile, key } => {
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                audit_secret_access("delete", msg.sender, profile, Some(key), "rate-limited");
                return send_response(ctx.client, msg, EventKind::SecretDeleteResponse { success: false }, ctx.daemon_id).await;
            }

            // H-020: Per-secret access control (NIST AC-3, AC-6).
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("delete", msg.sender, profile, Some(key), "denied-acl");
                return send_response(ctx.client, msg, EventKind::SecretDeleteResponse { success: false }, ctx.daemon_id).await;
            }

            let Some(state) = ctx.unlocked_state.as_mut() else {
                audit_secret_access("delete", msg.sender, profile, Some(key), "denied-locked");
                return send_response(ctx.client, msg, EventKind::SecretDeleteResponse { success: false }, ctx.daemon_id).await;
            };
            let success = match state.vault_for(profile) {
                Ok(vault) => {
                    match vault.store().delete(key).await {
                        Ok(()) => {
                            vault.flush().await;
                            true
                        }
                        Err(e) => {
                            tracing::warn!(profile = %profile, key, error = %e, "secret delete failed");
                            false
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    false
                }
            };
            let outcome = if success { "success" } else { "failed" };
            audit_secret_access("delete", msg.sender, profile, Some(key), outcome);
            Some(EventKind::SecretDeleteResponse { success })
        }

        // -- Secret List (profile-scoped) --
        EventKind::SecretList { profile } => {
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);

            // H-016: rate limiting (re-keyed on verified identity per P1 fix).
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                audit_secret_access("list", msg.sender, profile, None, "rate-limited");
                return send_response(ctx.client, msg, EventKind::SecretListResponse { keys: vec![] }, ctx.daemon_id).await;
            }

            // H-020: ACL check -- deny list if daemon has explicit empty ACL (NIST AC-3, AC-6).
            if !check_secret_list_access(ctx.config, profile, requester_name) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    "secret list denied by per-profile ACL"
                );
                audit_secret_access("list", msg.sender, profile, None, "denied-acl");
                return send_response(ctx.client, msg, EventKind::SecretListResponse { keys: vec![] }, ctx.daemon_id).await;
            }

            let Some(state) = ctx.unlocked_state.as_mut() else {
                audit_secret_access("list", msg.sender, profile, None, "denied-locked");
                return send_response(ctx.client, msg, EventKind::SecretListResponse { keys: vec![] }, ctx.daemon_id).await;
            };
            let keys = match state.vault_for(profile) {
                Ok(vault) => vault.store().list_keys().await.unwrap_or_default(),
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    vec![]
                }
            };
            let outcome = if keys.is_empty() { "empty" } else { "success" };
            audit_secret_access("list", msg.sender, profile, None, outcome);
            Some(EventKind::SecretListResponse { keys })
        }

        // -- Profile Activate (open vault, register for concurrent access) --
        EventKind::ProfileActivate { profile_name, .. } => {
            let Some(state) = ctx.unlocked_state.as_mut() else {
                tracing::warn!(profile = %profile_name, "profile activate while locked");
                return send_response(ctx.client, msg, EventKind::ProfileActivateResponse { success: false }, ctx.daemon_id).await;
            };
            let success = match state.vault_for(profile_name) {
                Ok(_) => {
                    tracing::info!(profile = %profile_name, "profile activated");
                    true
                }
                Err(e) => {
                    tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
                    false
                }
            };
            Some(EventKind::ProfileActivateResponse { success })
        }

        // -- Profile Deactivate (flush JIT, close vault) --
        EventKind::ProfileDeactivate { profile_name, .. } => {
            let Some(state) = ctx.unlocked_state.as_mut() else {
                tracing::warn!(profile = %profile_name, "profile deactivate while locked");
                return send_response(ctx.client, msg, EventKind::ProfileDeactivateResponse { success: false }, ctx.daemon_id).await;
            };
            let success = match state.deactivate_profile(profile_name).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(profile = %profile_name, error = %e, "profile deactivation failed");
                    false
                }
            };
            Some(EventKind::ProfileDeactivateResponse { success })
        }

        // -- Ignore other events --
        _ => None,
    };

    if let Some(event) = response_event {
        send_response(ctx.client, msg, event, ctx.daemon_id).await?;
    }

    Ok(true)
}

/// Send a correlated response to an inbound request.
async fn send_response(
    client: &mut BusClient,
    request: &Message<EventKind>,
    response_event: EventKind,
    daemon_id: DaemonId,
) -> anyhow::Result<bool> {
    let response = Message::new(
        daemon_id,
        response_event,
        request.security_level,
        client.epoch(),
    )
    .with_correlation(request.msg_id);

    client.send(&response).await.context("failed to send response")?;
    Ok(true)
}

/// Perform the unlock flow: derive master key from password.
///
/// Vaults are opened lazily on first access to each profile, not eagerly.
///
/// ADR-SEC-001 keyring integration:
/// 1. If salt exists and keyring has a wrapped key, try the fast path
///    (derive KEK, unwrap master key from keyring — avoids Argon2id).
/// 2. If fast path fails (wrong password, no keyring entry, first run),
///    fall through to full Argon2id derivation.
/// 3. After successful derivation, store KEK-wrapped master key in keyring.
async fn unlock(
    password: &[u8],
    config_dir: &Path,
    ttl: u64,
) -> core_types::Result<UnlockedState> {
    let sp = salt_path(config_dir);
    let salt_exists = sp.exists();

    // Fast path: try keyring retrieval (avoids Argon2id).
    #[cfg(target_os = "linux")]
    if salt_exists {
        let salt_bytes = std::fs::read(&sp).map_err(|e| {
            core_types::Error::Config(format!("failed to read salt: {e}"))
        })?;
        if let Some(master_key) = keyring_retrieve(password, &salt_bytes).await {
            return Ok(UnlockedState {
                master_key,
                vaults: HashMap::new(),
                ttl: Duration::from_secs(ttl),
                config_dir: config_dir.to_path_buf(),
            });
        }
    }

    // Slow path: full Argon2id derivation.
    let master_key = if salt_exists {
        subsequent_run_derive(password, config_dir)?
    } else {
        first_run_derive(password, config_dir)?
    };

    // Store KEK-wrapped master key in keyring for next unlock.
    #[cfg(target_os = "linux")]
    {
        let salt_bytes = std::fs::read(salt_path(config_dir)).map_err(|e| {
            core_types::Error::Config(format!("failed to read salt for keyring store: {e}"))
        })?;
        keyring_store(&master_key, password, &salt_bytes).await;
    }

    Ok(UnlockedState {
        master_key,
        vaults: HashMap::new(),
        ttl: Duration::from_secs(ttl),
        config_dir: config_dir.to_path_buf(),
    })
}

/// Wait for SIGTERM (Unix) or simulate on non-Unix.
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

/// Apply Landlock + seccomp sandbox (Linux only).
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{
        apply_sandbox, FsAccess, LandlockRule, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();

    let pds_dir = PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    let rules = vec![
        // Config dir: vault DBs + salt stored here.
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite,
        },
        // H-017: Per-daemon key file isolation (NIST AC-6). Only this daemon's keypair.
        LandlockRule {
            path: keys_dir.join("daemon-secrets.key"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-secrets.pub"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-secrets.checksum"),
            access: FsAccess::ReadOnly,
        },
        // Bus public key: needed if reconnect ever happens.
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        // Bus socket: connect + read/write IPC traffic.
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        // D-Bus socket — non-directory fd, use ReadWriteFile to avoid
        // PartiallyEnforced from directory-only landlock flags.
        LandlockRule {
            path: PathBuf::from(&runtime_dir).join("bus"),
            access: FsAccess::ReadWriteFile,
        },
    ];

    let seccomp = SeccompProfile {
        daemon_name: "daemon-secrets".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "unlink".into(),
            "fcntl".into(), "flock".into(), "fdatasync".into(),
            "mkdir".into(), "getdents64".into(),
            // Memory (secrets needs mlock/munlock/madvise for zeroization)
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "mlock".into(), "munlock".into(), "madvise".into(),
            "brk".into(),
            // Process / threading
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "getuid".into(), "geteuid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            // Networking / IPC
            "socket".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "socketpair".into(),
            "sendmsg".into(), "recvmsg".into(),
            "shutdown".into(), "getsockopt".into(),
            // Signals
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            // Misc
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(),
            "pipe2".into(), "dup".into(), "ioctl".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

// ============================================================================
// Platform keyring integration (ADR-SEC-001)
//
// The raw master key NEVER touches the platform keyring. Instead:
// 1. A KEK (key-encrypting-key) is derived from password+salt via BLAKE3
//    with a dedicated context string independent from Argon2id derivation.
// 2. The master key is AES-256-GCM encrypted under the KEK with a random nonce.
// 3. The wrapped blob [12-byte nonce || ciphertext || 16-byte tag] is stored.
// 4. On retrieval, the KEK is re-derived from password+salt, and the blob
//    is decrypted. GCM tag verification rejects wrong passwords.
// ============================================================================

/// KeyLocker service/account constants for platform keyring.
const KEYLOCKER_SERVICE: &str = "pds";
const KEYLOCKER_ACCOUNT: &str = "master-key";

/// Wrap the master key with a KEK and store the wrapped blob in the
/// platform keyring (best-effort).
///
/// Wire format: `[12-byte random nonce][ciphertext + 16-byte GCM tag]`
/// Total: 12 + 32 + 16 = 60 bytes for a 32-byte master key.
#[cfg(target_os = "linux")]
async fn keyring_store(master_key: &SecureBytes, password: &[u8], salt: &[u8]) {
    use core_secrets::KeyLocker;

    // Derive KEK from password+salt (BLAKE3, independent of Argon2id).
    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: KEK construction failed");
            return;
        }
    };

    // Random nonce for wrapping.
    let mut nonce = [0u8; 12];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        tracing::warn!(error = %e, "keyring: nonce generation failed");
        return;
    }

    // Encrypt master key under KEK.
    let ciphertext = match enc_key.encrypt(&nonce, master_key.as_bytes()) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: master key wrapping failed");
            return;
        }
    };

    // Wire format: [nonce || ciphertext+tag]
    let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend(ciphertext);

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker
        .store_wrapped_key(KEYLOCKER_SERVICE, KEYLOCKER_ACCOUNT, &wrapped)
        .await
    {
        Ok(()) => tracing::info!(wrapped_len = wrapped.len(), "KEK-wrapped master key stored in platform keyring"),
        Err(e) => tracing::warn!(error = %e, "keyring: failed to store wrapped key"),
    }
}

/// Retrieve and unwrap the master key from the platform keyring.
///
/// Returns `Some(master_key)` on success, `None` if the keyring entry
/// doesn't exist, the password is wrong (GCM tag fails), or any I/O error.
#[cfg(target_os = "linux")]
async fn keyring_retrieve(password: &[u8], salt: &[u8]) -> Option<SecureBytes> {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::debug!(error = %e, "keyring: failed to connect to session bus");
            return None;
        }
    };
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);

    // Check if a wrapped key exists.
    match locker.has_wrapped_key(KEYLOCKER_SERVICE, KEYLOCKER_ACCOUNT).await {
        Ok(true) => {}
        Ok(false) => return None,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: has_wrapped_key check failed");
            return None;
        }
    }

    // Retrieve the wrapped blob.
    let wrapped = match locker
        .retrieve_wrapped_key(KEYLOCKER_SERVICE, KEYLOCKER_ACCOUNT)
        .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: retrieve failed");
            return None;
        }
    };

    // Validate minimum size: 12 (nonce) + 32 (master key) + 16 (tag) = 60.
    if wrapped.len() < 60 {
        tracing::warn!(len = wrapped.len(), "keyring: wrapped blob too short, ignoring");
        return None;
    }

    // Derive KEK from password+salt.
    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: KEK construction failed");
            return None;
        }
    };

    // Split nonce and ciphertext.
    let nonce: [u8; 12] = wrapped.as_bytes()[..12].try_into().ok()?;
    let ciphertext = &wrapped.as_bytes()[12..];

    // Decrypt — GCM tag verification rejects wrong passwords.
    match enc_key.decrypt(&nonce, ciphertext) {
        Ok(master_key) => {
            tracing::info!("master key unwrapped from platform keyring (fast path)");
            Some(master_key)
        }
        Err(_) => {
            tracing::debug!("keyring: GCM tag verification failed (wrong password or corrupted)");
            None
        }
    }
}

/// Delete the wrapped master key from the platform keyring (best-effort).
#[cfg(target_os = "linux")]
async fn keyring_delete() {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker
        .delete_wrapped_key(KEYLOCKER_SERVICE, KEYLOCKER_ACCOUNT)
        .await
    {
        Ok(()) => tracing::info!("wrapped master key deleted from platform keyring"),
        Err(e) => tracing::debug!(error = %e, "keyring: delete failed (may not exist)"),
    }
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }

    Ok(())
}
