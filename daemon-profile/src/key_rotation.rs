//! Key rotation: two-phase Noise IK keypair rotation with grace period,
//! and shared keypair generation helper (DRY extraction).

use anyhow::Context;
use core_ipc::{BusServer, Message};
use core_profile::{AuditAction, AuditLogger};
use core_types::{DaemonId, EventKind, SecurityLevel};

use crate::{KEY_ROTATION_GRACE, KNOWN_DAEMONS};

/// Snapshot of daemon generations at phase 1 start.
/// Used by phase 2 to skip daemons that were revoked during the grace period.
static ROTATION_BASELINE: tokio::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
    tokio::sync::Mutex::const_new(None);

/// Key rotation phase 1: generate keypairs, write to disk, announce pending.
///
/// Returns immediately — does NOT sleep. The grace period is handled by a
/// spawned background task that signals phase 2 via channel.
pub(crate) async fn rotate_keys_phase1<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let noise_params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid noise params");
    let builder = snow::Builder::new(noise_params);

    // Snapshot generations BEFORE writing any new keys.
    let baseline = bus.registry_mut().await.snapshot_generations();

    for &(daemon_name, _security_level) in KNOWN_DAEMONS {
        let new_keypair = core_ipc::ZeroizingKeypair::new(
            builder
                .generate_keypair()
                .context(format!("failed to generate new keypair for {daemon_name}"))?,
        );

        let mut new_pubkey = [0u8; 32];
        new_pubkey.copy_from_slice(new_keypair.public());

        core_ipc::noise::write_daemon_keypair(daemon_name, new_keypair.as_inner())
            .await
            .context(format!("failed to write rotated keypair for {daemon_name}"))?;

        let event = EventKind::KeyRotationPending {
            daemon_name: daemon_name.into(),
            new_pubkey,
            grace_period_s: KEY_ROTATION_GRACE,
        };
        let msg = Message::new(&msg_ctx, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-pending",
            daemon = daemon_name,
            grace_period_s = KEY_ROTATION_GRACE,
            "key rotation announced"
        );
        let current_generation = bus
            .registry_mut()
            .await
            .find_by_name(daemon_name)
            .map_or(0, |(_, e)| e.generation);
        let _ = audit.append(AuditAction::KeyRotationStarted {
            daemon_name: daemon_name.into(),
            generation: current_generation,
        });
    }

    // Store baseline for phase 2.
    *ROTATION_BASELINE.lock().await = Some(baseline);

    Ok(())
}

/// Key rotation phase 2: atomic registry swap + announce completion.
///
/// Called after the grace period expires. Reads all new pubkeys first, then
/// acquires the registry write lock ONCE for an atomic batch update.
pub(crate) async fn rotate_keys_phase2<W: std::io::Write>(
    bus: &BusServer,
    daemon_id: DaemonId,
    audit: &mut AuditLogger<W>,
) -> anyhow::Result<()> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let baseline = ROTATION_BASELINE
        .lock()
        .await
        .take()
        .context("phase 2 called without phase 1 baseline")?;

    // Collect all new pubkeys before taking the lock (avoid per-daemon lock churn).
    let mut new_keys: Vec<(&str, [u8; 32], SecurityLevel)> = Vec::new();
    for &(daemon_name, security_level) in KNOWN_DAEMONS {
        let pubkey = core_ipc::noise::read_daemon_public_key(daemon_name)
            .await
            .context(format!("failed to read rotated pubkey for {daemon_name}"))?;
        new_keys.push((daemon_name, pubkey, security_level));
    }

    // Single lock acquisition — atomic swap, skipping daemons that were
    // already revoked-and-re-keyed during the grace period.
    {
        let mut reg = bus.registry_mut().await;
        for &(daemon_name, new_pubkey, security_level) in &new_keys {
            // Check if the daemon's generation advanced since phase 1.
            let current_gen = reg.find_by_name(daemon_name).map(|(_, e)| e.generation);
            let baseline_gen = baseline.get(daemon_name).copied();

            if current_gen != baseline_gen {
                tracing::info!(
                    audit = "key-management",
                    event_type = "rotation-skipped",
                    daemon = daemon_name,
                    baseline_gen = ?baseline_gen,
                    current_gen = ?current_gen,
                    "skipping rotation — daemon was revoked during grace period"
                );
                continue;
            }

            if let Some((old_key, _)) = reg.find_by_name(daemon_name) {
                let old_key = *old_key;
                reg.rotate_key(&old_key, new_pubkey);
            } else {
                reg.register(new_pubkey, daemon_name.into(), security_level);
            }
        }
    }

    // Announce completion for each daemon.
    for &(daemon_name, _, _) in &new_keys {
        let event = EventKind::KeyRotationComplete {
            daemon_name: daemon_name.into(),
        };
        let msg = Message::new(&msg_ctx, event, SecurityLevel::Internal, bus.epoch());
        if let Ok(payload) = core_ipc::encode_frame(&msg) {
            bus.publish(&payload, SecurityLevel::Internal).await;
        }

        tracing::info!(
            audit = "key-management",
            event_type = "key-rotation-complete",
            daemon = daemon_name,
            "key rotation complete, registry updated"
        );
        let current_generation = bus
            .registry_mut()
            .await
            .find_by_name(daemon_name)
            .map_or(0, |(_, e)| e.generation);
        let _ = audit.append(AuditAction::KeyRotationCompleted {
            daemon_name: daemon_name.to_string(),
            generation: current_generation,
        });
    }

    Ok(())
}
