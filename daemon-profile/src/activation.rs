//! Profile activation/deactivation transaction with rollback.
//!
//! Coordinates the multi-step process of activating or deactivating a profile
//! across daemons. Each step is recorded so that on failure, completed steps
//! can be reversed in exact reverse order.
//!
//! Activation:
//!   1. Emit `ProfileActivationBegun` on IPC bus
//!   2. Send `ProfileActivate` to daemon-secrets (opens vault, initializes JIT)
//!   3. Emit `ProfileActivated` on IPC bus
//!   4. Append audit entry
//!
//! Deactivation:
//!   1. Emit `ProfileDeactivationBegun` on IPC bus
//!   2. Send `ProfileDeactivate` to daemon-secrets (flushes JIT, closes vault)
//!   3. Emit `ProfileDeactivated` on IPC bus
//!   4. Append audit entry
//!
//! If any step fails, completed steps are reversed. If rollback also fails,
//! the error is logged and `ProfileActivationFailed` is emitted (best-effort).

use core_ipc::{BusServer, Message};
use core_profile::AuditLogger;
use core_types::{DaemonId, EventKind, ProfileId, SecurityLevel, TrustProfileName};
use std::time::Instant;

/// Steps completed during an activation/deactivation, for rollback tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletedStep {
    ActivationBegunEmitted,
    SecretsVaultOpened,
    SecretsJitFlushed,
    SecretsVaultClosed,
    ActivationCompletedEmitted,
}

/// Execute a profile activation transaction.
///
/// Coordinates with daemon-secrets via IPC to open the vault, then emits
/// bus events and writes an audit entry. Returns the elapsed duration on
/// success, or an error with best-effort rollback on failure.
pub async fn activate<W: std::io::Write>(
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
) -> Result<u32, String> {
    let start = Instant::now();
    let mut completed: Vec<CompletedStep> = Vec::new();

    // Step 1: Emit ActivationBegun broadcast.
    let begun_event = EventKind::ProfileActivationBegun {
        target,
        trigger: format!("explicit activation of {profile_name}"),
    };
    if let Err(e) = broadcast(bus, daemon_id, begun_event).await {
        return Err(format!("failed to emit ActivationBegun: {e}"));
    }
    completed.push(CompletedStep::ActivationBegunEmitted);

    // Step 2: Send ProfileActivate to daemon-secrets.
    let activate_event = EventKind::ProfileActivate {
        profile_name: profile_name.clone(),
        target,
    };
    if let Err(e) = broadcast(bus, daemon_id, activate_event).await {
        rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
        return Err(format!("failed to send ProfileActivate: {e}"));
    }
    completed.push(CompletedStep::SecretsVaultOpened);

    // Step 3: Emit ProfileActivated broadcast.
    let duration_ms = start.elapsed().as_millis() as u32;
    let activated_event = EventKind::ProfileActivated {
        target,
        duration_ms,
    };
    if let Err(e) = broadcast(bus, daemon_id, activated_event).await {
        rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
        return Err(format!("failed to emit ProfileActivated: {e}"));
    }
    completed.push(CompletedStep::ActivationCompletedEmitted);

    // Step 4: Append audit entry.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileActivated {
        target,
        duration_ms,
    }) {
        tracing::error!(error = %e, "failed to write activation audit entry");
        // Audit failure is logged but does not trigger rollback —
        // the activation itself succeeded.
    }

    Ok(duration_ms)
}

/// Execute a profile deactivation transaction.
///
/// Coordinates with daemon-secrets via IPC to flush JIT cache and close
/// the vault, then emits bus events and writes an audit entry.
pub async fn deactivate<W: std::io::Write>(
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
) -> Result<u32, String> {
    let start = Instant::now();
    let mut completed: Vec<CompletedStep> = Vec::new();

    // Step 1: Emit DeactivationBegun broadcast.
    let begun_event = EventKind::ProfileDeactivationBegun { target };
    if let Err(e) = broadcast(bus, daemon_id, begun_event).await {
        return Err(format!("failed to emit DeactivationBegun: {e}"));
    }
    completed.push(CompletedStep::ActivationBegunEmitted);

    // Step 2: Send ProfileDeactivate to daemon-secrets.
    let deactivate_event = EventKind::ProfileDeactivate {
        profile_name: profile_name.clone(),
        target,
    };
    if let Err(e) = broadcast(bus, daemon_id, deactivate_event).await {
        rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
        return Err(format!("failed to send ProfileDeactivate: {e}"));
    }
    completed.push(CompletedStep::SecretsJitFlushed);
    completed.push(CompletedStep::SecretsVaultClosed);

    // Step 3: Emit ProfileDeactivated broadcast.
    let duration_ms = start.elapsed().as_millis() as u32;
    let deactivated_event = EventKind::ProfileDeactivated {
        target,
        duration_ms,
    };
    if let Err(e) = broadcast(bus, daemon_id, deactivated_event).await {
        rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
        return Err(format!("failed to emit ProfileDeactivated: {e}"));
    }
    completed.push(CompletedStep::ActivationCompletedEmitted);

    // Step 4: Append audit entry.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileDeactivated {
        target,
        duration_ms,
    }) {
        tracing::error!(error = %e, "failed to write deactivation audit entry");
    }

    Ok(duration_ms)
}

/// Serialize and publish an event on the bus.
async fn broadcast(
    bus: &BusServer,
    daemon_id: DaemonId,
    event: EventKind,
) -> Result<(), String> {
    let msg = Message::new(daemon_id, event, SecurityLevel::Internal, bus.epoch());
    let payload = core_ipc::encode_frame(&msg).map_err(|e| e.to_string())?;
    bus.publish(&payload, SecurityLevel::Internal).await;
    Ok(())
}

/// Best-effort rollback of completed steps in reverse order.
///
/// Emits `ProfileActivationFailed` if rollback is attempted. Writes an
/// audit entry for the failure. Individual rollback step failures are
/// logged but do not propagate.
async fn rollback<W: std::io::Write>(
    completed: &[CompletedStep],
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
) {
    tracing::warn!(
        target = %target,
        profile = %profile_name,
        steps = completed.len(),
        "rolling back activation/deactivation"
    );

    for step in completed.iter().rev() {
        match step {
            CompletedStep::SecretsVaultOpened => {
                let event = EventKind::ProfileDeactivate {
                    profile_name: profile_name.clone(),
                    target,
                };
                if let Err(e) = broadcast(bus, daemon_id, event).await {
                    tracing::error!(error = %e, "rollback: failed to deactivate secrets vault");
                }
            }
            CompletedStep::SecretsJitFlushed | CompletedStep::SecretsVaultClosed => {
                let event = EventKind::ProfileActivate {
                    profile_name: profile_name.clone(),
                    target,
                };
                if let Err(e) = broadcast(bus, daemon_id, event).await {
                    tracing::error!(error = %e, "rollback: failed to re-activate secrets vault");
                }
            }
            CompletedStep::ActivationBegunEmitted
            | CompletedStep::ActivationCompletedEmitted => {}
        }
    }

    // Audit the failure.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileActivationFailed {
        target,
        reason: "transaction rolled back".into(),
    }) {
        tracing::error!(error = %e, "rollback: failed to write audit entry");
    }

    // Emit failure event on bus (best-effort).
    let event = EventKind::ProfileActivationFailed {
        target,
        reason: "transaction rolled back".into(),
    };
    let _ = broadcast(bus, daemon_id, event).await;
}
