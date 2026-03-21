//! Context engine helpers: activation rule construction, audit state recovery,
//! and audit chain verification.

use anyhow::Context;
use core_profile::context::{ProfileActivation, RuleCombinator};
use std::path::PathBuf;

/// Build activation rules from the loaded config.
///
/// Parses `activation_rules`, `rule_combinator`, `priority` from
/// each profile's config. For now: single default profile with no context rules.
pub(crate) fn build_activation_rules(
    config: &core_config::Config,
    default_id: core_types::ProfileId,
    install_ns: &uuid::Uuid,
) -> Vec<ProfileActivation> {
    use core_profile::context::{ActivationRule, RuleTrigger};

    let mut activations = Vec::new();

    for (idx, (name, profile)) in config.profiles.iter().enumerate() {
        let act = &profile.activation;
        let mut rules = Vec::new();

        for ssid in &act.wifi_ssids {
            rules.push(ActivationRule {
                trigger: RuleTrigger::Ssid,
                value: ssid.clone(),
            });
        }

        for usb in &act.usb_devices {
            rules.push(ActivationRule {
                trigger: RuleTrigger::UsbDevice,
                value: usb.clone(),
            });
        }

        for time_rule in &act.time_rules {
            rules.push(ActivationRule {
                trigger: RuleTrigger::TimeWindow,
                value: time_rule.clone(),
            });
        }

        if act.require_security_key {
            rules.push(ActivationRule {
                trigger: RuleTrigger::HardwareKey,
                value: "present".into(),
            });
        }

        // Derive a deterministic ProfileId from the profile name so IDs are
        // stable across restarts.  The default profile keeps its caller-supplied
        // ID for backwards compatibility with the rest of daemon-profile.
        let profile_id = if name == &config.global.default_profile.to_string() {
            default_id
        } else {
            core_types::ProfileId::from_uuid(uuid::Uuid::new_v5(
                install_ns,
                format!("profile:{}", name).as_bytes(),
            ))
        };

        activations.push(ProfileActivation {
            profile_id,
            rules,
            combinator: RuleCombinator::Any,
            priority: idx as u32,
            switch_delay_ms: 0,
        });
    }

    if activations.is_empty() {
        activations.push(ProfileActivation {
            profile_id: default_id,
            rules: vec![],
            combinator: RuleCombinator::Any,
            priority: 0,
            switch_delay_ms: 0,
        });
    }

    activations
}

/// Load the last hash and sequence from an existing audit log.
pub(crate) fn load_audit_state(path: &PathBuf) -> (String, u64) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return (String::new(), 0);
    };

    let Some(last_line) = contents.lines().rev().find(|l| !l.trim().is_empty()) else {
        return (String::new(), 0);
    };

    if let Ok(entry) = serde_json::from_str::<core_profile::AuditEntry>(last_line) {
        let hash = blake3::hash(last_line.as_bytes());
        (hash.to_hex().to_string(), entry.sequence)
    } else {
        tracing::warn!(path = %path.display(), "failed to parse last audit entry; starting fresh chain");
        (String::new(), 0)
    }
}

/// Verify the audit log hash chain integrity.
pub(crate) fn verify_audit_chain(path: &PathBuf) -> anyhow::Result<u64> {
    let contents = std::fs::read_to_string(path).context("failed to read audit log")?;
    core_profile::verify_chain(&contents, &core_types::AuditHash::Blake3)
        .map_err(|e| anyhow::anyhow!("{e}"))
}
