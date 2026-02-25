//! Filesystem and syscall sandboxing via Landlock and seccomp-bpf.
//!
//! Each daemon calls `apply_landlock()` after opening all needed file
//! descriptors, then `apply_seccomp()` to restrict syscalls. Order matters:
//! seccomp is applied AFTER landlock because landlock setup requires
//! syscalls that seccomp would block.
//!
//! Landlock: unprivileged filesystem sandboxing (kernel >= 5.13, ABI V1+).
//! seccomp-bpf: syscall filtering via libseccomp (C library).
//!
//! Phase 1: type definitions and API surface. Implementations in Phase 2+.

/// Filesystem access rights for Landlock rules.
#[derive(Debug, Clone, Copy)]
pub enum FsAccess {
    ReadOnly,
    ReadWrite,
    Execute,
}

/// A single Landlock filesystem rule: path + access rights.
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: std::path::PathBuf,
    pub access: FsAccess,
}

/// Result of applying a Landlock ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// All rules enforced at requested ABI level.
    FullyEnforced,
    /// Some rules degraded due to older kernel ABI.
    PartiallyEnforced,
    /// Landlock not available on this kernel.
    NotEnforced,
}

/// Apply Landlock filesystem sandbox with the given rules.
///
/// Calls `prctl(PR_SET_NO_NEW_PRIVS)` then `landlock_restrict_self()`.
/// Once applied, the process cannot gain additional filesystem access.
///
/// Uses `CompatLevel::BestEffort` for graceful degradation on older kernels.
/// Returns the enforcement status so callers can decide whether to proceed
/// or abort on partial enforcement.
///
/// Phase 1: returns `NotEnforced` (no implementation yet).
pub fn apply_landlock(_rules: &[LandlockRule]) -> core_types::Result<EnforcementStatus> {
    Ok(EnforcementStatus::NotEnforced)
}

/// Predefined seccomp-bpf profile for a daemon.
///
/// Each daemon declares its required syscall set. The profile is translated
/// to a seccomp filter that kills the process on disallowed syscalls.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub daemon_name: String,
    pub allowed_syscalls: Vec<String>,
}

/// Apply a seccomp-bpf syscall filter.
///
/// Must be called AFTER `apply_landlock()` — landlock setup syscalls would
/// be blocked by seccomp.
///
/// Default action: `SCMP_ACT_KILL_PROCESS` for disallowed syscalls.
///
/// Phase 1: no-op (no implementation yet).
pub fn apply_seccomp(_profile: &SeccompProfile) -> core_types::Result<()> {
    tracing::warn!(
        daemon = %_profile.daemon_name,
        "seccomp not yet implemented (Phase 2); running without syscall filtering"
    );
    Ok(())
}

/// Apply the full sandbox stack for a daemon: Landlock then seccomp.
///
/// Convenience function that combines `apply_landlock()` + `apply_seccomp()`.
///
/// Phase 1: logs warnings, does not enforce.
pub fn apply_sandbox(
    landlock_rules: &[LandlockRule],
    seccomp_profile: &SeccompProfile,
) -> core_types::Result<EnforcementStatus> {
    let status = apply_landlock(landlock_rules)?;
    apply_seccomp(seccomp_profile)?;
    Ok(status)
}
