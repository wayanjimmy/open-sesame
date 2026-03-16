//! Process-level security hardening.
//!
//! Called early in daemon startup before any key material is loaded.

/// Disable core dumps and mark the process as non-dumpable.
///
/// - `PR_SET_DUMPABLE(0)`: Prevents ptrace-attach by non-root processes.
///   Also prevents core dumps from containing process memory.
/// - `RLIMIT_CORE(0,0)`: Belt-and-suspenders with `PR_SET_DUMPABLE`.
///   Prevents core files even if dumpable is re-enabled by setuid.
///
/// Logs errors via tracing but does not fail — these are best-effort hardening.
/// A daemon should still apply Landlock/seccomp even if these calls fail.
pub fn harden_process() {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` is a simple integer flag operation
    // with no pointer arguments, no preconditions, and no UB on failure (returns -1).
    // Signal-safe per POSIX.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            tracing::error!(
                "prctl(PR_SET_DUMPABLE, 0) failed (errno {}) — \
                 process may be ptrace-attachable",
                *libc::__errno_location()
            );
        }
    }

    // SAFETY: `setrlimit(RLIMIT_CORE, &rlimit{0,0})` is a simple struct-pointer
    // operation. The rlimit struct is stack-allocated and valid for the call
    // duration. No UB on failure (returns -1).
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            tracing::error!(
                "setrlimit(RLIMIT_CORE, 0) failed (errno {}) — \
                 core dumps may still be enabled",
                *libc::__errno_location()
            );
        }
    }

    tracing::debug!("process hardening applied: non-dumpable, no core dumps");
}

/// Resource limits for a daemon, applied via setrlimit (POSIX).
///
/// This makes resource limits application-owned rather than solely relying
/// on systemd `LimitNOFILE=`/`LimitMEMLOCK=`. On platforms without systemd
/// (macOS launchd, Windows Task Scheduler, bare metal), the application
/// still enforces its own resource boundaries.
pub struct ResourceLimits {
    /// Maximum open file descriptors (RLIMIT_NOFILE).
    pub nofile: u64,
    /// Maximum locked memory in bytes (RLIMIT_MEMLOCK). 0 = don't set.
    pub memlock_bytes: u64,
}

/// Apply resource limits via setrlimit.
///
/// Should be called early in daemon startup, before sandbox application.
/// Logs warnings on failure but does not panic — systemd limits provide
/// a fallback on Linux, and the daemon can still run with defaults.
pub fn apply_resource_limits(limits: &ResourceLimits) {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: limits.nofile,
            rlim_max: limits.nofile,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
            tracing::warn!(
                nofile = limits.nofile,
                errno = *libc::__errno_location(),
                "setrlimit(RLIMIT_NOFILE) failed — using system default"
            );
        } else {
            tracing::info!(nofile = limits.nofile, "RLIMIT_NOFILE set");
        }

        if limits.memlock_bytes > 0 {
            let rlim = libc::rlimit {
                rlim_cur: limits.memlock_bytes,
                rlim_max: limits.memlock_bytes,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
                tracing::warn!(
                    memlock_bytes = limits.memlock_bytes,
                    errno = *libc::__errno_location(),
                    "setrlimit(RLIMIT_MEMLOCK) failed — using system default"
                );
            } else {
                tracing::info!(memlock_bytes = limits.memlock_bytes, "RLIMIT_MEMLOCK set");
            }
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    // SECURITY INVARIANT: After harden_process(), the process must not be
    // dumpable. PR_GET_DUMPABLE == 0 prevents ptrace-attach by non-root
    // and prevents core dumps from containing process memory.
    #[test]
    fn harden_process_disables_dumpable() {
        harden_process();
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(
            dumpable, 0,
            "process must be non-dumpable after harden_process()"
        );
    }

    // SECURITY INVARIANT: After harden_process(), RLIMIT_CORE must be zero
    // (both soft and hard limits). This prevents core dumps even if dumpable
    // is re-enabled by setuid (belt-and-suspenders).
    #[test]
    fn harden_process_sets_rlimit_core_zero() {
        harden_process();
        let mut rlim = libc::rlimit {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };
        assert_eq!(rc, 0, "getrlimit should succeed");
        assert_eq!(rlim.rlim_cur, 0, "RLIMIT_CORE soft limit must be 0");
        assert_eq!(rlim.rlim_max, 0, "RLIMIT_CORE hard limit must be 0");
    }
}
