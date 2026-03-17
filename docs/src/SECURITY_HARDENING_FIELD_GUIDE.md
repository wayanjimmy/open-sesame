# Security Hardening Field Guide

A practical, encyclopedic reference for debugging and troubleshooting Linux
security hardening across seccomp-bpf, Landlock, systemd sandboxing, and
related tooling. Written for engineers hardening multi-daemon Linux applications.

---

## 1. Overview

Modern Linux application hardening is built on **defense-in-depth**: multiple
independent security layers that each reduce the blast radius of a compromise.
No single layer is sufficient. The three primary layers are:

| Layer | Scope | Enforced By |
|---|---|---|
| **systemd sandboxing** | Mount namespaces, resource limits, lifecycle | systemd (PID 1 / user manager) |
| **Landlock** | Filesystem access control | Kernel LSM, applied per-process |
| **seccomp-bpf** | Syscall filtering | Kernel, applied per-thread/process |

These layers compose because they operate at different abstraction levels:

- **systemd mount namespaces** control what the process *can see* on the
  filesystem. A process inside `ProtectSystem=strict` literally cannot write
  to `/usr` because its mount namespace has a read-only bind mount.
- **Landlock** controls what the process *is allowed to access* within the
  paths it can see. Even if systemd exposes a writable path, Landlock can
  restrict the process to specific subdirectories.
- **seccomp-bpf** controls what the process *is allowed to do* at the syscall
  level. Even if a process can open a file, seccomp can block it from calling
  `execve`, `ptrace`, or `mount`.

A compromised daemon that escapes one layer still faces the others. This guide
covers how to implement each layer correctly, the non-obvious failure modes,
and how to debug them when things go wrong.

---

## 2. seccomp-bpf

### 2.1 How seccomp works

seccomp-bpf attaches a BPF program to a process (or thread) that intercepts
every syscall *before* the kernel executes it. The BPF program inspects the
syscall number and arguments, then returns a verdict.

**Activation:**

```c
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // required first
seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
```

The `SECCOMP_FILTER_FLAG_TSYNC` flag is critical for multi-threaded programs:
it synchronizes the filter to *all* threads in the thread group atomically. Without
it, each thread must install the filter individually, creating a race window.

**Action modes:**

| Action | Behavior | Use Case |
|---|---|---|
| `SECCOMP_RET_KILL_PROCESS` | Kills the entire process with SIGSYS | Production: fail-closed, no zombie threads |
| `SECCOMP_RET_KILL_THREAD` | Kills only the offending thread | Dangerous with async runtimes (see 2.2) |
| `SECCOMP_RET_ERRNO` | Returns an errno to the caller | Graceful degradation, testable |
| `SECCOMP_RET_LOG` | Allows but logs via audit | Development/audit mode |

**Choosing an action mode:**

- Use `SECCOMP_RET_KILL_PROCESS` in production. It is the safest default.
  A process that violates its seccomp policy is compromised and should die.
- Use `SECCOMP_RET_LOG` during development to discover which syscalls your
  code actually needs without killing it.
- Use `SECCOMP_RET_ERRNO(EPERM)` only when you have code that gracefully
  handles the error (e.g., optional features that degrade).
- **Avoid `SECCOMP_RET_KILL_THREAD`** unless you fully understand the
  implications for your threading model. Read section 2.2.

### 2.2 KillThread + async runtimes (CRITICAL)

This is the single most dangerous failure mode in seccomp'd async applications.

When `SECCOMP_RET_KILL_THREAD` kills a thread in tokio's (or async-std's)
blocking thread pool, the `JoinHandle` returned by `spawn_blocking` **never
resolves**. The kernel destroys the thread. The channel that the runtime uses
to send the result back is dropped without sending. The `JoinHandle` future
polls forever.

The cascade:

1. A `spawn_blocking` task calls a blocked syscall (e.g., `ftruncate` for
   SQLite WAL rollback).
2. seccomp kills that thread with SIGSYS.
3. The `JoinHandle` future never completes.
4. The `tokio::select!` branch waiting on that handle blocks forever.
5. The event loop freezes. No other futures make progress.
6. The watchdog timer (if it ticks inside the same event loop) stops ticking.
7. systemd's `WatchdogSec` fires and kills the process.

**This is silent.** No logs. No crash. No panic. The process simply freezes
and systemd eventually SIGKILLs it. Journalctl shows a watchdog timeout with
no preceding error messages.

**Design rule:** Every `spawn_blocking` in a seccomp-filtered process MUST
have a timeout wrapper:

```rust
use tokio::time::{timeout, Duration};

let result = timeout(
    Duration::from_secs(10),
    tokio::task::spawn_blocking(move || {
        // potentially blocked operation
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    }),
)
.await;

match result {
    Ok(Ok(Ok(rows))) => { /* success */ }
    Ok(Ok(Err(e))) => { /* database error */ }
    Ok(Err(e)) => { /* JoinError: thread panicked */ }
    Err(_) => {
        // TIMEOUT: likely seccomp killed the thread
        tracing::error!("spawn_blocking timed out -- possible seccomp kill");
        // Initiate graceful shutdown or restart
    }
}
```

This does not prevent the thread death, but it prevents the entire event loop
from freezing and gives you a log line to debug.

### 2.3 SIGSYS signal handler

When seccomp blocks a syscall, the kernel delivers SIGSYS to the thread before
killing it (for `KILL_THREAD`) or to the process (for `KILL_PROCESS`). You can
install a handler to log which syscall was blocked.

**Constraints:** The signal handler runs in signal context. You must not
allocate, lock mutexes, or call most libc functions. Use only async-signal-safe
functions.

```rust
use libc::{
    c_int, c_void, sigaction, siginfo_t, SA_RESETHAND, SA_SIGINFO, SIGSYS,
};

unsafe extern "C" fn sigsys_handler(
    _sig: c_int,
    info: *mut siginfo_t,
    _ctx: *mut c_void,
) {
    // si_syscall contains the blocked syscall number
    let syscall = (*info).si_syscall;

    // Write directly to stderr (fd 2) -- no allocator, no buffering
    // Manual integer formatting in a stack buffer
    let mut buf = [0u8; 64];
    let prefix = b"seccomp: blocked syscall ";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();

    // Convert syscall number to decimal digits
    if syscall == 0 {
        buf[pos] = b'0';
        pos += 1;
    } else {
        let mut n = syscall;
        let start = pos;
        while n > 0 {
            buf[pos] = b'0' + (n % 10) as u8;
            pos += 1;
            n /= 10;
        }
        buf[start..pos].reverse();
    }
    buf[pos] = b'\n';
    pos += 1;

    let _ = libc::write(2, buf.as_ptr() as *const c_void, pos);
}

pub fn install_sigsys_handler() {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsys_handler as usize;
        sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
        sigaction(SIGSYS, &sa, std::ptr::null_mut());
    }
}
```

**Important:** Install the handler *before* applying the seccomp filter.

**Why output may not appear in journalctl:**

- With `KILL_THREAD`, the thread dies but the process lives. The write to
  stderr may succeed, but if the process later freezes (see 2.2), journald
  may not flush the pipe buffer before systemd kills it.
- With `KILL_PROCESS`, the write races against process teardown.
- Use `SA_RESETHAND` so the handler fires once, then the default (kill) takes
  effect on the next violation.

### 2.4 Building seccomp allowlists with strace

The only reliable way to build a seccomp allowlist is to trace your application
under real workloads.

**Step 1: Trace all threads**

```bash
# Attach to a running process
strace -f -o /tmp/trace.log -p $(pidof my-daemon)

# Or launch under strace
strace -f -o /tmp/trace.log -- ./my-daemon
```

The `-f` flag follows child threads and processes.

**Step 2: Exercise ALL code paths**

This is where most allowlists fail. You must exercise:

- Startup and initialization
- Normal operation (happy path)
- Error paths (invalid input, network failure, disk full)
- Shutdown (graceful and SIGTERM)
- Database operations (open, read, write, WAL checkpoint, vacuum)
- Config reload (inotify, file re-read)
- IPC (socket creation, connection, message exchange)

**Step 3: Extract unique syscalls**

```bash
awk -F'(' '{print $1}' /tmp/trace.log \
  | sed 's/^[0-9]* *//' \
  | sort -u \
  > /tmp/syscalls.txt
```

**Step 4: Diff against your allowlist**

Compare the trace output against your current allowlist. Add any missing
syscalls.

**Commonly missed syscalls:**

| Syscall | Triggered By |
|---|---|
| `ftruncate` | SQLite WAL rollback/checkpoint |
| `fsync` | SQLite PRAGMA, checkpoint, journal |
| `fdatasync` | SQLite WAL writes |
| `pwrite64` | SQLite WAL page writes |
| `fallocate` | SQLite pre-allocating journal/WAL space |
| `readlink` | Symlink resolution (common on NixOS) |
| `inotify_init1` | File watcher initialization |
| `inotify_add_watch` | Watching config files for changes |
| `inotify_rm_watch` | Cleaning up file watches |
| `statx` | Modern stat replacement (glibc 2.28+) |
| `getrandom` | Cryptographic RNG, SQLCipher |
| `clone3` | Modern thread creation (glibc 2.34+) |

### 2.5 Common pitfalls

**fdatasync vs fsync:**
SQLite uses *both*. `fdatasync` for WAL writes (it only needs data, not
metadata). `fsync` for PRAGMA operations and WAL checkpoints (it needs full
metadata sync). Missing either one causes intermittent seccomp kills that
only trigger under write load.

**SQLite WAL mode syscall set:**
A complete SQLite WAL allowlist includes: `openat`, `ftruncate`, `pwrite64`,
`pread64`, `fallocate`, `rename`, `fsync`, `fdatasync`, `fcntl` (for
`F_SETLK`/`F_GETLK` advisory locking), `fstat`, `lseek`, `unlink`.

**D-Bus / zbus syscalls:**
If your daemon communicates over D-Bus (e.g., for desktop integration):
`socket`, `connect`, `sendmsg`, `recvmsg`, `geteuid` (D-Bus auth), `shutdown`,
`getsockopt`, `setsockopt`.

**inotify file watchers:**
Any config hot-reload mechanism using inotify needs: `inotify_init1`,
`inotify_add_watch`, `inotify_rm_watch`, `read` (for reading events from the
inotify fd), `epoll_ctl` (if using epoll to watch the inotify fd).

**SECCOMP_FILTER_FLAG_TSYNC timing:**
`TSYNC` applies the filter to all *existing* threads. If a file watcher
thread was spawned before seccomp is applied, it gets the filter too. If that
thread's syscalls are not in the allowlist, it dies. Either:

1. Apply seccomp *before* spawning any background threads, or
2. Ensure the allowlist covers all threads' syscalls, or
3. Have background threads install their own filters before doing work.

---

## 3. Landlock

### 3.1 How Landlock works

Landlock is a Linux Security Module (LSM) that provides unprivileged,
process-level filesystem access control. Unlike seccomp (which filters
syscalls), Landlock filters *filesystem operations* on specific paths.

```rust
// Pseudocode for Landlock setup
let ruleset = Ruleset::default()
    .handle_access(AccessFs::from_all(abi_version))?
    .create()?;

// Grant read-only access to config directory
ruleset.add_rule(PathBeneath::new(
    File::open("/etc/myapp")?,
    AccessFs::ReadFile | AccessFs::ReadDir,
))?;

// Grant read-write access to runtime directory
ruleset.add_rule(PathBeneath::new(
    File::open("/run/user/1000/myapp")?,
    AccessFs::from_all(abi_version),
))?;

// Enforce -- no more rules can be added after this
ruleset.restrict_self()?;
```

**Key properties:**

- Rules are **additive**: you start with no access and grant specific paths.
- Rules are **inherited**: child processes inherit the restriction.
- Rules are **stackable**: multiple Landlock rulesets compose (intersection).
- Landlock requires **no privileges** -- any process can restrict itself.

**ABI versions** (V1 through V6) add support for new access rights. Always
query the running kernel's supported version and degrade gracefully:

```rust
let abi = landlock::ABI::V3; // minimum supported
let actual = landlock::ABI::new_current().unwrap_or(abi);
```

### 3.2 Symlink resolution

Landlock grants access to the **resolved path**, not the symlink itself.
This is a critical distinction on distributions that use symlink farms.

**NixOS and Guix** store all packages in `/nix/store/` (or `/gnu/store/`)
and symlink configuration files into place:

```
/etc/myapp/config.toml -> /nix/store/abc123-myapp-config/config.toml
```

If you grant Landlock access to `/etc/myapp/`, the process can open the
symlink. But the *target* is in `/nix/store/`, which is not in the ruleset.
The open fails with `EACCES`.

**Solution:** Canonicalize all config paths before building Landlock rules:

```rust
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashSet;

fn resolve_landlock_paths(paths: &[&str]) -> HashSet<PathBuf> {
    let mut resolved = HashSet::new();
    for path in paths {
        let p = Path::new(path);
        if p.exists() {
            // Add the original path
            resolved.insert(p.to_path_buf());
            // Add the canonical (resolved) path
            if let Ok(canonical) = fs::canonicalize(p) {
                resolved.insert(canonical.clone());
                // Also add parent directories for traversal
                if let Some(parent) = canonical.parent() {
                    resolved.insert(parent.to_path_buf());
                }
            }
        }
    }
    resolved
}
```

Then add *all* resolved paths as read-only rules.

### 3.3 Common pitfalls

**`/dev/urandom` blocked:**
SQLCipher and OpenSSL read from `/dev/urandom` for random bytes. If Landlock
blocks `/dev/urandom`, they fall back to the `getrandom()` syscall, which
bypasses the filesystem entirely. This usually works, but you may see `EACCES`
errors in logs. Grant read access to `/dev/urandom` to silence them:

```rust
ruleset.add_rule(PathBeneath::new(
    File::open("/dev/urandom")?,
    AccessFs::ReadFile,
))?;
```

**`NOTIFY_SOCKET` path:**
`sd_notify()` communicates with systemd via a Unix socket whose path is in
`$NOTIFY_SOCKET`. This can be either:

- **Abstract socket** (prefixed with `@`): Bypasses the filesystem entirely.
  Landlock does not apply. No rule needed.
- **Filesystem socket** (e.g., `/run/user/1000/systemd/notify`): Landlock
  must allow write access to this path, or `sd_notify()` silently fails.

Check before adding rules:

```rust
if let Ok(sock) = std::env::var("NOTIFY_SOCKET") {
    if !sock.starts_with('@') {
        // Filesystem socket -- add to Landlock rules
        let sock_path = Path::new(&sock);
        if let Some(parent) = sock_path.parent() {
            ruleset.add_rule(PathBeneath::new(
                File::open(parent)?,
                AccessFs::WriteFile,
            ))?;
        }
    }
}
```

**Abstract sockets bypass Landlock entirely:**
Any Unix domain socket with an abstract address (beginning with a null byte,
shown as `@` in `ss` output) is not subject to Landlock filesystem rules.
This is by design -- abstract sockets live in the network namespace, not the
filesystem. If you need to restrict abstract socket access, use seccomp to
filter `connect`/`bind` with argument inspection, or use network namespaces.

---

## 4. systemd Sandboxing

### 4.1 Mount namespaces

systemd can create per-service mount namespaces that restrict the filesystem
view. This is the outermost sandbox layer.

Key directives for `[Service]` sections:

```ini
[Service]
# Read-only root filesystem (bind mount overlays)
ProtectSystem=strict

# User home directory is read-only
ProtectHome=read-only

# Specific writable paths (bind-mounted into the namespace)
ReadWritePaths=/run/user/%U/myapp /home/%U/.local/share/myapp

# Restrict /proc, /sys, kernel tunables
ProtectProc=invisible
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Private /tmp
PrivateTmp=yes

# No new privileges (required for seccomp)
NoNewPrivileges=yes

# Restrict capabilities
CapabilityBoundingSet=
AmbientCapabilities=
```

**Critical requirement:** Every path listed in `ReadWritePaths=` **must exist
on the host** before the service starts. If the directory does not exist,
systemd cannot create the bind mount, and the service fails with
**exit status 226/NAMESPACE**.

This is the most common systemd sandbox failure mode.

### 4.2 tmpfiles.d for directory pre-creation

The chicken-and-egg problem: your daemon creates its directories on first
run, but systemd's mount namespace fails if those directories do not already
exist.

**Solution:** Use `systemd-tmpfiles` to create directories at user session
login, before any service starts.

For NixOS (in your system or home-manager configuration):

```nix
systemd.user.tmpfiles.rules = [
  "d %t/myapp        0700 - - -"    # /run/user/UID/myapp
  "d %h/.config/myapp 0700 - - -"   # ~/.config/myapp
  "d %h/.local/share/myapp 0700 - - -"
];
```

For other distributions, create `~/.config/systemd/user/tmpfiles.d/myapp.conf`:

```
# Type  Path                      Mode  User  Group  Age
d       %t/myapp                  0700  -     -      -
d       %h/.config/myapp          0700  -     -      -
d       %h/.local/share/myapp     0700  -     -      -
```

Specifiers: `%t` = `$XDG_RUNTIME_DIR`, `%h` = `$HOME`, `%U` = numeric UID.

**For wipe/reinitialize flows** (e.g., factory reset, test harness):

```bash
# Recreate directories after wiping
rm -rf ~/.local/share/myapp
systemd-tmpfiles --user --create
systemctl --user restart myapp.service
```

**Defense-in-depth:** The application should also create its directories on
startup (a `bootstrap_dirs()` function) so it works on platforms without
systemd (containers, macOS, BSDs). tmpfiles.d is the systemd-specific layer;
application bootstrap is the portable layer.

### 4.3 Service type alignment

**`Type=notify`:**
The daemon signals readiness by calling `sd_notify("READY=1")`. systemd waits
for this signal before marking the service as active.

```rust
// Using the sd-notify crate or raw socket write
sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;
```

If you set `Type=simple` but your daemon calls `sd_notify`, **systemd ignores
the notification silently**. The service is marked active immediately on exec.
This is not an error -- it just means your readiness signal does nothing.

**`WatchdogSec=`:**
The daemon must call `sd_notify("WATCHDOG=1")` at least every
`WatchdogSec / 2` interval. If the event loop freezes (e.g., due to seccomp
killing a thread -- see 2.2), the watchdog fires and systemd restarts the
service.

```rust
// Tick the watchdog inside the main event loop
loop {
    tokio::select! {
        msg = ipc_rx.recv() => { handle_message(msg).await; }
        _ = watchdog_interval.tick() => {
            sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog])?;
        }
    }
}
```

**Place the watchdog tick in the event loop, not in a separate thread.** A
separate thread will keep ticking even when the event loop is frozen, defeating
the purpose.

**`TimeoutStopSec=`:**
How long systemd waits after sending SIGTERM before sending SIGKILL. Set this
to give your daemon time for graceful shutdown (flush databases, close
connections), but not so long that a hung daemon blocks restarts.

```ini
TimeoutStopSec=10s
```

### 4.4 Common pitfalls

**`RuntimeDirectory=` with `ProtectSystem=strict`:**
For user services, `RuntimeDirectory=myapp` creates `/run/user/UID/myapp`
inside the mount namespace. This directory is only visible to *that specific
service instance*. Other services in the same user session cannot see it.
If you need a shared runtime directory, use `ReadWritePaths=` with a
directory created by tmpfiles.d.

**`PrivateNetwork=yes` and Unix sockets:**
`PrivateNetwork=yes` creates a new network namespace with only a loopback
interface. TCP/UDP connections to external hosts are blocked. However, **Unix
domain sockets on the filesystem are unaffected** -- they are filesystem
operations, not network operations. This means IPC over Unix sockets works
fine with `PrivateNetwork=yes`, which is usually what you want for a daemon
that only communicates via local IPC.

**`sd_notify` silently succeeds when `NOTIFY_SOCKET` is unset:**
When running outside systemd (e.g., in a terminal for debugging),
`$NOTIFY_SOCKET` is not set. The `sd_notify()` call returns success without
doing anything. Add diagnostic logging so you know whether notifications are
actually being delivered:

```rust
if std::env::var("NOTIFY_SOCKET").is_ok() {
    tracing::info!("systemd notify socket available");
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;
} else {
    tracing::warn!("NOTIFY_SOCKET not set -- sd_notify disabled");
}
```

---

## 5. Debugging Toolkit

### 5.1 strace

strace is the single most valuable tool for debugging seccomp and Landlock
issues.

**Trace all threads of a running process:**

```bash
strace -f -o /tmp/trace.log -p $(pidof my-daemon)
```

**Filter out noisy syscalls:**

```bash
strace -f -e trace='!read,write,close,epoll_wait,futex,nanosleep' \
  -o /tmp/trace.log -p $(pidof my-daemon)
```

**Find seccomp kills:**

```bash
grep "killed by SIGSYS" /tmp/trace.log
```

The last syscall logged for that thread (immediately before the
`+++ killed by SIGSYS +++` line) is the blocked syscall. Example:

```
[pid 12345] ftruncate(7, 0)     = ?
[pid 12345] +++ killed by SIGSYS (core dumped) +++
```

This tells you `ftruncate` is missing from the allowlist.

**Trace all daemons simultaneously** for comprehensive coverage:

```bash
for pid in $(pgrep -f 'my-daemon'); do
    strace -f -o /tmp/trace-${pid}.log -p $pid &
done
# Exercise all code paths, then kill strace processes
```

### 5.2 journalctl

**View logs for a user service:**

```bash
journalctl --user -u my-daemon.service --no-pager -o short-precise
```

**Key exit status codes:**

| Status | Meaning | Likely Cause |
|---|---|---|
| **226/NAMESPACE** | Mount namespace setup failed | `ReadWritePaths` directory does not exist |
| **31/SYS** | Killed by signal 31 (SIGSYS) | seccomp blocked a syscall |
| **6/ABRT** | Aborted | Watchdog timeout, assertion failure, or panic |
| **-1/WATCHDOG** | Watchdog timeout | Event loop frozen (see 2.2) |

**Watch in real time:**

```bash
journalctl --user -u my-daemon.service -f -o short-precise
```

### 5.3 systemctl

**Check service status:**

```bash
systemctl --user status my-daemon.service
```

Look for: `Active:` (running/failed/inactive), `Main PID:`, exit code/status.

**Clear failed state:**
After a service fails, systemd remembers the failure. You must reset it before
restarting:

```bash
systemctl --user reset-failed my-daemon.service
systemctl --user start my-daemon.service
```

**Recreate tmpfiles.d directories:**

```bash
systemd-tmpfiles --user --create
```

This is idempotent -- safe to run anytime.

### 5.4 Diagnostic patterns

**"No such file or directory" + status=226:**
The service's `ReadWritePaths` or `ReadOnlyPaths` references a directory that
does not exist on the host filesystem. systemd cannot create the bind mount
into the namespace.

Fix: Ensure tmpfiles.d rules create all required directories. Run
`systemd-tmpfiles --user --create` and retry.

**Watchdog timeout with no error logs:**
The event loop is frozen. The most common cause is seccomp `KILL_THREAD`
silently destroying a thread that `tokio::select!` is waiting on (see 2.2).

Debug: Attach strace to the process, exercise the code path that triggers the
freeze, look for `SIGSYS` kills. Add timeout wrappers to `spawn_blocking`
calls to regain visibility.

**"database is locked" after timeout:**
A `spawn_blocking` thread was killed by seccomp while holding an `fcntl`
advisory lock on a SQLite file. The lock was not released because the thread
died without running destructors. The file descriptor may still be open (held
by the process, not the thread).

Fix: Add the missing syscall to the allowlist. If the database is stuck,
restart the process (the lock is released when the fd is closed on process
exit). For robustness, set `PRAGMA busy_timeout` so SQLite retries instead of
immediately returning `SQLITE_BUSY`.

**Silent timeout from CLI (e.g., 5 seconds, no response):**
The daemon received the IPC message but froze during processing. The CLI's
request timeout fires. This is the user-visible symptom of the event loop
freeze described above.

Debug: Check if the daemon process is still running (`ps aux | grep daemon`).
If it is running but not responding, it is frozen. Attach strace.

---

## 6. Defense-in-Depth Architecture

The two-tier model:

```
                    +--------------------------+
                    |     systemd (outer)      |
                    |  Mount namespaces         |
                    |  Resource limits          |
                    |  (LimitNOFILE, MemoryMax) |
                    |  Watchdog lifecycle       |
                    |  ProtectSystem,           |
                    |  ProtectHome              |
                    +-----------+--------------+
                                |
                    +-----------v--------------+
                    |   Application (inner)    |
                    |  Landlock filesystem ACL  |
                    |  seccomp-bpf syscall      |
                    |  filter                   |
                    |  setrlimit               |
                    |  (NOFILE, MEMLOCK)        |
                    |  Directory bootstrap      |
                    +--------------------------+
```

**systemd owns:**

- Process lifecycle (start, stop, restart, watchdog)
- Outer filesystem isolation (mount namespaces)
- Resource limits that survive application bugs (`MemoryMax`, `TasksMax`)
- Compliance posture (auditors can inspect unit files)

**The application owns:**

- Inner filesystem isolation (Landlock -- more granular than mount namespaces)
- Syscall filtering (seccomp -- systemd's `SystemCallFilter` is a convenience
  wrapper, but application-level gives more control)
- Resource self-limits (`setrlimit` -- defense against fd leaks, memory leaks)
- Directory bootstrapping (portable across platforms)

**Both layers are required:**

- systemd provides the compliance and lifecycle layer. Auditors and
  distribution packagers can review unit files without reading application code.
- Landlock and seccomp provide the defense-in-depth layer. They protect against
  vulnerabilities within the application itself.
- The application must work on non-systemd platforms (containers, macOS,
  embedded Linux). Landlock and seccomp are Linux-specific but do not require
  systemd. The application's bootstrap code handles the portable case.

---

## 7. Checklist: Hardening a New Daemon

Use this checklist when adding security hardening to a new daemon. Each item
addresses a specific failure mode described in this guide.

### systemd unit file

- [ ] `Type=notify` with `sd_notify("READY=1")` in application code
- [ ] `WatchdogSec=30s` (adjust to your heartbeat interval)
- [ ] `TimeoutStopSec=10s` (enough for graceful shutdown)
- [ ] `Restart=on-failure`, `RestartSec=2s`
- [ ] `ProtectSystem=strict`
- [ ] `ProtectHome=read-only`
- [ ] `ReadWritePaths=` for every writable directory
- [ ] `NoNewPrivileges=yes`
- [ ] `PrivateTmp=yes`
- [ ] tmpfiles.d rules for every directory in `ReadWritePaths`

### Application bootstrap

- [ ] `bootstrap_dirs()` creates all required directories (portable fallback)
- [ ] `setrlimit(RLIMIT_NOFILE, ...)` to cap file descriptors
- [ ] `setrlimit(RLIMIT_MEMLOCK, ...)` if using mlock for secrets

### Landlock

- [ ] Grant `ReadWrite` to runtime directory (`$XDG_RUNTIME_DIR/myapp`)
- [ ] Grant `ReadOnly` to config directory (`$XDG_CONFIG_HOME/myapp`)
- [ ] Grant `ReadWrite` to data directory (`$XDG_DATA_HOME/myapp`)
- [ ] Canonicalize all paths to resolve symlinks (NixOS/Guix)
- [ ] Grant `ReadOnly` to `/dev/urandom` if using crypto
- [ ] Check `$NOTIFY_SOCKET` -- if filesystem path, grant write access
- [ ] Test on NixOS or with symlinked configs

### seccomp allowlist

- [ ] Trace with `strace -f` under ALL code paths
- [ ] Include `fsync` AND `fdatasync` (SQLite uses both)
- [ ] Include `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch` if
      using file watchers
- [ ] Include `readlink`, `readlinkat` if paths may be symlinks
- [ ] Include `getrandom` for crypto operations
- [ ] Include `clone3` if targeting glibc >= 2.34
- [ ] Use `SECCOMP_RET_KILL_PROCESS` (not `KILL_THREAD`) in production
- [ ] Use `SECCOMP_FILTER_FLAG_TSYNC` for multi-threaded programs

### Defensive timeouts

- [ ] Every `spawn_blocking` wrapped with `tokio::time::timeout`
- [ ] Timeout duration is shorter than `WatchdogSec / 2`
- [ ] Timeout fires a log message identifying the blocked operation

### SIGSYS handler

- [ ] Installed *before* seccomp filter is applied
- [ ] Uses only async-signal-safe functions (raw `write` to fd 2)
- [ ] Logs the blocked syscall number
- [ ] Uses `SA_RESETHAND` to avoid infinite handler loops

### Watchdog

- [ ] Ticks inside the main event loop (`tokio::select!` branch)
- [ ] Does NOT tick in a separate thread
- [ ] Interval is `WatchdogSec / 2` or less

### Testing

- [ ] Wipe all state directories and recreate from scratch
- [ ] Start all daemons -- verify no 226/NAMESPACE errors
- [ ] Exercise all features under normal operation
- [ ] Trigger error paths (bad input, network down, disk full)
- [ ] Verify watchdog ticks appear in journal
- [ ] Verify graceful shutdown completes within `TimeoutStopSec`
- [ ] Run full test cycle twice (catches state leaks from first run)

---

## References

- [seccomp(2) man page](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [landlock-rs crate](https://docs.rs/landlock/)
- [systemd.exec(5) -- sandboxing directives](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [systemd-tmpfiles(8)](https://www.freedesktop.org/software/systemd/man/systemd-tmpfiles.html)
- [strace(1)](https://man7.org/linux/man-pages/man1/strace.1.html)
- [Kernel BPF documentation](https://docs.kernel.org/bpf/)
