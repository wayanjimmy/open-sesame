# Adversarial Security Review: Open Sesame v2 Protocol Hardening

**Reviewer:** Automated Principal Staff Security Engineering Analysis
**Scope:** Deliverables D-001 through D-008 from the Security Protocol Omnibus
**Commit:** Post-implementation (all phases complete)
**Date:** 2026-02-27

---

## Executive Summary

The implementation addresses every P0 vulnerability identified in the omnibus specification. The active profile authorization gate (D-001), confirmed RPC mechanism (D-002), lock state consistency (D-003), unlock hardening (D-004), vault key zeroization (D-005), state reconciliation (D-006), typed denial responses (D-007), and test suite (D-008) are all present and structurally correct.

However, adversarial analysis reveals **3 P0 findings**, **5 P1 findings**, **4 P2 findings**, and **3 P3 findings** that were either introduced during implementation, represent incomplete coverage of spec requirements, or constitute attack surface the omnibus did not anticipate.

---

## Severity Classification

| Severity | Definition | Count |
|----------|-----------|-------|
| **P0 Critical** | Exploitable security bypass or data exposure | 3 |
| **P1 High** | Security degradation under adversarial conditions | 5 |
| **P2 Medium** | Defense-in-depth gap or incomplete hardening | 4 |
| **P3 Low** | Best-practice deviation or informational | 3 |

---

## Detailed Findings

### P0-001: `pragma_rekey_clear()` is synchronous but called in async context without blocking guard

**File:** `core-secrets/src/sqlcipher.rs:173-192`
**File:** `daemon-secrets/src/main.rs:134,409,508`

The spec (Section 4.8) specified `pub async fn pragma_rekey_clear(&self)` using `self.conn.lock().await` (tokio async Mutex). The implementation uses `std::sync::Mutex` (line 24 of sqlcipher.rs: `conn: Mutex<Connection>`) and the method is synchronous:

```rust
pub fn pragma_rekey_clear(&self) {
    match self.conn.lock() {
        Ok(conn) => { ... }
        Err(e) => { ... }
    }
}
```

This is called from async contexts in `daemon-secrets/src/main.rs` (lines 134, 409, 508). Holding a `std::sync::Mutex` across an `.await` point is a classic deadlock vector. While the current call sites don't actually `.await` while holding the lock (the method itself is sync and doesn't yield), the real problem is **`std::sync::Mutex::lock()` blocks the tokio worker thread**. If the Mutex is poisoned or contended (e.g., a panic in another thread holding it), this blocks the entire single-threaded tokio runtime, halting all IPC processing including security-critical lock/deactivation operations.

The `SecretsStore` trait methods (`get`, `set`, `delete`, `list_keys`) in `sqlcipher.rs` also use `self.conn.lock()` (std::sync::Mutex) inside `Box::pin(async move { ... })` blocks. If `pragma_rekey_clear()` is called concurrently with an in-flight secret operation, the std::sync::Mutex serializes correctly on a single thread, but a poisoned mutex (from a panic in encrypt/decrypt) would permanently block `pragma_rekey_clear()`, preventing key zeroization on lock/deactivate/shutdown.

**Impact:** Under adversarial conditions (crafted input causing panic in encrypt/decrypt path), the mutex poisons and all subsequent `pragma_rekey_clear()` calls log a warning and return without zeroizing. The SQLCipher C-level key buffer persists in memory indefinitely.

**Recommendation:** Either switch to `tokio::sync::Mutex` for the connection (spec's original design), or use `self.conn.lock().unwrap_or_else(|e| e.into_inner())` to recover from poisoned mutex for the zeroization path. Zeroization must not fail due to a poisoned mutex.

---

### P0-002: Confirmation channel shared across concurrent operations without serialization

**File:** `daemon-profile/src/main.rs:197` (channel creation)
**File:** `daemon-profile/src/main.rs:304-311` (watchdog reconciliation)
**File:** `daemon-profile/src/main.rs:611,638` (activation/deactivation)

The confirmation channel `(confirm_tx, confirm_rx)` is a single `mpsc::channel::<Vec<u8>>(16)` shared between:
1. `activation::activate()` / `activation::deactivate()` (called from ProfileActivate/ProfileDeactivate handlers)
2. `reconcile_secrets_state()` (called from watchdog every 30s)

These are all called from the same `tokio::select!` loop, so they cannot run truly concurrently on a single-threaded runtime. However, the watchdog tick fires on a timer. Consider this sequence:

1. CLI sends `ProfileActivate` at T=29.9s
2. `activation::activate()` registers confirmation for msg_id_A, sends to daemon-secrets, starts `timeout(5s, confirm_rx.recv())`
3. At T=30s, the 5s timeout has NOT expired, but the `activate()` future is suspended at the `.await` on `confirm_rx.recv()`
4. Because `tokio::select!` is cooperative, the watchdog tick arm cannot preempt a running arm

Actually, on closer analysis, since `activate()` is called from within a `select!` arm and holds `&mut confirm_rx`, the watchdog cannot simultaneously call `reconcile_secrets_state()` with the same `&mut confirm_rx`. Rust's borrow checker prevents this at compile time.

**Revised assessment:** This is actually safe due to exclusive borrow semantics. The `&mut confirm_rx` is exclusively borrowed by whichever operation is running. However, there is a subtler issue:

If `activation::activate()` times out (5s) and returns an error, and then the watchdog tick fires in the next `select!` iteration, the reconciliation's `confirm_rx.recv()` could receive a **stale response** from daemon-secrets that arrived after the activate timeout but before the `ConfirmationGuard` was dropped. The `ConfirmationGuard` drops when `confirmed_rpc()` returns, which deregisters the confirmation route. But if daemon-secrets' response arrives between the timeout firing and the guard dropping (a tiny window), it gets forwarded to `confirm_tx` and sits in the channel buffer. The next `confirm_rx.recv()` (from reconciliation) picks up this stale activate response instead of the reconciliation response.

The `confirmed_rpc()` function does verify `response.correlation_id != Some(msg_id)` (activation.rs:236), but `reconcile_secrets_state()` does NOT verify correlation_id (daemon-profile/src/main.rs:728-761). It decodes the frame and checks the payload type (`SecretsStateResponse`), which would not match a `ProfileActivateResponse`. So a stale activate response would fall through to the "unexpected response type" warning at line 757. The reconciliation would silently fail without correcting state.

**Impact:** After an activation timeout, the next watchdog reconciliation silently fails, leaving daemon-profile with potentially stale lock/active-profile state for another 30s until the next reconciliation attempt.

**Recommendation:** `reconcile_secrets_state()` should drain stale messages from `confirm_rx` before sending its own request, or verify `correlation_id` matches its own `msg_id`. Add a loop that drains `confirm_rx` with `try_recv()` before the reconciliation send.

---

### P0-003: Deactivation failure path does not trigger reconciliation

**File:** `daemon-profile/src/main.rs:648-655`
**Spec:** Section 3.3 ("If timeout -- IMMEDIATELY trigger state reconciliation")

The spec explicitly requires that deactivation timeout triggers IMMEDIATE reconciliation. The `deactivate()` function in `activation.rs:168-176` returns an error string on timeout. The caller in `daemon-profile/src/main.rs:648-655` handles this:

```rust
Err(e) => {
    tracing::error!(
        profile = %profile_name,
        error = %e,
        "profile deactivation failed"
    );
    Some(EventKind::ProfileDeactivateResponse { success: false })
}
```

There is **no call to `reconcile_secrets_state()`** on deactivation failure. The spec (Section 3.3, invariant) states: "Deactivation timeout triggers IMMEDIATE reconciliation, not deferred." The code assertion A-013 states: "`activation::deactivate()` timeout -> Triggers `reconcile_secrets_state()`."

After a deactivation timeout, daemon-secrets may have already deactivated the profile (the RPC succeeded server-side, the response just didn't arrive in time). daemon-profile still has the profile in `active_profiles`. The user sees `success: false` and may try to deactivate again, or worse, assume the profile is still active and continue operating. The reconciliation would fix this -- but it only runs on the next 30s watchdog tick, not immediately.

**Impact:** 30-second window where daemon-profile's active_profiles diverges from daemon-secrets after deactivation timeout. During this window, `StatusRequest` reports the profile as active when it may not be, and secret operations may fail with confusing "profile not active" errors from daemon-secrets while daemon-profile thinks it's active.

**Recommendation:** Add `reconcile_secrets_state()` call in the deactivation error path before returning the response. This matches the spec requirement exactly.

---

### P1-001: `check_secret_requester()` is advisory-only with no enforcement

**File:** `daemon-secrets/src/acl.rs:130-146`
**File:** `daemon-secrets/src/main.rs:560,657,739,802`

The `check_secret_requester()` function logs a warning for unexpected requesters but does not deny the request. It is called at step 3 of every secret RPC handler but has no return value and no enforcement:

```rust
pub(crate) fn check_secret_requester(requester: DaemonId, verified_name: Option<&str>) {
    if let Some(name) = verified_name {
        match name {
            "daemon-secrets" | "daemon-launcher" => {} // Expected requesters.
            other => {
                tracing::warn!(audit = "anomaly", ...);
            }
        }
    }
    // None = unregistered client. Not anomalous.
}
```

The omnibus (Section 3.6, step 3) describes this as "Anomaly detection on requester identity" which implies advisory. However, the spec also states "Assume advanced persistent threat for all security decisions" (Section 2.1). An APT-compromised daemon (e.g., `daemon-wm`) could issue unlimited `SecretGet` requests. The ACL check (step 5) may catch this if ACL policy is configured, but if no ACL policy exists (backward-compatible default), the compromised daemon has unrestricted access to all secrets in all active profiles.

**Impact:** A compromised daemon with no ACL restriction can exfiltrate all secrets from all active profiles. The anomaly log is the only detection, and it requires active log monitoring.

**Recommendation:** Consider making unexpected requester identity a configurable enforcement point (deny by default with an opt-out). At minimum, document this as accepted residual risk in the threat model.

---

### P1-002: Rate limiter state not cleared on lock

**File:** `daemon-secrets/src/main.rs:340` (rate_limiter initialization)
**File:** `daemon-secrets/src/main.rs:504-518` (lock handler)

`SecretRateLimiter` is created once at daemon startup (line 340) and never cleared. When the daemon locks and re-unlocks, the rate limiter retains state from the previous session. An attacker who exhausted a daemon's rate limit before lock retains the exhaustion after unlock, causing legitimate requests from that daemon to be denied.

More importantly, the rate limiter uses `governor::DefaultDirectRateLimiter` which stores timestamps. After a lock/unlock cycle, the stored timestamps are stale. The governor GCRA algorithm will correctly handle this (stale timestamps mean the bucket has refilled), so this is not a functional bug. However, the `HashMap<String, RateLimiter>` grows unboundedly across lock/unlock cycles if different daemon names connect. There is no eviction.

**Impact:** Memory growth proportional to unique daemon names across the daemon's lifetime. Not a direct security bypass but a resource exhaustion vector under sustained attack with spoofed daemon names (requires Noise IK compromise to create new verified names, so impact is limited by the transport security).

**Recommendation:** Clear `rate_limiter` on lock, or add LRU eviction to the limiter map.

---

### P1-003: `JitDelivery::resolve()` TOCTOU between cache read and store fetch

**File:** `core-secrets/src/jit.rs:43-71`

The `resolve()` method reads the cache under a `RwLock::read()`, then if cache miss or TTL expired, drops the read lock, fetches from the store, then acquires a write lock to insert:

```rust
{
    let cache = self.cache.read().await;
    if let Some(cached) = cache.get(key)
        && cached.fetched_at.elapsed() < self.ttl
    {
        return Ok(cached.value.clone());
    }
}
// <-- Gap: cache lock dropped, but profile might be deactivated here
let value = self.store.get(key).await?;
{
    let mut cache = self.cache.write().await;
    cache.insert(key.to_owned(), CachedSecret { ... });
}
```

Between dropping the read lock and acquiring the write lock, `flush()` could run (called from `deactivate_profile()`), clearing the cache. The `resolve()` would then re-populate the cache with a value fetched from the store -- but the store itself may have been closed by `deactivate_profile()` calling `pragma_rekey_clear()` and dropping the vault. The store fetch at line 56 would fail with an error from rusqlite (connection closed / key invalid), so this is not exploitable in practice. The error propagates up correctly.

However, there is a subtler issue: `flush()` clears the cache but does NOT prevent subsequent `resolve()` calls from re-populating it. If a `SecretGet` is in-flight during deactivation (accepted per spec Section 3.3), the in-flight request completes with the old vault, `resolve()` fetches from the still-open vault (cooperative scheduling means deactivation hasn't run yet), and the result is cached. Then deactivation runs, calls `flush()`, clears the cache, closes the vault. This is the accepted in-flight behavior. No actual bug here.

**Revised severity:** P3 (informational). The cooperative scheduling model makes this safe, but it should be documented that `JitDelivery` provides no atomicity guarantee between `resolve()` and `flush()`.

---

### P1-004: `name_to_conn` mapping vulnerable to name squatting

**File:** `core-ipc/src/server.rs:718-727`

```rust
if let EventKind::DaemonStarted { .. } = &msg.payload
    && let Some(ref name) = verified_name
{
    state.name_to_conn.write().await.insert(name.clone(), sender_conn_id);
}
```

The `name_to_conn` mapping is overwritten unconditionally when a `DaemonStarted` message arrives from a connection with a verified name. If two connections authenticate with the same public key (which the registry allows -- there is no uniqueness constraint on connections per pubkey), the second connection's `DaemonStarted` overwrites the first. This could be used by an attacker who compromises a daemon's private key to hijack the `send_to_named()` routing: connect with the stolen key, emit `DaemonStarted`, and intercept all confirmed RPCs intended for the real daemon.

The `ClearanceRegistry` tracks pubkeys, not connections. Multiple connections can authenticate with the same pubkey. The registry does check generation numbers (H-019), but a stolen key from the current generation would authenticate successfully.

**Impact:** If a daemon's Noise IK private key is compromised (requires filesystem access to `$XDG_RUNTIME_DIR/pds/keys/`), the attacker can hijack confirmed RPCs to that daemon. For `daemon-secrets`, this means intercepting activation/deactivation RPCs and returning forged responses.

**Recommendation:** The `name_to_conn` insert should either reject duplicates (keeping the first connection) or disconnect the old connection when a new one claims the same name. The Landlock sandbox on daemon-secrets (H-017) limits key file access, which is the primary mitigation.

---

### P1-005: Broadcast lock/unlock response sent AFTER correlated unicast response

**File:** `daemon-secrets/src/main.rs:887-907`

The lock/unlock broadcast to daemon-profile is sent AFTER the correlated unicast response to the CLI:

```rust
send_response(ctx.client, msg, event, ctx.daemon_id).await?;

if let Some(notify) = broadcast
    && let Err(e) = ctx.client.publish(notify, SecurityLevel::Internal).await
{
    tracing::error!(...);
}
```

If the daemon crashes between `send_response()` (line 897) and the broadcast (line 900), the CLI receives `LockResponse { success: true }` but daemon-profile never receives the broadcast. The user sees "locked" but daemon-profile still thinks it's unlocked.

The reconciliation watchdog (30s) corrects this, but there is a 30-second window where the UX lies about lock state. Under the APT threat model, an attacker who can trigger daemon crashes at precise moments could exploit this window.

**Impact:** Up to 30s of stale lock state in daemon-profile after a crash between unicast and broadcast. Mitigated by watchdog reconciliation but not eliminated.

**Recommendation:** Send the broadcast BEFORE the unicast response, or send both atomically. The CLI can tolerate slightly delayed responses; daemon-profile seeing stale state is the security risk.

---

### P2-001: `SqlCipherStore` uses `std::sync::Mutex` -- no `Drop` guarantees for `pragma_rekey_clear()`

**File:** `core-secrets/src/sqlcipher.rs:16,24`

`SqlCipherStore` has no `Drop` impl. If a `JitDelivery<SqlCipherStore>` is dropped without calling `pragma_rekey_clear()` first (e.g., due to a panic unwind in daemon-secrets), the SQLCipher C-level key buffer is never explicitly cleared. The spec acknowledges this (Section 4.8) but the implementation does not add any safety net.

The three explicit call sites (deactivate, lock, shutdown) all call `pragma_rekey_clear()`. But a panic in any handler between vault open and one of these call sites would skip zeroization. Rust's unwind safety means `Drop` would run, but there is no `Drop` impl.

**Recommendation:** Add a `Drop` impl for `SqlCipherStore` that calls `PRAGMA rekey = '';` as a best-effort safety net. The std::sync::Mutex can be locked in Drop (it's synchronous).

---

### P2-002: `UnlockResponse` broadcast does not clear daemon-profile's active_profiles

**File:** `daemon-profile/src/main.rs:670-673`

```rust
EventKind::UnlockResponse { success: true } => {
    *locked = false;
    tracing::info!("secrets daemon unlocked, lock state updated");
    None
}
```

The spec (Section 3.5, step 3b) states: "Clear active_profiles (fresh unlock = no profiles active)." The `UnlockResponse` handler sets `locked = false` but does NOT clear `active_profiles`. The spec rationale: after unlock, zero profiles are active -- the user must explicitly activate. If `active_profiles` is not cleared here, a stale set from a previous session could persist.

In practice, the `LockResponse` handler (line 676-681) does clear `active_profiles`, so if the normal lock->unlock sequence occurs, active_profiles is already empty from the lock step. But if daemon-secrets restarts while unlocked and re-broadcasts `UnlockResponse` without a preceding `LockResponse`, daemon-profile would retain stale active_profiles.

The daemon-secrets restart path (DaemonStarted handler, line 507-514) does clear active_profiles, so this specific scenario is covered. But the defense-in-depth principle says `UnlockResponse` should also clear the set.

**Impact:** Low -- covered by other paths. But violates spec Section 3.5 step 3b.

**Recommendation:** Add `active_profiles.clear()` to the `UnlockResponse` handler.

---

### P2-003: No validation of `PRAGMA rekey = ''` success semantics

**File:** `core-secrets/src/sqlcipher.rs:173-192`

The `pragma_rekey_clear()` method executes `PRAGMA rekey = '';` and logs a warning on failure, but does not verify that the operation actually cleared the key. `PRAGMA rekey` in SQLCipher changes the encryption key -- setting it to empty string may either:
1. Re-encrypt the database with an empty key (making it unencrypted)
2. Clear the internal key buffer without re-encrypting
3. Fail silently if the connection is in a bad state

The spec (DISC-006) flags this as requiring empirical verification: "Verify that rusqlite exposes PRAGMA rekey and that SQLCipher honors it for zeroization." There is no evidence this verification was performed. The database files on disk could be silently re-encrypted with empty string, making them accessible without any key.

**Impact:** If `PRAGMA rekey = ''` actually re-encrypts the database, all vault databases become unencrypted on disk after every lock/deactivate/shutdown. This would be catastrophic.

**Recommendation:** Empirically verify `PRAGMA rekey = ''` behavior with the specific SQLCipher version linked by rusqlite. If it re-encrypts, switch to a no-op key clear or use `sqlite3_rekey()` FFI with a null pointer. Add an integration test that verifies the database remains encrypted after `pragma_rekey_clear()`.

---

### P2-004: `SecretList` request broadcasts profile existence to all bus subscribers

**File:** `core-ipc/src/server.rs:776-791`

When a CLI sends `SecretList { profile: "work" }`, this is a new request (no correlation_id) and goes through the broadcast path in `route_frame()`. All connected daemons receive the request, revealing which profiles the user is accessing. While the response is routed unicast (via correlation_id), the request itself is broadcast.

Under the APT model, a compromised daemon observing bus traffic learns which profiles are active and when secrets are accessed, even if it cannot read the secret values.

**Impact:** Information leakage of profile access patterns to all bus subscribers. Mitigated by Noise IK encryption (all subscribers are authenticated), but a compromised daemon sees the traffic.

**Recommendation:** Consider routing secret requests via `send_to_named("daemon-secrets")` instead of broadcast, or document this as accepted given the authenticated bus model.

---

### P3-001: Hardcoded 16 MiB max frame size

**File:** `core-ipc/src/framing.rs` (MAX_FRAME_SIZE = 16 MiB)

A single secret value could theoretically be 16 MiB. With double encryption overhead (nonce + GCM tag at entry level, plus Noise chunking), this is a significant memory allocation. No per-value size limit is enforced at the `SecretsStore` level.

**Recommendation:** Add a max secret value size check in `SecretSet` handling.

---

### P3-002: `test_master_key()` in tests uses deterministic key derivation

**File:** `daemon-secrets/src/main.rs:1291-1297`

The test helper generates a deterministic "master key" with a simple byte pattern. This is fine for unit tests but the function is named ambiguously. Not a security issue, just hygiene.

---

### P3-003: `check_secret_access()` has O(n) scan for daemon key lookup

**File:** `daemon-secrets/src/acl.rs:61`

```rust
allowed_keys.iter().any(|k| k == key)
```

Linear scan over allowed keys. For large ACL lists, this is a performance concern. Not security-impacting.

---

## Deliverable Compliance Matrix

| Deliverable | Status | Evidence | Gaps |
|-------------|--------|----------|------|
| **D-001: Active Profile Authorization** | PASS | `active_profiles: HashSet<TrustProfileName>` at `daemon-secrets/src/main.rs:81`; `vault_for()` gates at line 94; all 4 RPC handlers check at step 2; lock clears at line 506; unlock initializes empty at line 985 | None |
| **D-002: Confirmed RPC** | PASS | `register_confirmation()` at `server.rs`; `send_to_named()` with `name_to_conn`; `activation.rs` uses `confirmed_rpc()` for activate (line 76), deactivate (line 151), rollback (lines 295,306); `ConfirmationGuard` RAII cleanup | P0-003: deactivation timeout does not trigger immediate reconciliation |
| **D-003: Lock State Consistency** | PASS with gaps | daemon-profile clears active_profiles on LockResponse (line 678); resets on daemon-secrets restart (line 507-514); broadcast failure logged at error (line 902-906) | P2-002: UnlockResponse does not clear active_profiles; P1-005: broadcast after unicast ordering |
| **D-004: Unlock Hardening** | PASS | `UnlockRejected` returned at `daemon-secrets/src/main.rs:482-486`; CLI handles at `init.rs:226-228`; active_profiles empty after unlock (line 985-986) | None |
| **D-005: Vault Key Zeroization** | PASS with gaps | `pragma_rekey_clear()` at `sqlcipher.rs:173-192`; called from deactivate (line 134), lock (line 508), shutdown (line 409) | P0-001: std::sync::Mutex poisoning; P2-001: no Drop impl safety net; P2-003: PRAGMA rekey semantics unverified |
| **D-006: State Reconciliation** | PASS | `SecretsStateRequest/Response` in core-types; handler at `daemon-secrets/src/main.rs:872-881`; `reconcile_secrets_state()` at `daemon-profile/src/main.rs:691-778`; watchdog trigger every 30s (line 303); fail-closed on timeout (line 771-776); fail-closed on unreachable (line 720-722) | P0-002: stale confirmation channel messages; P0-003: missing immediate reconciliation on deactivation timeout |
| **D-007: Typed Denial Responses** | PASS | `SecretDenialReason` enum in core-types; `denial: Option<SecretDenialReason>` on all 4 response types; CLI `format_denial_reason()` at `open-sesame/src/main.rs:1374-1384` | None |
| **D-008: Test Suite** | PASS | Tier 1: unit tests in `daemon-secrets/src/main.rs` (A-001 through A-023 coverage); integration tests in `core-ipc/tests/socket_integration.rs`; ACL tests (T-ACL-001 through T-ACL-015); rate limit tests (rate_001 through rate_005) | No Tier 2 shell script found (tests/protocol_validation.sh not verified) |

---

## Test Coverage Assessment

### Strengths
- **ACL module:** 15 tests covering all 8 branches of `check_secret_access()` and 7 branches of `check_secret_list_access()`. Security invariants documented in test comments.
- **Rate limiter:** 5 tests covering burst allowance, exhaustion, cross-daemon independence, anonymous isolation, and shared anonymous bucket.
- **IPC integration:** 10 tests including Noise handshake rejection, bystander isolation (M11 unicast), clearance escalation blocking, sender identity change blocking, and verified_sender_name stamping.
- **UnlockedState:** 8 unit tests covering vault_for rejection, activation, deactivation idempotency, reactivation, active_profiles semantics, and lock clearing.

### Gaps
- **No test for `pragma_rekey_clear()`:** No test verifies that calling `pragma_rekey_clear()` actually clears the key or that the database remains encrypted afterward.
- **No test for confirmation channel stale message handling:** The P0-002 scenario (stale response in channel buffer) has no test coverage.
- **No test for concurrent deactivation + secret access:** The in-flight request behavior documented in spec Section 3.3 is accepted but untested.
- **No test for reconciliation timeout fail-closed:** The `reconcile_secrets_state()` timeout path (line 771-776) is untested.
- **No negative test for `check_secret_requester()`:** The anomaly detection logging is untested.

---

## Concurrency Analysis

The daemon-secrets event loop is single-threaded (`#[tokio::main]` defaults to current-thread runtime unless configured otherwise). This provides cooperative scheduling guarantees:
- In-flight `SecretGet` completes before `ProfileDeactivate` runs (accepted behavior)
- `vault_for()` + `resolve()` is not preempted by `deactivate_profile()`
- Lock check at step 1 runs before any timing-observable operations (rate limit, ACL, vault I/O)

The daemon-profile event loop is also single-threaded. The `tokio::select!` arms are mutually exclusive -- an in-progress `activate()` blocks the watchdog reconciliation arm.

**Risk:** If either daemon is configured with a multi-threaded runtime (`#[tokio::main(flavor = "multi_thread")]`), the cooperative scheduling assumptions break. The `std::sync::Mutex` on `SqlCipherStore.conn` prevents data races on the connection, but `active_profiles: HashSet` in `UnlockedState` is accessed via `&mut self` (exclusive borrow), which is enforced by Rust's ownership model, not runtime synchronization. The `UnlockedState` is stored as `Option<UnlockedState>` (line 339) and accessed as `ctx.unlocked_state` (line 361), which is `&mut Option<UnlockedState>` -- exclusive access guaranteed by the single `&mut MessageContext`.

**Verdict:** Safe under current single-threaded runtime. Would require significant refactoring (Arc<RwLock<UnlockedState>>) for multi-threaded safety.

---

## Wire Format Security Analysis

### Noise IK Transport
- Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s` -- correct, provides mutual authentication and forward secrecy
- UCred prologue binding: PID + UID bound into Noise prologue (`noise.rs`) -- prevents relay attacks
- Chunked transport for >65519 byte payloads: chunk count header prevents truncation
- Handshake timeout (5s): prevents slow-handshake DoS
- ZeroizingKeypair: private key zeroized on drop

### Message Format
- wire_version=2 with postcard serialization
- `verified_sender_name` stamped by server (not self-declared)
- Re-encoding after stamping (line 735) adds serialization overhead but ensures downstream receivers see the verified identity
- DaemonId binding on first message prevents mid-session identity change

### Concerns
- Postcard serialization: no schema evolution mechanism. Wire version 2 is fixed. Adding fields requires wire version bump.
- No message authentication at the application layer (relies entirely on Noise transport). If Noise is ever bypassed (e.g., debug mode), all messages are unauthenticated.
- `SensitiveBytes` in `EventKind::SecretGetResponse` traverses postcard serialization in cleartext within the Noise tunnel. The `ipc-field-encryption` feature is disabled by default.

---

## Recommendations (Priority Order)

1. **P0-001:** Fix `pragma_rekey_clear()` mutex poisoning recovery. Use `unwrap_or_else(|e| e.into_inner())` for the zeroization path. This is a one-line fix.

2. **P0-002:** Add `confirm_rx` draining in `reconcile_secrets_state()` before sending the reconciliation request:
   ```rust
   while confirm_rx.try_recv().is_ok() {} // Drain stale messages
   ```

3. **P0-003:** Add `reconcile_secrets_state()` call in the deactivation error handler at `daemon-profile/src/main.rs:648-655`.

4. **P2-003:** Empirically verify `PRAGMA rekey = ''` behavior. Write an integration test that opens a SQLCipher database, calls `pragma_rekey_clear()`, closes and reopens the database, and verifies the original key is still required.

5. **P2-001:** Add `Drop` impl to `SqlCipherStore` as safety net for panic unwind.

6. **P2-002:** Add `active_profiles.clear()` to the `UnlockResponse` handler in daemon-profile.

7. **P1-005:** Reorder broadcast before unicast in the lock/unlock response path.
