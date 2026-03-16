//! systemd integration helpers.

/// Notify systemd that the daemon is ready (Type=notify).
///
/// `unset_environment` is false to preserve NOTIFY_SOCKET for
/// subsequent watchdog keepalive pings.
pub fn notify_ready() {
    match std::env::var("NOTIFY_SOCKET") {
        Ok(val) => {
            tracing::info!(notify_socket = %val, "sd_notify: NOTIFY_SOCKET present, sending READY=1")
        }
        Err(_) => tracing::warn!("sd_notify: NOTIFY_SOCKET not set — notify will be a no-op"),
    }
    match sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        Ok(()) => tracing::info!("sd_notify: READY=1 sent successfully"),
        Err(e) => tracing::error!(error = %e, "sd_notify: failed to send READY=1"),
    }
}

/// Send a watchdog keepalive to systemd.
pub fn notify_watchdog() {
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
        tracing::warn!(error = %e, "sd_notify: watchdog ping failed");
    }
}

/// Update the daemon's status string visible in `systemctl status`.
pub fn notify_status(status: &str) {
    sd_notify::notify(false, &[sd_notify::NotifyState::Status(status)]).ok();
}
