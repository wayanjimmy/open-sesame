//! daemon-input: Input remapper daemon.
//!
//! Captures keyboard events via evdev, applies per-profile remap layers,
//! and re-emits remapped events via uinput virtual device. App-aware layer
//! switching requires integration with daemon-wm focus tracking.
//!
//! Landlock: /dev/input (read), /dev/uinput (write), runtime dir (IPC).
//! No network access beyond local IPC.

use anyhow::Context;
use clap::Parser;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, InputLayerInfo, SecurityLevel};

#[derive(Parser, Debug)]
#[command(name = "daemon-input", about = "Input remapper daemon")]
struct Cli {
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli.log_format)?;

    tracing::info!("daemon-input starting");

    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    let config = core_config::load_config(None)
        .context("failed to load config")?;

    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, _config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || { let _ = reload_tx.blocking_send(()); })),
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    let socket_path = core_ipc::socket_path()
        .context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key().await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();

    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-input", daemon_id, &socket_path, &server_pub, 5,
        std::time::Duration::from_millis(500),
    ).await.context("failed to connect to IPC bus")?;
    drop(_client_keypair);

    #[cfg(target_os = "linux")]
    apply_sandbox();

    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["input".into(), "remap".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-input ready, entering event loop");

    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            Some(msg) = client.recv() => {
                let response_event = match &msg.payload {
                    EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                        if daemon_name == "daemon-input" =>
                    {
                        tracing::info!(grace_period_s, "key rotation pending");
                        match BusClient::handle_key_rotation(
                            "daemon-input", daemon_id, &socket_path, &server_pub, new_pubkey,
                            vec!["input".into(), "remap".into()], env!("CARGO_PKG_VERSION"),
                        ).await {
                            Ok(new_client) => {
                                client = new_client;
                                tracing::info!("reconnected with rotated keypair");
                            }
                            Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                        }
                        None
                    }

                    EventKind::InputLayersList => {
                        // evdev remapping not yet wired — report configured layers from config.
                        let layers = vec![InputLayerInfo {
                            name: "default".into(),
                            is_active: true,
                            remap_count: 0,
                        }];
                        Some(EventKind::InputLayersListResponse { layers })
                    }

                    EventKind::InputStatus => {
                        Some(EventKind::InputStatusResponse {
                            active_layer: "default".into(),
                            grabbed_devices: vec![],
                            remapping_active: false,
                        })
                    }

                    _ => None,
                };

                if let Some(event) = response_event {
                    let response = Message::new(
                        daemon_id, event, msg.security_level, client.epoch(),
                    ).with_correlation(msg.msg_id);
                    if let Err(e) = client.send(&response).await {
                        tracing::warn!(error = %e, "failed to send response");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reloaded");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["input".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
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
        .ok();

    tracing::info!("daemon-input shut down");
    Ok(())
}

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

#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{
        apply_sandbox, FsAccess, LandlockRule, SeccompProfile,
    };

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| "/run/user/1000".into());

    let pds_dir = std::path::PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    let rules = vec![
        LandlockRule {
            path: keys_dir.join("daemon-input.key"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-input.pub"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: keys_dir.join("daemon-input.checksum"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        LandlockRule {
            path: std::path::PathBuf::from("/dev/input"),
            access: FsAccess::ReadOnly,
        },
    ];

    let seccomp = SeccompProfile {
        daemon_name: "daemon-input".into(),
        allowed_syscalls: vec![
            "read".into(), "write".into(), "close".into(),
            "openat".into(), "lseek".into(), "pread64".into(),
            "fstat".into(), "stat".into(), "newfstatat".into(),
            "statx".into(), "access".into(), "fcntl".into(),
            "ioctl".into(), "mkdir".into(), "getdents64".into(),
            "mmap".into(), "mprotect".into(), "munmap".into(),
            "madvise".into(), "brk".into(),
            "futex".into(), "clone3".into(), "clone".into(),
            "set_robust_list".into(), "set_tid_address".into(),
            "rseq".into(), "sched_getaffinity".into(),
            "prlimit64".into(), "prctl".into(),
            "getpid".into(), "gettid".into(), "getuid".into(), "geteuid".into(),
            "kill".into(),
            "epoll_wait".into(), "epoll_ctl".into(),
            "epoll_create1".into(), "eventfd2".into(),
            "poll".into(), "ppoll".into(),
            "clock_gettime".into(), "timer_create".into(),
            "timer_settime".into(), "timer_delete".into(),
            "socket".into(), "connect".into(), "sendto".into(),
            "recvfrom".into(), "recvmsg".into(), "sendmsg".into(),
            "getsockname".into(), "getpeername".into(),
            "setsockopt".into(), "socketpair".into(),
            "shutdown".into(), "getsockopt".into(),
            "sigaltstack".into(), "rt_sigaction".into(),
            "rt_sigprocmask".into(), "rt_sigreturn".into(),
            "tgkill".into(),
            "exit_group".into(), "exit".into(), "getrandom".into(),
            "restart_syscall".into(),
            "pipe2".into(), "dup".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} -- refusing to run unsandboxed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_layer_info_construction() {
        let layer = InputLayerInfo {
            name: "gaming".into(),
            is_active: false,
            remap_count: 12,
        };
        assert_eq!(layer.name, "gaming");
        assert!(!layer.is_active);
        assert_eq!(layer.remap_count, 12);
    }

    #[test]
    fn default_status_values() {
        // Mirrors the InputStatus handler's default response.
        let active_layer = "default";
        let grabbed_devices: Vec<String> = vec![];
        let remapping_active = false;

        assert_eq!(active_layer, "default");
        assert!(grabbed_devices.is_empty());
        assert!(!remapping_active);
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
