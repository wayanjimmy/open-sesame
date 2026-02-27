//! IPC bus protocol, postcard framing, and BusServer/BusClient for PDS.
//!
//! The central nervous system of the Programmable Desktop Suite.
//! All inter-daemon communication uses postcard-encoded frames over Unix domain sockets.
//!
//! Wire format: `[4-byte BE length][postcard(Message<EventKind>)]`
#![forbid(unsafe_code)]

mod message;
mod framing;
pub mod noise;
pub mod registry;
mod transport;
mod server;
mod client;

pub use message::{Message, WIRE_VERSION};
pub use framing::{encode_frame, decode_frame};
pub use noise::{NoiseTransport, ZeroizingKeypair, generate_keypair};
pub use registry::ClearanceRegistry;
pub use transport::{PeerCredentials, extract_ucred, local_credentials, socket_path};
pub use server::{BusServer, SubscriptionFilter};
pub use client::BusClient;
