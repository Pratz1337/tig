//! HTTP remote and the dumb `tig-server`. See DESIGN.md "Collaboration", rules 6 and 7.
//!
//! The server stores bytes. It checks object hashes, pack ids, and that a
//! writer is the owner or a current member. It does not decrypt.

mod auth;
mod client;
mod limits;
mod mem;
mod server;
mod wire;

pub use client::HttpRemote;
pub use mem::MemRemote;
pub use server::{init_server_dir, read_server_owner, serve, Server, TlsConfig};

#[cfg(test)]
mod tests;
