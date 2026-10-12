//! Dumb HTTPS (or loopback HTTP) storage for a tig remote.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tig_private::keys::PublicIdentity;
use tig_private::remote::{DirRemote, Remote};
use tig_remote_http::{init_server_dir, read_server_owner, serve, TlsConfig};

#[derive(Parser)]
#[command(name = "tig-server", about = "Dumb storage for a tig remote")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a remote directory and record its owner.
    Init {
        dir: PathBuf,
        /// 128 hex characters: X25519 public key then Ed25519 public key.
        #[arg(long)]
        owner: String,
    },
    /// Serve a remote directory.
    Serve {
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8470")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Init { dir, owner } => match run_init(&dir, &owner) {
            Ok(id) => {
                println!("{}", hex::encode(id));
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("tig-server init: {error}");
                ExitCode::from(1)
            }
        },
        Command::Serve {
            dir,
            listen,
            tls_cert,
            tls_key,
        } => match run_serve(&dir, listen, tls_cert, tls_key) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tig-server serve: {error}");
                ExitCode::from(1)
            }
        },
    }
}

fn run_init(dir: &std::path::Path, owner_hex: &str) -> Result<[u8; 16], String> {
    let owner = parse_owner(owner_hex)?;
    init_server_dir(dir, &owner).map_err(|e| e.to_string())
}

fn run_serve(
    dir: &std::path::Path,
    listen: std::net::SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<(), String> {
    let owner = read_server_owner(dir).map_err(|e| e.to_string())?;
    let remote = DirRemote::open(dir).map_err(|e| e.to_string())?;
    let tls = match (tls_cert, tls_key) {
        (None, None) => None,
        (Some(cert), Some(key)) => Some(TlsConfig {
            cert_pem: std::fs::read(cert).map_err(|e| e.to_string())?,
            key_pem: std::fs::read(key).map_err(|e| e.to_string())?,
        }),
        _ => return Err("pass both --tls-cert and --tls-key, or neither".into()),
    };
    let server = serve(Arc::new(remote) as Arc<dyn Remote>, owner, listen, tls)
        .map_err(|e| e.to_string())?;
    eprintln!("tig-server listening on {}", server.local_addr());
    // The accept thread runs until the process is killed. Parking keeps the
    // listener, and the files, alive.
    loop {
        std::thread::park();
    }
}

fn parse_owner(hex_text: &str) -> Result<PublicIdentity, String> {
    let hex_text = hex_text.trim();
    if hex_text.len() != 128 {
        return Err("owner must be 128 hex characters (encryption key then signing key)".into());
    }
    let raw = hex::decode(hex_text).map_err(|_| "owner is not hex".to_string())?;
    let mut encryption = [0u8; 32];
    let mut signing = [0u8; 32];
    encryption.copy_from_slice(&raw[..32]);
    signing.copy_from_slice(&raw[32..]);
    Ok(PublicIdentity {
        encryption,
        signing,
    })
}
