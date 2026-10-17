//! `tig identity`

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroizing;

mod protection;

use tig_private::keys::Identity;

use super::settings;
use super::{CliError, Result};
use crate::ui;

pub(super) fn run(show: bool) -> Result<()> {
    let path = identity_path()?;
    if show {
        if !path.try_exists()? {
            return Err(CliError::msg(
                "no identity yet; run tig identity to create one",
            ));
        }
        print_identity(&read_identity(&path)?);
        return Ok(());
    }
    print_identity(&load_or_create()?);
    Ok(())
}

/// Loads the identity file, creating it on first use. Never overwrites.
pub(super) fn load_or_create() -> Result<Identity> {
    let path = identity_path()?;
    if path.try_exists()? {
        return read_identity(&path);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let identity = Identity::generate()?;
    let bytes = protection::seal(&identity)?;
    let created = super::disk::write_new(&path, &bytes[..], true)?;
    if created {
        Ok(identity)
    } else {
        read_identity(&path)
    }
}

/// The identity when the file already exists. Missing is `None`; malformed
/// or locked envelopes are errors. Fetch uses this so an outsider needs no identity.
pub(super) fn load_if_present() -> Result<Option<Identity>> {
    let path = identity_path()?;
    if path.try_exists()? {
        Ok(Some(read_identity(&path)?))
    } else {
        Ok(None)
    }
}

fn print_identity(identity: &Identity) {
    let public = identity.public();
    println!("{}", ui::identity_token(&public));
    println!("fingerprint: {}", public.fingerprint());
}

fn read_identity(path: &std::path::Path) -> Result<Identity> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path).and_then(|file| file.take(16 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|err| CliError::msg(format!("cannot read {}: {err}", ui::show_path(path))))?;
    if bytes.len() > 16 * 1024 {
        return Err(CliError::msg("protected identity file is too large"));
    }
    if bytes.len() == 64 && !bytes.starts_with(b"TIGI") {
        let mut stored = [0u8; 64];
        stored.copy_from_slice(&bytes);
        let identity = Identity::from_bytes(stored);
        let protected = protection::seal(&identity)?;
        super::disk::write_replace(path, &protected, true)?;
        return Ok(identity);
    }
    protection::open(&bytes)
}

fn identity_path() -> Result<PathBuf> {
    if let Some(path) = settings::env_nonempty("TIG_IDENTITY_FILE")? {
        return Ok(PathBuf::from(path));
    }
    let home = settings::home_dir().ok_or_else(|| CliError::msg("HOME is not set"))?;
    Ok(home.join(".tig").join("identity"))
}
