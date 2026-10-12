//! Atomic file writes for identity and remote config.
//!
//! A unique temp file is created with `create_new` in the destination
//! directory. Secret files are mode 0600 on Unix before the bytes are linked
//! into place. `write_new` never replaces an existing file: it hard-links the
//! temp onto the destination, which fails if the name is taken.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{CliError, Result};
use crate::ui;

pub(super) fn write_new(dest: &Path, bytes: &[u8], secret: bool) -> Result<bool> {
    write_atomic(dest, bytes, secret, false)
}

pub(super) fn write_replace(dest: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    write_atomic(dest, bytes, secret, true).map(|_| ())
}

fn write_atomic(dest: &Path, bytes: &[u8], secret: bool, replace: bool) -> Result<bool> {
    if !replace && dest.try_exists()? {
        return Ok(false);
    }
    let parent = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;
    let (mut file, tmp_path) = create_temp(parent)?;
    let guard = RemoveOnDrop(tmp_path);
    if secret {
        lock_down(&guard.0)?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if replace {
        place_replace(&guard.0, dest)?;
        Ok(true)
    } else {
        place_new(&guard.0, dest)
    }
}

fn create_temp(dir: &Path) -> Result<(File, PathBuf)> {
    for _ in 0..8 {
        let mut rnd = [0u8; 16];
        getrandom::getrandom(&mut rnd)
            .map_err(|err| CliError::msg(format!("no randomness: {err}")))?;
        let path = dir.join(format!(".tmp-{}", hex::encode(rnd)));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(CliError::msg(format!(
                    "cannot create {}: {err}",
                    ui::show_path(&path)
                )))
            }
        }
    }
    Err(CliError::msg("could not create a temp file"))
}

/// Hard-link into place so an existing destination is left untouched.
fn place_new(tmp: &Path, dest: &Path) -> Result<bool> {
    match fs::hard_link(tmp, dest) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) => {
            if dest.try_exists()? {
                return Ok(false);
            }
            match fs::rename(tmp, dest) {
                Ok(()) => Ok(true),
                Err(err) => {
                    if dest.try_exists()? {
                        Ok(false)
                    } else {
                        Err(CliError::msg(format!(
                            "cannot create {}: {err}",
                            ui::show_path(dest)
                        )))
                    }
                }
            }
        }
    }
}

fn place_replace(tmp: &Path, dest: &Path) -> Result<()> {
    let mut wait = Duration::from_millis(1);
    let mut last = None;
    for _ in 0..5 {
        match fs::rename(tmp, dest) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = Some(err);
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_millis(16));
            }
        }
    }
    match last {
        Some(err) => Err(CliError::msg(format!(
            "cannot replace {}: {err}",
            ui::show_path(dest)
        ))),
        None => Err(CliError::msg("rename failed")),
    }
}

fn lock_down(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_replace_keeps_existing_keys_and_recovery_data() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("owner-keys");
        let backup = dir.path().join("owner-keys.bak");
        fs::write(&dest, b"keys").unwrap();
        fs::write(&backup, b"recovery keys").unwrap();
        assert!(place_replace(&dir.path().join("missing"), &dest).is_err());
        assert_eq!(fs::read(dest).unwrap(), b"keys");
        assert_eq!(fs::read(backup).unwrap(), b"recovery keys");
    }
}
