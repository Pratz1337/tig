//! Run a command with role-authorized secrets in its environment.
//!
//! Values are parsed literally: no interpolation, no escape evaluation, no
//! shell. Sealed or unreadable sources are errors. Policy denial does not
//! look at a cached epoch key; an authorized child owns its output.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::process::Command;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("this identity cannot read the requested group")]
    Denied,
    #[error("sealed env source `{name}` was not opened")]
    Sealed { name: String },
    #[error("env source `{name}` could not be read")]
    Unreadable { name: String },
    #[error("env source `{name}` is not valid")]
    Invalid { name: String },
    #[error("could not run the command")]
    Spawn,
}

/// Execute the child with ordinary inherited streams. The caller owns and
/// drops parsed secrets before propagating this status to its own process.
pub fn run(
    program: &OsStr,
    args: &[OsString],
    secrets: &BTreeMap<String, Zeroizing<String>>,
    allowed: bool,
) -> Result<std::process::ExitStatus, EnvError> {
    if !allowed { return Err(EnvError::Denied); }
    let mut command = Command::new(program);
    command.args(args);
    for (name, value) in secrets {
        if !valid_name(name) { return Err(EnvError::Invalid { name: "environment".into() }); }
        command.env(name, value.as_str());
    }
    let status = command.status().map_err(|_| EnvError::Spawn)?;
    drop(command);
    Ok(status)
}

/// Literal dotenv. `export ` is optional. Matching quotes are stripped once
/// and the inside is kept character for character. `$` is not expanded.
pub fn parse_dotenv(_name: &str, bytes: &[u8]) -> Result<BTreeMap<String, Zeroizing<String>>, EnvError> {
    if bytes.contains(&0) {
        return Err(EnvError::Invalid { name: "source".into() });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| EnvError::Invalid { name: "source".into() })?;
    let mut out = BTreeMap::new();
    for (number, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(EnvError::Invalid { name: format!("line {}", number + 1) });
        };
        if !valid_name(key) {
            return Err(EnvError::Invalid { name: format!("line {}", number + 1) });
        }
        let value = literal_value(value).ok_or_else(|| EnvError::Invalid {
            name: format!("line {}", number + 1),
        })?;
        out.insert(key.to_string(), Zeroizing::new(value));
    }
    Ok(out)
}

pub fn load_source(
    name: &str,
    read: std::io::Result<Vec<u8>>,
    sealed: bool,
) -> Result<BTreeMap<String, Zeroizing<String>>, EnvError> {
    if sealed {
        return Err(EnvError::Sealed { name: name.into() });
    }
    let bytes = read.map_err(|_| EnvError::Unreadable { name: name.into() })?;
    parse_dotenv(name, &bytes)
}

fn literal_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
        {
            return Some(value[1..value.len() - 1].to_string());
        }
    }
    if value.chars().any(|c| c == '"' || c == '\'') {
        return None;
    }
    Some(value.to_string())
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

