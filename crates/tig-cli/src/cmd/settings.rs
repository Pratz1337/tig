//! Author and clock. Env wins, then `~/.gitconfig`, then the OS user name.

use std::env;
use std::path::PathBuf;

use tig_core::repo::Settings;

use super::{CliError, Result};

pub(super) struct Loaded {
    pub(super) settings: Settings,
    /// True when the name or the email came from the OS-user fallback.
    pub(super) fell_back: bool,
}

pub(super) fn load() -> Result<Loaded> {
    let (cfg_name, cfg_email) = gitconfig_user()?;
    let env_name = env_nonempty("TIG_AUTHOR_NAME")?;
    let env_email = env_nonempty("TIG_AUTHOR_EMAIL")?;

    let mut fell_back = false;
    let name = if let Some(name) = env_name.or(cfg_name) {
        name
    } else {
        fell_back = true;
        os_user()
    };
    let email = if let Some(email) = env_email.or(cfg_email) {
        email
    } else {
        fell_back = true;
        format!("{name}@localhost")
    };
    let fixed_time_ms =
        match env::var("TIG_TIMESTAMP_MS") {
            Ok(text) => Some(text.parse::<i64>().map_err(|_| {
                CliError::msg(format!("TIG_TIMESTAMP_MS is not an integer: {text}"))
            })?),
            Err(env::VarError::NotPresent) => None,
            Err(_) => return Err(CliError::msg("TIG_TIMESTAMP_MS is not valid text")),
        };

    Ok(Loaded {
        settings: Settings {
            user_name: name,
            user_email: email,
            tz_offset_min: 0,
            fixed_time_ms,
        },
        fell_back,
    })
}

pub(super) fn env_nonempty(key: &str) -> Result<Option<String>> {
    match env::var(key) {
        Ok(value) => {
            let value = value.trim();
            Ok(if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            })
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(CliError::msg(format!("{key} is not valid text"))),
    }
}

fn os_user() -> String {
    for key in ["USERNAME", "USER", "LOGNAME"] {
        if let Ok(value) = env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    "tig".to_string()
}

/// `HOME` when it is set, otherwise `USERPROFILE`. Git for Windows does the same.
pub(super) fn home_dir() -> Option<PathBuf> {
    let home = env::var_os("HOME").filter(|value| !value.is_empty());
    let profile = env::var_os("USERPROFILE").filter(|value| !value.is_empty());
    home.or(profile).map(PathBuf::from)
}

fn gitconfig_user() -> Result<(Option<String>, Option<String>)> {
    let Some(home) = home_dir() else {
        return Ok((None, None));
    };
    let path = home.join(".gitconfig");
    let text = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(err) => {
            return Err(CliError::msg(format!(
                "cannot read {}: {err}",
                path.display()
            )))
        }
    };
    let text = String::from_utf8(text)
        .map_err(|_| CliError::msg(format!("{} is not utf-8", path.display())))?;
    Ok(parse_gitconfig_user(&text))
}

/// Reads `[user] name` and `[user] email`. Subsections are ignored. Last value wins.
fn parse_gitconfig_user(text: &str) -> (Option<String>, Option<String>) {
    let mut in_user = false;
    let mut name = None;
    let mut email = None;
    for raw in text.lines() {
        let Some(line) = strip_comment(raw) else {
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                in_user = false;
                continue;
            };
            let header = &rest[..end];
            let base = header.split_whitespace().next().unwrap_or("");
            // `[user "subsection"]` is not the identity block.
            in_user = !header.contains('"') && base.eq_ignore_ascii_case("user");
            let inline = rest[end + 1..].trim();
            if in_user && !inline.is_empty() {
                apply_user_pair(inline, &mut name, &mut email);
            }
            continue;
        }
        if in_user {
            apply_user_pair(line, &mut name, &mut email);
        }
    }
    (name, email)
}

fn strip_comment(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        None
    } else {
        Some(line)
    }
}

fn apply_user_pair(line: &str, name: &mut Option<String>, email: &mut Option<String>) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    let key = key.trim();
    let value = unquote(value.trim());
    if key.eq_ignore_ascii_case("name") {
        *name = Some(value.to_string());
    } else if key.eq_ignore_ascii_case("email") {
        *email = Some(value.to_string());
    }
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::parse_gitconfig_user;

    #[test]
    fn reads_the_user_section_only() {
        let text = "\
[user]
    name = Ada Lovelace
    email = \"ada@example.com\"
[user \"github\"]
    name = ignored
[alias]
    name = also ignored
";
        let (name, email) = parse_gitconfig_user(text);
        assert_eq!(name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(email.as_deref(), Some("ada@example.com"));
    }
}
