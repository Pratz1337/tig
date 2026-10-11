//! Shared text for `tig` commands. No repository mutations live here.

use tig_core::repo::{root_revision_id, Repo};
use tig_core::{ChangeId, ObjectId, Revision};

/// `@` for this workspace's working revision, `*` for the root, `o` otherwise.
/// Root wins when a workspace is somehow sitting on it: the root marker is the
/// one the log promised.
pub fn marker(id: ObjectId, working: ObjectId) -> char {
    if id == root_revision_id() {
        '*'
    } else if id == working {
        '@'
    } else {
        'o'
    }
}

/// Shortest unique change-id prefix, widened to at least 8 characters of the id.
pub fn change_label(repo: &Repo, change: &ChangeId, all: &[(ObjectId, Revision)]) -> String {
    let unique = repo.short_change_id(change, all);
    let full = change.to_text();
    let n = unique.len().max(8).min(full.len());
    full[..n].to_string()
}

pub fn object_label(id: ObjectId) -> String {
    id.short(8)
}

/// First non-empty line of a description, or `(no description)`.
pub fn first_line(description: &str) -> &str {
    if description.trim().is_empty() {
        return "(no description)";
    }
    description
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .unwrap_or("(no description)")
}

pub struct RevLabel {
    pub change_id: String,
    pub object_id: String,
    pub summary: String,
}

impl RevLabel {
    pub fn from_revision(
        repo: &Repo,
        id: ObjectId,
        rev: &Revision,
        all: &[(ObjectId, Revision)],
    ) -> Self {
        // The root is the same empty start in every repo; its zero change id
        // and 1970 timestamp are noise.
        if id == tig_core::repo::root_revision_id() {
            return RevLabel {
                change_id: "root".into(),
                object_id: String::new(),
                summary: String::new(),
            };
        }
        RevLabel {
            change_id: change_label(repo, &rev.change_id, all),
            object_id: object_label(id),
            summary: first_line(&rev.description).to_string(),
        }
    }

    /// `change object summary`, or just `root` for the root revision.
    pub fn line(&self) -> String {
        if self.object_id.is_empty() {
            return self.change_id.clone();
        }
        format!("{} {} {}", self.change_id, self.object_id, self.summary)
    }
}

/// One log row: marker, ids, email, UTC time, then bookmarks, `name@`, `(empty)`.
pub fn format_rev_line(
    marker: char,
    label: &RevLabel,
    email: &str,
    time: &str,
    extras: &[String],
) -> String {
    let mut parts = Vec::with_capacity(6 + extras.len());
    parts.push(format!("{marker} {} {}", label.change_id, label.object_id));
    if !email.is_empty() {
        parts.push(email.to_string());
    }
    parts.push(time.to_string());
    parts.extend(extras.iter().cloned());
    parts.join(" ")
}

pub fn working_change_line(label: &RevLabel) -> String {
    format!("Working change: {}", label.line())
}

/// UTC `YYYY-MM-DD HH:MM`. Milliseconds are truncated, not rounded.
pub fn format_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u64;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {hour:02}:{min:02}")
}

/// Howard Hinnant's `civil_from_days`. `div_euclid` keeps the era split correct
/// for dates before the Unix epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    // `era` is floor(z / 146097), so the remainder is in `0..146097`.
    let doe = u64::try_from(z - era * 146_097).expect("day of era is non-negative");
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month as u32, day as u32)
}

/// Shareable public identity: `tig1:` plus hex(encryption key || signing key).
pub fn identity_token(identity: &tig_private::keys::PublicIdentity) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&identity.encryption);
    bytes[32..].copy_from_slice(&identity.signing);
    format!("tig1:{}", hex::encode(bytes))
}

/// Parses a token from [`identity_token`]. The hex may be any case.
pub fn parse_identity_token(text: &str) -> Result<tig_private::keys::PublicIdentity, String> {
    let text = text.trim();
    let hex_part = text
        .strip_prefix("tig1:")
        .ok_or("identity token must start with tig1:")?;
    if hex_part.len() != 128 || !hex_part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("identity token must be tig1: followed by 128 hex characters".into());
    }
    let bytes = hex::decode(hex_part).map_err(|_| "identity token is not hex".to_string())?;
    if bytes.len() != 64 {
        return Err("identity token must be tig1: followed by 128 hex characters".into());
    }
    let mut encryption = [0u8; 32];
    let mut signing = [0u8; 32];
    encryption.copy_from_slice(&bytes[..32]);
    signing.copy_from_slice(&bytes[32..]);
    Ok(tig_private::keys::PublicIdentity {
        encryption,
        signing,
    })
}

/// A path as people expect to read it. On Windows, canonical paths carry the
/// verbatim prefix (`\?\C:\...`); drop it when the rest is a plain drive path.
pub fn show_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_path_drops_verbatim_drive_prefix_only() {
        use std::path::Path;
        assert_eq!(show_path(Path::new(r"\\?\C:\work\repo")), r"C:\work\repo");
        // UNC verbatim paths keep their prefix: stripping it would change meaning.
        assert_eq!(
            show_path(Path::new(r"\\?\UNC\server\share")),
            r"\\?\UNC\server\share"
        );
        assert_eq!(show_path(Path::new("/home/me/repo")), "/home/me/repo");
    }

    #[test]
    fn identity_token_round_trip() {
        let identity = tig_private::keys::PublicIdentity {
            encryption: [0xab; 32],
            signing: [0xcd; 32],
        };
        let token = identity_token(&identity);
        assert_eq!(token.len(), "tig1:".len() + 128);
        assert_eq!(parse_identity_token(&token).unwrap(), identity);
        assert_eq!(
            parse_identity_token(&format!("  {token}\n")).unwrap(),
            identity
        );
        let upper = format!(
            "tig1:{}",
            hex::encode_upper({
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(&identity.encryption);
                bytes[32..].copy_from_slice(&identity.signing);
                bytes
            })
        );
        assert_eq!(parse_identity_token(&upper).unwrap(), identity);
        assert!(parse_identity_token("tig1:abcd").is_err());
        assert!(parse_identity_token("nope").is_err());
    }

    #[test]
    fn format_time_known_instants() {
        assert_eq!(format_time(0), "1970-01-01 00:00");
        assert_eq!(format_time(60_000), "1970-01-01 00:01");
        assert_eq!(format_time(3_600_000), "1970-01-01 01:00");
        assert_eq!(format_time(1_700_000_000_000), "2023-11-14 22:13");
        assert_eq!(format_time(1_700_000_000_999), "2023-11-14 22:13");
        assert_eq!(format_time(-1000), "1969-12-31 23:59");
    }
}
