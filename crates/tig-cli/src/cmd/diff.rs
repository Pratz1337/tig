//! `tig diff`

use std::path::Path;

use similar::{ChangeTag, TextDiff};
use tig_core::repo::Repo;
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{diff_trees, lookup, DiffEntry, Leaf};
use tig_core::RepoPath;
use tig_core::ObjectId;

use super::{CliError, Result};

pub(super) fn run(repository: Option<&Path>, revision: Option<&str>, stat: bool) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let spec = revision.unwrap_or("@");
    let id = session.resolve(spec)?;
    let conflicts = if id == session.working()? { session.wc.conflict_paths() } else { Vec::new() };
    print_revision_diff(&session.repo, id, stat, &conflicts)
}

pub(super) fn print_revision_diff(repo: &Repo, rev_id: ObjectId, stat: bool, conflicts: &[RepoPath]) -> Result<()> {
    let rev = repo.revision(&rev_id)?;
    let parent_tree = match rev.parents.first() {
        Some(parent) => repo.revision(parent)?.tree,
        None => empty_tree_id(),
    };
    let mut entries = diff_trees(repo.store().as_ref(), &parent_tree, &rev.tree)?;
    for path in conflicts {
        if !entries.iter().any(|entry| entry.path == *path) {
            entries.push(DiffEntry { path: path.clone(), old: lookup(repo.store().as_ref(), &parent_tree, path)?, new: lookup(repo.store().as_ref(), &rev.tree, path)? });
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    if stat {
        print_stat(repo, &entries)
    } else {
        print_unified(repo, &entries)
    }
}

fn print_unified(repo: &Repo, entries: &[DiffEntry]) -> Result<()> {
    let mut printed = false;
    for entry in entries {
        if let Some(text) = render_unified(repo, entry)? {
            print!("{text}");
            printed = true;
        }
    }
    if !printed {
        println!("No changes.");
    }
    Ok(())
}

fn print_stat(repo: &Repo, entries: &[DiffEntry]) -> Result<()> {
    let mut files = 0usize;
    let mut plus = 0usize;
    let mut minus = 0usize;
    let mut lines: Vec<String> = Vec::new();
    for entry in entries {
        let Some(row) = stat_row(repo, entry)? else {
            continue;
        };
        files += 1;
        plus += row.plus;
        minus += row.minus;
        lines.push(row.text);
    }
    if files == 0 {
        println!("No changes.");
        return Ok(());
    }
    for line in lines {
        println!("{line}");
    }
    let word = if files == 1 { "file" } else { "files" };
    println!("{files} {word} changed, +{plus} -{minus}");
    Ok(())
}

struct StatRow {
    text: String,
    plus: usize,
    minus: usize,
}

fn stat_row(repo: &Repo, entry: &DiffEntry) -> Result<Option<StatRow>> {
    if [entry.old, entry.new].into_iter().flatten().any(|leaf| leaf.kind() == tig_core::EntryKind::Conflict) {
        return Ok(Some(StatRow { text: format!("{} | conflict", entry.path), plus: 0, minus: 0 }));
    }
    match load_sides(repo, entry)? {
        None => Ok(None),
        Some(Sides::Binary) => Ok(Some(StatRow {
            text: format!("{} | binary", entry.path),
            plus: 0,
            minus: 0,
        })),
        Some(Sides::Text { old, new }) => {
            let (plus, minus) = line_delta(&old, &new);
            Ok(Some(StatRow {
                text: format!("{} | +{plus} -{minus}", entry.path),
                plus,
                minus,
            }))
        }
    }
}

fn render_unified(repo: &Repo, entry: &DiffEntry) -> Result<Option<String>> {
    if [entry.old, entry.new].into_iter().flatten().any(|leaf| leaf.kind() == tig_core::EntryKind::Conflict) {
        let mut text = format!("Conflict {}\n", entry.path);
        if let Some(leaf) = entry.new {
            text.push_str(&String::from_utf8_lossy(&tig_core::conflict::materialize(repo.store().as_ref(), leaf)?));
        } else { text.push_str("[deleted]\n"); }
        return Ok(Some(text));
    }
    let Some(sides) = load_sides(repo, entry)? else {
        return Ok(None);
    };
    match sides {
        Sides::Binary => Ok(Some(format!("Binary file {} differs\n", entry.path))),
        Sides::Text { old, new } => {
            let (old_header, new_header) = headers(entry);
            if old.is_empty() && new.is_empty() {
                return Ok(Some(format!("--- {old_header}\n+++ {new_header}\n")));
            }
            let diff = TextDiff::from_lines(&old, &new);
            let mut out = Vec::new();
            diff.unified_diff()
                .context_radius(3)
                .header(&old_header, &new_header)
                .to_writer(&mut out)?;
            if out.is_empty() {
                return Ok(None);
            }
            Ok(Some(String::from_utf8_lossy(&out).into_owned()))
        }
    }
}

fn headers(entry: &DiffEntry) -> (String, String) {
    match (&entry.old, &entry.new) {
        (None, Some(_)) => ("/dev/null".to_string(), format!("b/{}", entry.path)),
        (Some(_), None) => (format!("a/{}", entry.path), "/dev/null".to_string()),
        _ => (format!("a/{}", entry.path), format!("b/{}", entry.path)),
    }
}

enum Sides {
    Binary,
    Text { old: String, new: String },
}

/// `None` when both sides exist and the bytes are identical.
fn load_sides(repo: &Repo, entry: &DiffEntry) -> Result<Option<Sides>> {
    if !file_like(entry.old) || !file_like(entry.new) {
        return Ok(Some(Sides::Binary));
    }
    let old = read_leaf(repo, entry.old)?;
    let new = read_leaf(repo, entry.new)?;
    if old == new {
        return Ok(None);
    }
    let old_bytes = old.as_deref().unwrap_or(b"");
    let new_bytes = new.as_deref().unwrap_or(b"");
    if is_binary(old_bytes) || is_binary(new_bytes) {
        return Ok(Some(Sides::Binary));
    }
    let old = std::str::from_utf8(old_bytes)
        .map_err(|_| CliError::msg(format!("{} is not valid utf-8", entry.path)))?
        .to_string();
    let new = std::str::from_utf8(new_bytes)
        .map_err(|_| CliError::msg(format!("{} is not valid utf-8", entry.path)))?
        .to_string();
    Ok(Some(Sides::Text { old, new }))
}

fn file_like(leaf: Option<Leaf>) -> bool {
    match leaf {
        None => true,
        Some(leaf) => leaf.is_file_like(),
    }
}

fn read_leaf(repo: &Repo, leaf: Option<Leaf>) -> Result<Option<Vec<u8>>> {
    match leaf {
        None => Ok(None),
        Some(leaf) => Ok(Some(repo.store().get_blob(&leaf.id())?)),
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

fn line_delta(old: &str, new: &str) -> (usize, usize) {
    let diff = TextDiff::from_lines(old, new);
    let mut plus = 0usize;
    let mut minus = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => plus += 1,
            ChangeTag::Delete => minus += 1,
            ChangeTag::Equal => {}
        }
    }
    (plus, minus)
}
