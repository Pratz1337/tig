//! Repo-relative paths: UTF-8, '/'-separated, no leading/trailing '/', no empty,
//! '.' or '..' components. The root is the empty path.

use std::fmt;

use crate::error::Result;
use crate::object::validate_name;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RepoPath(String);

impl RepoPath {
    pub fn root() -> Self {
        RepoPath(String::new())
    }

    /// Parses a normalized path. Use `from_os_relative` for paths from the filesystem.
    pub fn new(s: &str) -> Result<Self> {
        if !s.is_empty() {
            for c in s.split('/') {
                validate_name(c)?;
            }
        }
        Ok(RepoPath(s.to_string()))
    }

    /// Accepts '\\' as a separator too (Windows input), then validates.
    pub fn from_os_relative(s: &str) -> Result<Self> {
        RepoPath::new(&s.replace('\\', "/"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    pub fn parent(&self) -> Option<RepoPath> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(i) => RepoPath(self.0[..i].to_string()),
            None => RepoPath::root(),
        })
    }

    /// Appends one validated component.
    pub fn join(&self, name: &str) -> Result<RepoPath> {
        validate_name(name)?;
        Ok(if self.is_root() { RepoPath(name.to_string()) } else { RepoPath(format!("{}/{}", self.0, name)) })
    }

    /// True if `self` equals `dir` or lies inside it.
    pub fn starts_with(&self, dir: &RepoPath) -> bool {
        dir.is_root() || self.0 == dir.0 || (self.0.starts_with(&dir.0) && self.0.as_bytes().get(dir.0.len()) == Some(&b'/'))
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_root() { "." } else { &self.0 })
    }
}

impl fmt::Debug for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoPath({:?})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let p = RepoPath::new("a/b/c.txt").unwrap();
        assert_eq!(p.file_name(), Some("c.txt"));
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert!(p.starts_with(&RepoPath::new("a").unwrap()));
        assert!(!RepoPath::new("ab").unwrap().starts_with(&RepoPath::new("a").unwrap()));
        assert!(RepoPath::new("/a").is_err());
        assert!(RepoPath::new("a//b").is_err());
        assert!(RepoPath::new("a/../b").is_err());
        assert_eq!(RepoPath::from_os_relative("a\\b").unwrap().as_str(), "a/b");
    }
}
