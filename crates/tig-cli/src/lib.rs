//! The `tig` command-line tool: thin wrappers over tig-core and tig-private,
//! plus the filesystem working copy.

pub mod cmd;
pub mod prefetch;
pub mod ui;
pub mod wc;
pub mod trace;
pub mod walk;
pub mod watcher;
