//! .private rules, roles, keys, sealing. See DESIGN.md "Privacy".

pub mod rules;

pub use rules::{RuleError, RuleRef, Rules, Verdict, DEFAULT_PRIVATE};
