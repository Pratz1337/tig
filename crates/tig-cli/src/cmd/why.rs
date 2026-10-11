//! `tig why`

use std::path::Path;

use tig_private::project::rules_of;
use tig_private::rules::Verdict;

use super::Result;

pub(super) fn run(repository: Option<&Path>, path: &str) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let id = session.working()?;
    let rev = session.repo.revision(&id)?;
    let rules = rules_of(session.repo.store().as_ref(), &rev.tree)?;
    let path = super::parse_path(path)?;
    match rules.classify(&path) {
        Verdict::Private { readers, rule } => {
            let group = readers.into_iter().collect::<Vec<_>>().join(", ");
            println!(
                "{path} is private (group: {group}) because of .private line {}: {}",
                rule.line, rule.text
            );
        }
        Verdict::Public { rule: Some(rule) } => {
            println!(
                "{path} is public because of .private line {}: {}",
                rule.line, rule.text
            );
        }
        Verdict::Public { rule: None } => {
            println!("{path} is public (no rule matches)");
        }
    }
    Ok(())
}
