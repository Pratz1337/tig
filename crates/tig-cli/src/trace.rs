//! `TIG_TRACE_PERF=1` prints how long each phase of a command took, like
//! git's `GIT_TRACE_PERFORMANCE`. Off by default; then a span costs one
//! cached environment lookup and nothing else.

use std::sync::OnceLock;
use std::time::Instant;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("TIG_TRACE_PERF").is_some_and(|v| v != "0"))
}

/// Times the enclosing scope; printed to stderr when it ends.
pub struct Span {
    name: &'static str,
    start: Option<Instant>,
}

pub fn span(name: &'static str) -> Span {
    Span { name, start: enabled().then(Instant::now) }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            eprintln!("trace: {:>8.2} ms  {}", start.elapsed().as_secs_f64() * 1000.0, self.name);
        }
    }
}
