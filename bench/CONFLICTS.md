# Normal status after stored conflicts

Measured October 12, 2026 on Windows with the retained pre-conflict release
executable and the final release executable. `trace_compare.py` alternates
them on the same generated 10,000-file workspace, ten samples per executable
per scenario. Each edited-status sample changes a file before that executable
runs. No build or test driver ran during the accepted final measurement.

Median process wall time, milliseconds:

| Scenario | Before conflicts | With conflicts |
|---|---:|---:|
| Clean status | 25.71 | 25.39 |
| Edited status | 37.45 | 38.12 |
| Startup (`--version`) | 8.26 | 8.73 |

This run shows comparable ordinary status times, not proof of exact timing
equivalence or of performance on real monorepos. The scan remains free of
privacy matching and encryption. Normal caches avoid conflict-path scans;
ordinary tree encodings and hashes remain unchanged. Conflict materialization
and resolution necessarily perform additional work on conflicted paths.

Raw samples and trace phases: `target/bench-trace-paired-conflicts.json`.
Measured executable SHA-256 values: `target/conflict-performance-provenance.json`.
The earlier exploratory comparison is preserved separately in
`target/bench-trace-paired-conflicts-initial.json`.
