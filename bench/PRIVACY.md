# Privacy at the publish boundary

`python -B bench/privacy.py --files 10000 --runs 5` runs real release CLI
processes over two generated, identical data trees. One has no private data;
the other marks 1,000 files private before initialization. Samples alternate
between fixtures. Clean status is warmed after the stat-cache racy window;
edited status and `new` modify the same file, which is private in the second
fixture. Each first-publish sample sends the baseline revision to a fresh
directory remote. Hot commands run again afterward.

Measured October 12, 2026. Median wall time, milliseconds:

| Operation | Windows 0% | Windows 10% | Modal Linux 0% | Modal Linux 10% |
|---|---:|---:|---:|---:|
| Clean status before publish | 26.64 | 28.31 | 124.62 | 139.78 |
| Edited status before publish | 42.92 | 41.13 | 155.69 | 156.63 |
| Record change before publish | 56.90 | 69.62 | 136.84 | 139.11 |
| First publish | 18,086.15 | 16,872.85 | 2,417.25 | 2,270.56 |
| Clean status after publish | 26.57 | 25.32 | 186.34 | 167.61 |
| Edited status after publish | 36.03 | 35.37 | 163.46 | 164.42 |
| Record change after publish | 66.33 | 63.00 | 178.75 | 184.84 |

The private run actually seals 1,010 objects (1,000 blobs and 10 trees),
while writing 9,096 public objects instead of 10,106. The publish row includes
classification, leak scans, packing, encryption and remote writes; it does not
isolate encryption cost. Fewer loose public objects can offset that cost.

These five-sample runs do not establish exact timing equivalence or a causal
privacy slowdown. Differences change direction across stages, and the Linux
container's plain fixture also slows after publishing. Windows' pre-publish
record medians differ by 22%, while its snapshot trace medians are 23.54 ms
and 22.47 ms respectively. That difference is outside the snapshot phase;
this run cannot attribute it to privacy. No rule matching or cryptography is
called by status or snapshot. The benchmark verifies that those commands do
not create identities, and publish leaves local file and recorded bytes plain.
It measures a local source after sealing its remote projection, not a fetched
outsider workspace. Windows and container timings are not directly comparable
and do not establish a cause for earlier Git-versus-tig platform differences.

Raw samples, trace phases and measured executable hashes are in
`target/privacy-windows-10000.json` and `target/privacy-linux-modal.json`.
Those measurements precede the subsequent conservative double-star matcher
update, which changes only trust-boundary processing.
