# Performance benchmarks

This standalone package is the portable synthetic-v2 benchmark harness. It uses
deterministic mixed-case Chinese/ASCII payloads and local HTTP/HTTPS servers. CI
also checks out `hexbay/finger-rules` at
`b245e9d7cf02b533b1948b19cc369e7fd734366d` (2603 rules). Every rule file must load
and compile successfully. No external target is scanned. Payloads are synthetic,
including those exercising real rules; they are not captured production traffic.

| Benchmark | Coverage |
| --- | --- |
| RuleSetMatch | 1/32/256 KiB, hit and miss, 258 rules |
| MatchMatrix | 128/1024/4096 rules × word/regex/mixed × 0/1/64 hits; regex version extraction |
| MatcherLogic | AND early/late miss, OR early/late hit, case sensitivity, extraction |
| RealRules | All 2603 real rules × 1/32/256 KiB × neutral/Wordpress+Nginx payload |
| LoadRealRules | Disk reading, YAML parsing and rule compilation (warm filesystem cache) |
| Scan | HTTP, HTTPS, redirect, favicon, 1 MiB response |
| ScanLoad | 1/8/32 workers × plain/20 ms delay/gzip/3 redirects/plugin/JavaScript/real rules |

There are 72 sub-benchmarks in the full suite. Real-rule tests skip explicitly
when `APPFINGER_RULES_DIR` is absent locally; CI always sets it to the pinned checkout.

Matching includes per-call normalization, but excludes rule compilation and payload
creation. Scan benchmarks reuse one scanner/client, warm the connection, and include
fetching, parsing, matching, and result construction. Plain HTTP, redirects, favicon,
and TLS are measured separately. JavaScript is enabled only in its dedicated load
scenario; retries are disabled. Load uses a shared scanner and client with 64 idle
connections per host. Both the replay server and client consume the runner's CPU.
Component names are validated before timing; request counts are checked before and
after timing. Load validates every scan and reports throughput, requests/target,
P50/P95/P99 execution latency and latency-samples. Latency excludes queue wait.
CI runs 128 targets per load sample, so P99 is coarse, not a production SLO estimate.
Use a longer fixed iteration count (for example `-benchtime=4096x`) for tail analysis.
Load `ns/op` is throughput amortization, not individual request latency.

Before timing, CI diffs complete real-rule outputs for neutral, Wordpress+Nginx
and Grafana fixtures, including incidental matches and extracted fields. A semantic
difference fails the job and remains available in corpus JSON/diff artifacts.

Run locally from the repository root:

```sh
# Set APPFINGER_RULES_DIR to a checkout at the exact rules commit above.
go test ./benchmarks -run '^$' -bench 'Benchmark(MatchMatrix|RealRules|MatcherLogic|LoadRealRules)' -benchmem -cpu=1 -benchtime=200ms -count=6
go test ./benchmarks -run '^$' -bench BenchmarkScanLoad -benchmem -cpu=4 -benchtime=128x -count=6
```

The Performance comparison GitHub Actions workflow runs on PRs and can also be
started manually with a baseline ref and `quick`/`full` suite selection. Baseline
commits must use the full 40-character SHA (short SHAs are not checkout refs).
PRs run quick (17 cases); manual runs default to full. PRs compare the exact base SHA with the exact
head SHA (not GitHub's merge commit). Both run sequentially in the same job on
`ubuntu-24.04`, using Go 1.26.0 and a pinned benchstat version. The candidate harness
is copied into the baseline checkout, then both binaries are compiled before any
measurements. Each binary is warmed up before six alternating samples (AB, BA).
Matching/sequential scans use CPU=1 and 200 ms per case; full concurrent scans use
CPU=4 and 128 targets per case. Both versions use identical limits.
Benchstat tables appear in the job summary; raw output, dataset hashes, CPU details,
and commit IDs are retained as artifacts for 30 days. Nothing is posted to PRs.

For a sensitivity check against the word normalization optimization, use baseline
`c89d066` resolved to its full SHA (`git rev-parse c89d066`), the last compatible
commit before that optimization. Comparing two commits that only change the harness
should show noise rather than engine gains. Historical comparisons include every
production change between the selected SHAs; interpret results accordingly.

The first PR introducing this harness works even if the base lacks `benchmarks/`,
provided its production API is compatible. Older versions lacking the scanner API
will fail to compile explicitly; use a compatible baseline rather than silently
comparing different workloads. Changes to this harness affect both versions and
must be reviewed alongside engine changes. Keep dataset versions distinct when
changing workloads; do not compare absolute values across unrelated CI runs.

Performance changes are informational initially. Correctness or compilation failures
fail the job. Establish normal variance before adding regression thresholds; a small
statistically significant change on one hosted runner still warrants a repeat run.
Longer fixed iteration runs and captured real response fixtures remain useful future
extensions. These local replay numbers are not Internet scanning capacity estimates.
