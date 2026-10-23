# Performance benchmarks

This standalone package is the portable benchmark harness. It uses synthetic-v1:
256 distinct nonmatching word signatures, one matching word signature, one regex
signature, deterministic mixed-case Chinese/ASCII payloads of 1/32/256 KiB, and
local HTTP/HTTPS servers. No rules are downloaded and no external target is scanned.
This is a controlled regression workload, not a representative accuracy dataset
or a prediction of production throughput. Real captured fixtures can be added later.

Matching includes per-call normalization, but excludes rule compilation and payload
creation. Scan benchmarks reuse one scanner/client, warm the connection, and include
fetching, parsing, matching, and result construction. Plain HTTP, redirects, favicon,
and TLS are measured separately. JavaScript redirects and retries are disabled.
Component names are validated before timing; request counts are checked before and
after timing. `targets/s` is sequential throughput, not a latency percentile.

Run locally from the repository root:

```sh
go test ./benchmarks -run '^$' -bench . -benchmem -cpu=1 -benchtime=1s -count=10
```

The Performance comparison GitHub Actions workflow runs on PRs and can also be
started manually with a baseline ref. PRs compare the exact base SHA with the exact
head SHA (not GitHub's merge commit). Both run sequentially in the same job on
`ubuntu-24.04`, using Go 1.26.0 and a pinned benchstat version. The candidate harness
is copied into the baseline checkout, then both binaries are compiled before any
measurements. Each binary is warmed up before ten alternating samples (AB, BA).
Benchstat tables appear in the job summary; raw output, dataset hashes, CPU details,
and commit IDs are retained as artifacts for 30 days. Nothing is posted to PRs.

The first PR introducing this harness works even if the base lacks `benchmarks/`,
provided its production API is compatible. Older versions lacking the scanner API
will fail to compile explicitly; use a compatible baseline rather than silently
comparing different workloads. Changes to this harness affect both versions and
must be reviewed alongside engine changes. Keep dataset versions distinct when
changing workloads; do not compare absolute values across unrelated CI runs.

Performance changes are informational initially. Correctness or compilation failures
fail the job. Establish normal variance before adding regression thresholds; a small
statistically significant change on one hosted runner still warrants a repeat run.
There is no concurrent-load test or P95/P99 report in this initial suite.
