# ArmourAPI Load Benchmarking

Implements doc Section 6.1's load tiers and Section 6.2's before/after metric table. This is the "controlled load-tier benchmarking" the doc requires instead of asserting flat CPU/RAM/latency numbers (Risk Register: "Flat CPU/RAM claims are not defensible without load context").

## Contents

- `k6/light.js`, `k6/medium.js`, `k6/heavy.js` - the doc's chosen tool, one script per tier (100/500/1000 req/s, 10/50/100 concurrency, 1-5/5-20/20-50 KB payload). **Not yet run** - k6 isn't installed in this dev environment (a standalone binary, independent of the Docker blocker - see the note below).
- `node-bench.mjs` - a supplementary harness written because k6 isn't installed, so *something* real could be measured now instead of nothing. **Not a substitute for k6** - see "Why the Node harness isn't good enough" below, which is itself one of this phase's findings.

Both target `/app/bench` (the Juice Shop passthrough prefix) rather than a schema-guarded `/api/v1/*` route - `/app/*` only runs blocklist + rate-limit + WAF (no schema guard with its own size/count caps), isolating payload size as a pure WAF/proxy-throughput variable. Juice Shop isn't running (Docker), so every request 500s after the WAF scan completes - that's fine for what NFR1/NFR2 measure: `armourapi_request_latency_ms` is captured purely around the blocklist/rate-limit/WAF scan phase in the preHandler, before the proxy even attempts to reach the upstream.

## What was actually run, and the results

`node-bench.mjs` against a live local ArmourAPI instance (this dev machine: 12 logical cores, `os.availableParallelism()` - see finding below):

| Tier | Target | Achieved throughput | Server-side `armourapi_request_latency_ms` | CPU (of 1 core) | RAM (RSS) |
|---|---|---|---|---|---|
| Light | 100 req/s, 3KB | 58.9 req/s | p50≤1ms, p95≤50ms, p99≤50ms | 14.4% | 1395.7 MB |
| Medium | 500 req/s, 12KB | 195.5 req/s | p50≤1ms, p95≤25ms, p99 overflowed the histogram's largest bucket (>500ms) | 255.5% | 1555.7 MB |
| Heavy | 1000 req/s, 35KB | **not run** | - | - | - |

(Latency figures are approximated from Prometheus's cumulative histogram buckets client-side, not `histogram_quantile()` via a real Prometheus instance - Prometheus/Grafana are also pending Docker, per `docker-compose.yml`.)

## Why the Node harness isn't good enough - and why that itself matters

This is a genuine finding, not just a caveat. At the Medium tier, **client-observed p95/p99 latency exploded to ~15 seconds**, while ArmourAPI's own server-side metric stayed fast (p50≤1ms) for the same window. That gap is `node-bench.mjs`'s own request-dispatch loop and Node's default `fetch()` connection-pool limits queueing requests client-side under an open-loop firing pattern it can't actually sustain at 500 req/s from a single process - not ArmourAPI. It's exactly the failure mode a purpose-built load tool avoids, which is presumably why the doc specifies k6 for this rather than ad-hoc scripting. Achieved throughput undershooting the target at both tiers (59/100, 196/500) is the same limitation. **Don't use the Medium-tier client-observed numbers for anything** - the server-side ones are more trustworthy but still need real k6 confirmation before they go in a report.

## A real NFR2 finding: idle RAM was ~1.4GB, before a single request - fixed

`process_resident_memory_bytes` was ~1.46GB **at idle**, before any load was generated - confirmed by checking it right after server startup. This wasn't load-driven; it was the Coraza `WAFPool` sizing itself to `os.availableParallelism()` (12 worker threads on this dev machine, each holding its own compiled CRS/WASM instance - see `src/waf/coraza-adapter.js`). The doc's NFR2/Section 5.3 target is **<256MB RAM** - the original default overshot that by ~6x purely from WAF pool startup cost, independent of traffic volume.

Fixed: pool size is now configurable via `WAF_POOL_SIZE` (see `.env.example`), defaulting to `min(4, cores)` instead of the raw core count. Idle RAM measured at each size (same dev machine, 12 cores available):

| `WAF_POOL_SIZE` | Idle RAM | vs. NFR2's 256MB target |
|---|---|---|
| 12 (old default: all cores) | 1395.9 MB | ~5.5x over |
| 4 (new default) | 465.9 MB | ~1.8x over |
| 2 | 275.9 MB | ~1.1x over |
| 1 | 176.8 MB | **under target** |

This is a genuine concurrency-vs-RAM tradeoff, not a free lunch: `WAF_POOL_SIZE=1` serializes every WAF transaction through a single worker thread, which will cost throughput under real concurrent load (not yet measured - needs k6, see above). The new default of 4 was chosen as a reasonable middle ground, not validated against the target load tiers yet. Confirmed the WAF still blocks correctly at every pool size tested (re-ran the SQLi corpus check after each restart).

## Prerequisites to finish this phase for real

1. **k6** - standalone Go binary, `https://k6.io/docs/get-started/installation/`. Independent of Docker; can be installed on this machine directly.
2. **Docker** - for Prometheus (real `histogram_quantile()` instead of the bucket-approximation math in `node-bench.mjs`) and, eventually, the real Juice Shop/DVGA/AndroGoat targets so "protected" numbers can be diffed against genuine "baseline" (ArmourAPI disabled) numbers per Section 6's methodology - nothing here is a baseline run yet, it's all "protected."
