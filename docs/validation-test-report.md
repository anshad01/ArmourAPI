# ArmourAPI Validation Test Report

This report exists to hold real, measured data against the target figures in the two client-supplied requirement documents — never to restate their targets as if they were results. Every number below either came from a command run on this machine (reproducible via the paths given) or is explicitly marked as not yet measured. Where a measurement falls short of a target, that's stated plainly, with the reason understood, not hidden.

## Section 1: Detection Pipeline & Distributed-Systems Parameters ("Parameters.rtf.doc", Phase 13)

### 1.1 Per-scanner-stage latency (Latency Profiler)

Source: `test/load/profiler.mjs`, run 2026-09-14 against a local ArmourAPI instance (Redis down, in-memory fallback active — the worst case for the blocklist/rate-limiter stages, not the best), 500 mixed allow-path requests across `/app`, `/graphql`, and `/api/v1/products` so every scanner in every route's chain gets exercised. Figures are cumulative-histogram-bucket approximations from `armourapi_request_latency_ms` (now labeled by `scanner` as well as `route` — see `src/metrics/registry.js`), not exact percentiles; real values sit somewhere in the printed bucket, not exactly at it.

| Scanner stage | n | p50 | p95 | p99 | Doc's closest target | Verdict |
|---|---|---|---|---|---|---|
| fast-filter (Mode 1, allow-path) | 167 | ≤0.05ms | ≤0.05ms | ≤0.05ms | "Regex pre-filter latency = 0.42ms" / "Overhead: 0.04ms" | **Met** — allow-path cost is at or below the doc's own figure. (13.1's own testing measured 0.14–1.38ms on the *block* path, where a signature actually matches and more regex backtracking happens — a different, harder case than allow-path.) |
| blocklist guard (incl. Mode 3 jail check) | 167 | ≤0.05ms | ≤0.1ms | ≤0.25ms | not directly named in the doc | Not comparable — no equivalent line item, but sub-millisecond regardless. |
| rate-limiter | 167 | ≤0.05ms | ≤0.1ms | ≤0.25ms | not directly named | Not comparable — sub-millisecond. |
| token-guard (public route, no-op) | 100 | ≤0.05ms | ≤0.05ms | ≤0.05ms | "0.05ms Token Lookup Time" | **Met**, but caveat: this run only exercised the no-op path (`/products` needs no token) — the real revocation check (13.2's Bloom filter) is measured separately in §1.2, not here. |
| schema-guard (no-op path) | 100 | ≤0.05ms | ≤0.05ms | ≤0.05ms | not directly named | Not comparable — no-op path only. |
| graphql-guard | 100 | ≤0.05ms | ≤0.25ms | ≤0.25ms | "AST Tree Parsing Time = 2.15ms" | **Met** — real cost is well under the doc's target, for the trivial `{ __typename }` query this run sent (a deep/complex real query would cost more; not tested here). |
| coraza (WAF transaction, allow-path) | 100 | ≤10ms | ≤25ms | ≤50ms | "Coupled Latency Budget 2.38ms, p99" / "Inspection Latency (P99) 2.38ms SLA Passed (<4ms limit)" | **Not met.** A real Coraza WASM transaction on this machine costs roughly 10–50x the doc's target. This is the dominant cost in the whole chain by a wide margin — every other stage is sub-millisecond. |

**Total transit latency**: the doc's headline "3.38ms Total Transit Latency" figure is not achievable end-to-end on this hardware, because the Coraza stage alone already exceeds it. The honest total is dominated by whichever WAF engine is active — Coraza's WASM transaction cost, not the lightweight stages layered in front of it (fast-filter, blocklist, rate-limiter), which are the parts Phase 13 actually added and which do land at or under the doc's per-stage targets.

**Throughput targets** ("8520 req/s Load resilience", "12,200 req/s Sustained load", "8450 req/s Traffic throughput", "94.2% ... stress load: 8500 req/s") are **not comparable** with the tooling available on this machine. k6 (the doc's own named load tool) is still not installed; the Node-based fallback harness (`test/load/node-bench.mjs`) was already shown in Phase 11 to be untrustworthy above roughly Light/Medium tier due to its own open-loop connection-pool queueing, not ArmourAPI's overhead — reporting a number here would misattribute a harness artifact as a real throughput ceiling. This gap is carried forward from Phase 11, not new to Phase 13.

### 1.2 Memory footprint

Source: same `profiler.mjs` run. RSS sampled via `process_resident_memory_bytes` before and after the 500-request burst (with a 500ms settle delay for GC).

| Metric | Measured | Doc target | Verdict |
|---|---|---|---|
| RSS before burst | 496.7 MB | — | — |
| RSS after burst | 582.4 MB | — | — |
| Memory per intercepted request (RSS delta ÷ count) | **175.6 KB** | "97.4 KB" / "74.2 KB RAM per intercepted request, <100KB SLA" | **Not met.** |
| RAM relative to host capacity | 7.44% of 7.6GB | "<5%" (client's own Phase 12 feedback) | **Not met** at this instant, though Phase 11's tuned `WAF_POOL_SIZE=4` idle baseline (465.9MB / 8.2GB ≈ 5.7%) is the more representative resting figure — this run's 582MB reflects a burst still holding recently-allocated buffers, not steady state. |

**Why the per-request figure misses the target, and what it actually means**: this is RSS *delta over a single short burst*, not a per-request heap allocation traced individually — it necessarily includes one-time JIT warmup, WASM instance state that Coraza allocates lazily on first use of certain rule paths, and V8 heap growth that happens in steps (not smoothly per-request) rather than being released back to the OS immediately. A burst-based measurement like this structurally cannot distinguish "real steady-state cost per request" from "one-time warmup cost amortized over only 500 requests" — the fix isn't a better formula, it's a longer run. **This is exactly what the 13.6 soak test is for**: a multi-hour run watching `process_resident_memory_bytes` *trend* (not a single before/after delta) will show whether memory keeps climbing per request indefinitely (a real leak — doesn't match this project's design) or plateaus after warmup (the expected, and far more likely, explanation). Treat this section's number as a first data point to be superseded by §1.4's soak-test trend data, not a final answer.

### 1.3 Bloom-filter footprint ("Mode 2: Token Invalidation")

Source: 13.2's own testing (`src/auth/jwt.js`'s `getBloomFilterStats()`, inspected via the library's real internal fields, not assumed).

| Metric | Measured | Doc target | Verdict |
|---|---|---|---|
| Filter size | 19,631 bits ≈ 2.4 KB | "18.4 KB compact bloom filter" | **Met** (well under — this library is more space-efficient at this slot count/error-rate than the doc's figure implies) |
| Hash function count | 7 | "3 hash bit vector" | **Not met as a literal match** — a real 2048-slot/1%-error-rate Bloom filter genuinely needs more than 3 hashes to hit that error rate; 7 is the mathematically correct count for this library's `bloom-filters` implementation, not a bug. The doc's "3 hash" figure doesn't correspond to a real filter at this size/accuracy — reported as a discrepancy, not silently matched. |
| Revocation slots | 2048 | "2048 Active Blocklist size" | **Met** exactly (this was a direct sizing choice, not a coincidence). |
| Lookup complexity | O(1) (per `.has()` call) | "O(1) lookup complexity" | **Met.** |

### 1.4 Chaos Resilience & Soak Test

**Done**, scoped honestly: the doc's mandatory target is 72h continuous at 12,000 req/s sustained. This machine ran a real, continuous, unattended **600-second (10-minute)** soak at **~15 req/s**, with three chaos experiments interleaved, via `test/chaos/soak-and-chaos.mjs`. The gap between 600s and 72h (432,000s, ~720x longer) is stated plainly, not hidden — this is a real data point at a scale this laptop can actually sustain unattended in one session, not a substitute for the doc's figure.

**Throughput**: 7,628 requests sent over 600s (~12.7 req/s achieved, close to the ~15 req/s target rate — the shortfall is explained by the CPU-saturation and process-restart chaos windows below). **Not comparable** to the doc's 12,000 req/s target, same reasoning as Phase 11/13.4: k6 isn't installed, and this is a single Node process generating load against itself on the same machine, not a real distributed load generator.

**Error rate**: 12 errors out of 7,628 requests (0.16%). Real, and localized: the error count is exactly 0 for the entire run up to the process-kill chaos event, jumps to 12 in the sample immediately after, and stays flat at 12 for the rest of the run — i.e. every single error is directly attributable to the ~1s window while ArmourAPI itself was down mid-restart (see below), not to ongoing instability afterward.

**Memory drift (real trend, supersedes §1.2's single-burst figure)**: RSS climbed from 538.3MB to 720.0MB over the run (+181.6MB), with a clear reset down to ~540MB right at the process restart (fresh process, as expected) followed by a similar climb resuming afterward. **Honest, unresolved finding, not glossed over**: 600 seconds is not long enough to distinguish "still-settling JIT/WASM warmup that will plateau" (the far more likely explanation, and consistent with 13.4's own finding that a single burst can't separate warmup cost from steady-state cost) from "a genuine slow per-request leak" — both produce the same shape of graph over this short a window. **Doc target "0.0 MB Memory Drift... zero heap leak variance" is not met** by this measurement, but whether it's actually *unmet* in the sense the doc cares about (a real leak) is not yet established either way — a longer follow-up run (several hours, watching whether the curve flattens) would be needed to tell the difference, and is flagged here as follow-up work rather than claimed as either a pass or a confirmed leak.

**Chaos experiment 1 — CPU saturation** (all 12 logical cores saturated for 30s, t=120s-150s): latency visibly degraded during the window (p50 jumped from a ~2-9ms baseline to 73.39ms, p95 to 120.80ms, p99 to 226.65ms) and one further sample still showed elevated p95/p99 (95.47ms/112.74ms) before fully recovering to baseline by the next sample (~30s after the saturation ended). **Real, measured recovery: full latency recovery within ~30s of a 12-core, 30-second saturation event**, with zero dropped/errored requests throughout — the system degraded gracefully rather than failing.

**Chaos experiment 2 — process kill + restart under active load** ("WAF pool restart" in this single-process architecture, where the pool has no lifecycle independent of the process — restarting one is restarting the other, stated as such rather than stretched to look like a live cluster failover): the process was SIGKILL'd at t=240s with load still firing at it. **Real measured downtime: 1,057ms** from kill to the restarted process passing its readiness check — this script itself performed the restart, since ArmourAPI has no built-in process supervisor (an honest limitation: a real deployment would need pm2/systemd/a container orchestrator's restart policy to do this automatically). **Not comparable** to the doc's "Failover Dispatch SLA 0.84ms" / "Chaos Fault Recovery: 1.18ms" targets in the way the doc intends — those assume a live cluster where another already-running node takes over, not a cold process restart (Node startup + module loading + Coraza WASM compilation). No clustering exists in this project (Raft is a separate, unwired demo — see §1.5), so "re-election" experiments aren't applicable here, noted rather than faked.

**Chaos experiment 3 — Redis outage under active load**: Redis was never started for this entire 600s run (confirmed via the startup log's "redis unavailable - falling back to in-memory" line), so the in-memory rate-limiter/blocklist fallback was exercised continuously under real, sustained traffic for the full 10 minutes — not just verified at idle, per the plan's own bar. 7,616 of 7,628 requests succeeded with no Redis-attributable failures; the only errors were the 12 tied to the unrelated process-kill window above.

Full trend table and chaos-event log (real output, 2026-09-14): `test/chaos/soak-and-chaos.mjs`'s run transcript is reproducible by re-running the same command (`SOAK_DURATION_S=600 RATE=15 node test/chaos/soak-and-chaos.mjs`).

### 1.5 Raft Consensus

**Done** — standalone 3-node proof-of-concept using PySyncObj, `raft-demo/` (not part of ArmourAPI's tested request-blocking pipeline — see `raft-demo/README.md` for the full scope rationale and results). A real, scripted run (`raft-demo/run_demo.py`) verified: leader election among all 3 nodes, a majority-quorum write submitted through a follower (correctly forwarded and committed), continued availability with only 2/3 nodes alive after killing the leader outright (new leader elected, term advanced, a further write still committed), and the killed node rejoining and catching up via log replication after restart.

No timing claims from this demo are comparable to the doc's clustered targets (5120-entry replicated log, 12ms heartbeat, 180ms election SLA, etc.) — those assume a mature, tuned, multi-node production implementation that a first working demo isn't.

---

*Sections for Phase 12's baseline-vs-protected attack-class results and the formal threat-mapping matrix are tracked separately (see `test/attack-corpus/README.md` for the informal version) and were deferred per the client's own prioritization at the time ("except documentation... verify and test that last feedback").*
