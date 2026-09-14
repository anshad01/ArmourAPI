# Raft Consensus — Standalone Proof-of-Concept (Phase 13.5)

## What this is, and what it isn't

`Parameters.rtf.doc`'s "Inclusion of Raft Consensus" section describes maintaining "a single synchronised leader and replicated log across all gateway nodes for authoritative policy decisions" — a real distributed-systems feature for a multi-node ArmourAPI deployment. That's a genuinely different tier of engineering than this project's current single-process, single-machine architecture, and scope was explicitly discussed and confirmed with the client before building anything:

- **Standalone and decoupled** — this demo is not imported by, or wired into, ArmourAPI's tested request-blocking pipeline (`src/`). Nothing in `src/` depends on anything in this directory. It's a proof-of-concept of the consensus layer itself, documenting the target architecture for a possible future clustered deployment.
- **3 nodes, not the doc's 5** — client's explicit instruction, sized for one dev machine rather than a multi-AZ mesh.
- **PySyncObj (Python), not `hashicorp/raft` (Go)** — chosen after checking the environment: Go isn't installed on this machine at all (a new toolchain, comparable setup cost to the Android SDK install in Phase 12.4), while Python 3.12 is already installed and used successfully all project. PySyncObj is a single `pip install` with a much smaller API surface than `hashicorp/raft`'s (which requires hand-implementing a full FSM/transport/snapshot interface) — the right tradeoff for a correctness-focused demo, not a production system.

**No timing claims from this demo are comparable to the doc's clustered targets** (5120-entry replicated log, 12ms heartbeat, 180ms election SLA, <0.45ms bloom sync window, etc.) — those assume a mature, tuned, multi-node production implementation running on real network links between separate machines, not a first working demo of 3 processes on localhost.

## What's replicated

A toy blocklist — a set of "blocked IP" strings — the same shape of data as the real `src/rate-limiter/blocklist.js`'s `block()`/`isBlocked()`, just replicated via Raft log consensus instead of Redis. This is a stand-in for what a real clustered ArmourAPI deployment would actually need to keep consistent across nodes (revocations, blocklist entries), not a literal port of the JS module.

## Files

- `blocklist_node.py` — one Raft node. Run as `python blocklist_node.py <0|1|2>`. Each of the 3 nodes binds a Raft port (4321-4323) and a small local HTTP control API (8321-8323, not part of Raft itself) with:
  - `GET /status` — Raft state (follower/candidate/leader), current leader, term, quorum, log length
  - `GET /blocklist` — this node's locally-applied state (a local read, same as the real `isBlocked()`)
  - `POST /block {"ip": "..."}` — submit a replicated write (`sync=True`, so it blocks until committed or times out)
- `run_demo.py` — scripted, repeatable version of the full verification: spawns all 3 nodes, waits for election, writes through a follower, kills the leader, confirms re-election and continued availability with 2/3 nodes, restarts the killed node, confirms it catches up. Run: `python run_demo.py` (needs `pip install pysyncobj`).

## What was actually verified (this machine, 2026-09-14)

Real output from `python run_demo.py` — not simulated, not hand-edited:

1. **Leader election**: all 3 nodes agree on the same leader and term within ~1-2s of startup (`localhost:4322` elected leader, term 1, both other nodes FOLLOWER with `has_quorum: true`).
2. **Majority-quorum write via a follower**: `block_ip("10.0.0.5")` submitted directly to a *follower's* HTTP API — PySyncObj forwards it to the leader internally, commits it by majority, and it shows up correctly on all 3 nodes' local reads.
3. **Availability survives a node failure**: the leader process is killed outright (`SIGKILL`, not a graceful shutdown). The remaining 2 nodes detect the dead leader, elect a new one (term advances 1→3, confirming a real election happened, not a no-op), and correctly report `has_quorum: true` with only 2/3 nodes alive (2 is a majority of 3). A second write (`172.16.0.9`) submitted afterward still commits successfully and replicates to both survivors.
4. **Rejoin and catch-up**: the killed node is restarted as a fresh process (no local state carried over — this demo uses no journal/dump file). It rejoins the cluster, recognizes the current leader and term, and its local blocklist correctly ends up containing both previously-committed entries (`10.0.0.5` and `172.16.0.9`) via log replication from the leader, not from any persisted state of its own.

One earlier run of this exact script produced a misleading transcript (a write appeared to fail, and "fresh" nodes showed pre-existing state) — traced to a leftover process from an earlier *manual* verification session still holding the same ports, not a bug in the demo logic itself. Confirmed clean (`netstat`/`tasklist` showing no listeners on 4321-4323/8321-8323) before the run whose transcript is recorded above, and confirmed again that `run_demo.py`'s own `finally` block correctly killed all 3 of its child processes afterward with no leftovers.

## Relationship to a real clustered ArmourAPI

If ArmourAPI were ever deployed as an actual multi-node gateway cluster, this demo's pattern is roughly what the blocklist/token-revocation replication layer would look like: `block(type, value, ...)` and `revokeToken(jti, ...)` (currently Redis-backed with an in-memory fallback, see `src/rate-limiter/blocklist.js` and `src/auth/jwt.js`) would become `@replicated` methods on a `SyncObj` subclass instead, giving every gateway node the same view of blocklist/revocation state without a shared Redis instance as a single point of failure. That integration is explicitly **not** built here — it would require its own design pass (network topology, node discovery, failure-mode handling for the live traffic path) that's out of scope for a course-project proof-of-concept.
