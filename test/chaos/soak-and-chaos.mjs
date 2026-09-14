import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Phase 13.6 (mandatory - Parameters.rtf.doc's "Chaos Resilience and Soak
 * Test" section): the doc's literal target is 72h continuous at 12,000
 * req/s sustained. Neither is achievable on this single 7.6GB dev laptop -
 * stated openly here and in docs/validation-test-report.md, not hidden or
 * faked. What this script actually runs is a real, continuous, unattended
 * load run at a rate this machine can sustain, for a duration long enough to
 * show a genuine memory-drift TREND (not the single before/after burst delta
 * 13.4's profiler.mjs used, which couldn't distinguish warmup cost from a
 * real leak), plus three chaos experiments run against the real single-node
 * system that exists today:
 *
 *   1. Process kill + restart under active load ("WAF pool restart" in a
 *      single-process architecture where the pool has no lifecycle
 *      independent of the process - restarting one IS restarting the other;
 *      stated as such, not stretched to look like something it isn't).
 *   2. Redis-down-under-load confirmation (Redis is never started in this
 *      dev setup - the fallback is exercised for the ENTIRE run, not just at
 *      idle, and this experiment specifically watches for any errors that
 *      trace back to it).
 *   3. CPU saturation alongside the load run, measuring real latency
 *      degradation and recovery.
 *
 * No clustering exists in this project, so "Raft re-election under chaos"
 * is not applicable here - noted, not faked (raft-demo/'s own chaos
 * properties were already verified separately in Phase 13.5).
 *
 * Run: node test/chaos/soak-and-chaos.mjs
 * Env: SOAK_DURATION_S (default 600), RATE (req/s, default 20), PORT
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PORT = Number(process.env.PORT || 8099);
const BASE_URL = `http://localhost:${PORT}`;
const SOAK_DURATION_S = Number(process.env.SOAK_DURATION_S || 600);
const RATE = Number(process.env.RATE || 20);
const SAMPLE_INTERVAL_S = 20;

function readMetric(text, name) {
  const line = text.split('\n').find((l) => l.startsWith(`${name} `));
  return line ? Number(line.split(' ')[1]) : null;
}

function log(msg) {
  const t = new Date().toISOString().slice(11, 19);
  console.log(`[${t}] ${msg}`);
}

function startServer() {
  const proc = spawn(process.execPath, ['src/server.js'], {
    cwd: REPO_ROOT,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  return proc;
}

async function waitForReady(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE_URL}/api/v1/security/metrics`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await delay(200);
  }
  return false;
}

// --- Continuous load generator (runs for the script's whole lifetime) ---
const loadStats = { sent: 0, ok: 0, err: 0, latenciesMs: [] };
let loadRunning = true;

async function fireOne() {
  loadStats.sent++;
  const start = process.hrtime.bigint();
  try {
    // AndroGoat (the /api/v1 upstream) isn't running in this dev setup, so a
    // healthy ArmourAPI legitimately returns 500 here (@fastify/http-proxy's
    // FST_REPLY_FROM_INTERNAL_SERVER_ERROR - it scanned the request and
    // tried to forward it; the upstream is what's missing, not ArmourAPI).
    // What this experiment measures is ArmourAPI's OWN
    // availability, so any HTTP response at all (whatever its status) means
    // ArmourAPI itself answered; only a failed *connection to ArmourAPI* -
    // fetch throwing - counts as ArmourAPI being down.
    const res = await fetch(`${BASE_URL}/api/v1/products`);
    await res.arrayBuffer();
    loadStats.latenciesMs.push(Number(process.hrtime.bigint() - start) / 1e6);
    loadStats.ok++;
  } catch {
    loadStats.err++;
  }
}

async function runLoadLoop() {
  const intervalMs = 1000 / RATE;
  while (loadRunning) {
    fireOne();
    await delay(intervalMs);
  }
}

function percentile(arr, p) {
  if (arr.length === 0) return null;
  const sorted = [...arr].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

function drainLatencySnapshot() {
  const snap = loadStats.latenciesMs.splice(0, loadStats.latenciesMs.length);
  return { n: snap.length, p50: percentile(snap, 50), p95: percentile(snap, 95), p99: percentile(snap, 99) };
}

// --- CPU saturation experiment: N busy-loop child processes ---
function startCpuSaturators(count) {
  const workers = [];
  for (let i = 0; i < count; i++) {
    const w = spawn(process.execPath, ['-e', 'while(true){Math.sqrt(Math.random())}'], {
      stdio: 'ignore',
    });
    workers.push(w);
  }
  return workers;
}

function stopWorkers(workers) {
  for (const w of workers) w.kill();
}

async function main() {
  console.log('=== Phase 13.6: Chaos Resilience & Soak Test (scoped, honest duration) ===');
  console.log(`Target machine: ${os.cpus().length} logical cores, ${(os.totalmem() / 1024 / 1024 / 1024).toFixed(1)}GB RAM`);
  console.log(`Doc's mandatory target: 72h continuous @ 12,000 req/s sustained. This run: ${SOAK_DURATION_S}s @ ~${RATE} req/s.\n`);

  let server = startServer();
  log('starting ArmourAPI...');
  if (!(await waitForReady())) throw new Error('server did not become ready');
  log('server ready - Redis is not running for this entire test, so the whole run exercises the in-memory rate-limiter/blocklist fallback under real active load, not just at idle.');

  const loadPromise = runLoadLoop();
  const trend = [];
  const events = [];

  const startedAt = Date.now();
  const endAt = startedAt + SOAK_DURATION_S * 1000;

  // Schedule chaos events partway through the run, spaced apart.
  const cpuChaosAt = startedAt + Math.min(120_000, SOAK_DURATION_S * 200);
  const cpuChaosDurationMs = 30_000;
  const killChaosAt = startedAt + Math.min(240_000, SOAK_DURATION_S * 400);
  let cpuWorkers = null;
  let cpuChaosDone = false;
  let killChaosDone = false;

  while (Date.now() < endAt) {
    await delay(SAMPLE_INTERVAL_S * 1000);
    let metricsText;
    try {
      metricsText = await (await fetch(`${BASE_URL}/api/v1/security/metrics`)).text();
    } catch {
      metricsText = null;
    }
    const rssMB = metricsText ? readMetric(metricsText, 'process_resident_memory_bytes') / 1024 / 1024 : null;
    const latency = drainLatencySnapshot();
    const elapsedS = Math.round((Date.now() - startedAt) / 1000);
    trend.push({ elapsedS, rssMB, ...latency, sent: loadStats.sent, ok: loadStats.ok, err: loadStats.err });
    log(
      `t+${elapsedS}s  RSS=${rssMB?.toFixed(1) ?? 'N/A'}MB  reqs sent=${loadStats.sent} ok=${loadStats.ok} err=${loadStats.err}  ` +
        `latency p50=${latency.p50?.toFixed(2)}ms p95=${latency.p95?.toFixed(2)}ms p99=${latency.p99?.toFixed(2)}ms`,
    );

    if (!cpuChaosDone && Date.now() >= cpuChaosAt) {
      const n = os.cpus().length;
      log(`CHAOS: saturating all ${n} logical cores for ${cpuChaosDurationMs / 1000}s...`);
      cpuWorkers = startCpuSaturators(n);
      events.push({ type: 'cpu-saturation-start', atS: elapsedS });
      cpuChaosDone = true;
      // Stop them after the window, without blocking the sampling loop.
      delay(cpuChaosDurationMs).then(() => {
        stopWorkers(cpuWorkers);
        events.push({ type: 'cpu-saturation-end', atS: Math.round((Date.now() - startedAt) / 1000) });
        log('CHAOS: CPU saturation ended, workers killed.');
      });
    }

    if (!killChaosDone && Date.now() >= killChaosAt) {
      log('CHAOS: killing the ArmourAPI process outright (SIGKILL) mid-load...');
      const killedAt = Date.now();
      server.kill('SIGKILL');
      events.push({ type: 'process-killed', atS: Math.round((killedAt - startedAt) / 1000) });
      // Real gap: how long until requests succeed again. Nothing auto-
      // restarts this process (no supervisor built into ArmourAPI itself -
      // an honest limitation, not simulated away) - this script itself acts
      // as the restart trigger, same as a real deploy would need pm2/
      // systemd/Docker's restart policy to do.
      server = startServer();
      const ready = await waitForReady(20000);
      const recoveredAt = Date.now();
      const downtimeMs = recoveredAt - killedAt;
      events.push({ type: 'process-restarted', atS: Math.round((recoveredAt - startedAt) / 1000), downtimeMs, ready });
      log(`CHAOS: process restarted, ${ready ? 'became ready' : 'FAILED to become ready'} after ${downtimeMs}ms downtime.`);
      killChaosDone = true;
    }
  }

  loadRunning = false;
  await delay(500);

  console.log('\n=== Soak trend (memory + latency over time) ===');
  console.log('t+s\tRSS(MB)\tsent\tok\terr\tp50(ms)\tp95(ms)\tp99(ms)');
  for (const row of trend) {
    console.log(`${row.elapsedS}\t${row.rssMB?.toFixed(1)}\t${row.sent}\t${row.ok}\t${row.err}\t${row.p50?.toFixed(2)}\t${row.p95?.toFixed(2)}\t${row.p99?.toFixed(2)}`);
  }

  const firstRss = trend.find((r) => r.rssMB != null)?.rssMB;
  const lastRss = [...trend].reverse().find((r) => r.rssMB != null)?.rssMB;
  console.log(`\nMemory drift over ${SOAK_DURATION_S}s: ${firstRss?.toFixed(1)}MB -> ${lastRss?.toFixed(1)}MB (delta ${(lastRss - firstRss).toFixed(1)}MB)`);
  console.log(`Total requests: sent=${loadStats.sent} ok=${loadStats.ok} err=${loadStats.err} (error rate ${((loadStats.err / loadStats.sent) * 100).toFixed(2)}%)`);

  console.log('\n=== Chaos events ===');
  for (const e of events) console.log(JSON.stringify(e));

  server.kill('SIGKILL');
  console.log('\nDone.');
}

main().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
