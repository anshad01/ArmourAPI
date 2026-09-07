import { setTimeout as delay } from 'node:timers/promises';

/**
 * Supplementary load harness, used only because k6 (the doc's chosen tool -
 * see test/load/k6/) isn't installed in this dev environment. Not a
 * replacement for it: this is a simple open-loop request fire-and-track
 * script, not k6's proper constant-arrival-rate executor, and has no
 * distributed-load capability. Good enough to get real numbers today rather
 * than none.
 *
 * Targets /app/bench (Juice Shop passthrough - not running, so every request
 * 500s after the WAF scan completes). That's fine for what this measures:
 * armourapi_request_latency_ms is captured purely around the blocklist/rate-
 * limit/WAF scan phase in the preHandler, before the proxy even attempts to
 * reach the upstream - it's ArmourAPI's own added latency (NFR1), unaffected
 * by whether the real backend is reachable. The CLIENT-observed latency
 * printed below is a different, noisier number: it also includes the time
 * spent waiting for the failed upstream connection to time out, which has
 * nothing to do with ArmourAPI's own overhead. Read the server-side section,
 * not the client-side section, for anything resembling an NFR1 answer.
 *
 * Run: node test/load/node-bench.mjs
 * Env: BASE_URL, RATE (req/s), DURATION_S, PAYLOAD_KB, PATH_OVERRIDE
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const RATE = Number(process.env.RATE || 100);
const DURATION_S = Number(process.env.DURATION_S || 15);
const PAYLOAD_KB = Number(process.env.PAYLOAD_KB || 3);
const PATH = process.env.PATH_OVERRIDE || '/app/bench';

const payload = JSON.stringify({ padding: 'x'.repeat(PAYLOAD_KB * 1024) });
const intervalMs = 1000 / RATE;

const latencies = [];
let sent = 0;
let completed = 0;
let errors = 0;

async function fireOne() {
  sent++;
  const start = process.hrtime.bigint();
  try {
    const res = await fetch(`${BASE_URL}${PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
    });
    await res.arrayBuffer(); // drain the body so the connection can be reused
    latencies.push(Number(process.hrtime.bigint() - start) / 1e6);
    completed++;
  } catch {
    errors++;
  }
}

function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function readMetric(text, name) {
  const line = text.split('\n').find((l) => l.startsWith(`${name} `));
  return line ? line.split(' ')[1] : null;
}

function readHistogramApproxQuantiles(text, name) {
  const buckets = [];
  const pattern = new RegExp(`^${name}_bucket\\{[^}]*le="([^"]+)"[^}]*\\}\\s+(\\d+)`);
  for (const line of text.split('\n')) {
    const m = pattern.exec(line);
    if (m) buckets.push({ le: m[1] === '+Inf' ? Infinity : Number(m[1]), count: Number(m[2]) });
  }
  if (buckets.length === 0) return null;
  buckets.sort((a, b) => a.le - b.le);
  const total = buckets[buckets.length - 1].count;
  const quantile = (p) => {
    const target = p * total;
    const hit = buckets.find((b) => b.count >= target);
    return hit ? hit.le : null;
  };
  return { total, p50: quantile(0.5), p95: quantile(0.95), p99: quantile(0.99) };
}

const beforeMetrics = await (await fetch(`${BASE_URL}/api/v1/security/metrics`)).text();
const cpuBefore = Number(readMetric(beforeMetrics, 'process_cpu_user_seconds_total'));

console.log(`Firing ~${RATE} req/s for ${DURATION_S}s at ${PATH} (${PAYLOAD_KB}KB payload)...`);
const wallClockStart = Date.now();
const endAt = wallClockStart + DURATION_S * 1000;
const inFlight = [];
while (Date.now() < endAt) {
  inFlight.push(fireOne());
  await delay(intervalMs);
}
await Promise.allSettled(inFlight);

const sorted = [...latencies].sort((a, b) => a - b);
console.log('\n--- Client-observed (wall clock - includes the failed-upstream-connection wait, NOT a clean ArmourAPI-overhead number) ---');
console.log(`sent: ${sent}, completed: ${completed}, errors: ${errors}`);
console.log(
  `p50: ${percentile(sorted, 50)?.toFixed(2)}ms  p95: ${percentile(sorted, 95)?.toFixed(2)}ms  p99: ${percentile(sorted, 99)?.toFixed(2)}ms`,
);
console.log(`actual achieved throughput: ${(completed / DURATION_S).toFixed(1)} req/s`);

const wallClockSeconds = (Date.now() - wallClockStart) / 1000;
const metricsRes = await fetch(`${BASE_URL}/api/v1/security/metrics`);
const metricsText = await metricsRes.text();
const cpuAfter = Number(readMetric(metricsText, 'process_cpu_user_seconds_total'));
const cpuPercent = ((cpuAfter - cpuBefore) / wallClockSeconds) * 100;

console.log('\n--- ArmourAPI server-side metrics (this IS the NFR1/NFR2 number) ---');
console.log(
  `CPU: ${cpuPercent.toFixed(1)}% of one core (user CPU-seconds consumed during the run / wall-clock duration)`,
);
console.log(
  `RAM (RSS): ${(Number(readMetric(metricsText, 'process_resident_memory_bytes')) / 1024 / 1024).toFixed(1)} MB`,
);
const hist = readHistogramApproxQuantiles(metricsText, 'armourapi_request_latency_ms');
if (hist) {
  console.log(
    `armourapi_request_latency_ms (${hist.total} observations, cumulative-bucket approximation): p50<=${hist.p50}ms p95<=${hist.p95}ms p99<=${hist.p99}ms`,
  );
} else {
  console.log('armourapi_request_latency_ms: no data returned');
}
