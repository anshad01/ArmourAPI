import { setTimeout as delay } from 'node:timers/promises';

/**
 * Phase 13.4 (Parameters.rtf.doc's Memory/Latency Profiler tables): unlike
 * node-bench.mjs (single-route throughput/latency under load), this captures
 * two things the doc's tables ask for that node-bench.mjs doesn't: latency
 * broken out PER SCANNER STAGE (fast-filter/blocklist/rate-limiter/coraza/
 * graphql-guard/schema-guard/token-guard - via the new `scanner` label on
 * armourapi_request_latency_ms, metrics/registry.js), and a real memory-per-
 * intercepted-request figure (RSS delta over a fixed request count).
 *
 * Same honesty rule as every prior phase's benchmarking: report what this
 * machine actually measures, explicitly marked met/not met/not comparable
 * against the doc's target column - never substitute the target for a
 * measurement that wasn't taken.
 *
 * Run: node test/load/profiler.mjs
 * Env: BASE_URL, REQUEST_COUNT
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const REQUEST_COUNT = Number(process.env.REQUEST_COUNT || 500);

function readMetric(text, name) {
  const line = text.split('\n').find((l) => l.startsWith(`${name} `));
  return line ? Number(line.split(' ')[1]) : null;
}

// Per-scanner histograms: armourapi_request_latency_ms_bucket{route="...",scanner="fast-filter",le="1"} 42
function readPerScannerQuantiles(text, name) {
  const series = new Map(); // scanner -> [{le, count}]
  const pattern = new RegExp(`^${name}_bucket\\{([^}]*)\\}\\s+(\\d+)`);
  for (const line of text.split('\n')) {
    const m = pattern.exec(line);
    if (!m) continue;
    const labels = Object.fromEntries(
      [...m[1].matchAll(/(\w+)="([^"]*)"/g)].map(([, k, v]) => [k, v]),
    );
    const scanner = labels.scanner || 'unknown';
    const le = labels.le === '+Inf' ? Infinity : Number(labels.le);
    if (!series.has(scanner)) series.set(scanner, []);
    series.get(scanner).push({ le, count: Number(m[2]) });
  }
  const result = {};
  for (const [scanner, buckets] of series) {
    buckets.sort((a, b) => a.le - b.le);
    const total = buckets[buckets.length - 1].count;
    const quantile = (p) => {
      const target = p * total;
      const hit = buckets.find((b) => b.count >= target);
      return hit ? hit.le : null;
    };
    result[scanner] = { total, p50: quantile(0.5), p95: quantile(0.95), p99: quantile(0.99) };
  }
  return result;
}

async function fireMixedTraffic(count) {
  const requests = [];
  for (let i = 0; i < count; i++) {
    // Cycle through routes so every scanner in every chain gets exercised:
    // /app -> fast-filter+blocklist+rate-limiter+coraza (allow path)
    // /graphql -> + graphql-guard
    // /api/v1/products -> + schema-guard(no-op)+token-guard(no-op, public route)
    const mod = i % 3;
    if (mod === 0) {
      requests.push(fetch(`${BASE_URL}/app/rest/products`).catch(() => {}));
    } else if (mod === 1) {
      requests.push(
        fetch(`${BASE_URL}/graphql`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: '{ __typename }' }),
        }).catch(() => {}),
      );
    } else {
      requests.push(fetch(`${BASE_URL}/api/v1/products`).catch(() => {}));
    }
    if (requests.length % 20 === 0) await Promise.allSettled(requests.splice(0, requests.length));
  }
  await Promise.allSettled(requests);
}

console.log(`Firing ${REQUEST_COUNT} mixed requests at ${BASE_URL} (allow-path traffic, no attacks)...\n`);

const beforeMetrics = await (await fetch(`${BASE_URL}/api/v1/security/metrics`)).text();
const rssBefore = readMetric(beforeMetrics, 'process_resident_memory_bytes');
const totalMemBytes = readMetric(beforeMetrics, 'system_total_memory_bytes');

await fireMixedTraffic(REQUEST_COUNT);
// Let GC settle before sampling RSS - a burst leaves short-lived garbage that
// hasn't been collected yet, which would overstate the per-request figure.
await delay(500);

const afterMetrics = await (await fetch(`${BASE_URL}/api/v1/security/metrics`)).text();
const rssAfter = readMetric(afterMetrics, 'process_resident_memory_bytes');
const perScanner = readPerScannerQuantiles(afterMetrics, 'armourapi_request_latency_ms');

const rssDeltaBytes = rssAfter - rssBefore;
const perRequestKB = rssDeltaBytes / 1024 / REQUEST_COUNT;

console.log('=== Memory ===');
console.log(`RSS before: ${(rssBefore / 1024 / 1024).toFixed(1)} MB`);
console.log(`RSS after:  ${(rssAfter / 1024 / 1024).toFixed(1)} MB`);
console.log(`RSS delta over ${REQUEST_COUNT} requests: ${(rssDeltaBytes / 1024).toFixed(1)} KB`);
console.log(
  `Memory per intercepted request (RSS delta / count): ${perRequestKB.toFixed(2)} KB  ` +
    `[doc target: <100 KB SLA - can go negative if GC reclaimed more than the burst allocated, which is a real, valid outcome for allow-path traffic that allocates almost nothing long-lived]`,
);
console.log(
  `RAM relative to host capacity: ${((rssAfter / totalMemBytes) * 100).toFixed(2)}% of ${(totalMemBytes / 1024 / 1024 / 1024).toFixed(1)}GB total\n`,
);

console.log('=== Per-scanner-stage latency (armourapi_request_latency_ms, cumulative-bucket approximation) ===');
for (const [scanner, q] of Object.entries(perScanner)) {
  console.log(`${scanner.padEnd(20)} n=${String(q.total).padEnd(6)} p50<=${q.p50}ms  p95<=${q.p95}ms  p99<=${q.p99}ms`);
}

console.log('\nDone. See docs/validation-test-report.md for this run compared against the doc\'s target figures.');
