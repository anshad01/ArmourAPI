import os from 'node:os';
import client from 'prom-client';

export const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry });

// Client feedback (2026-08-31): CPU/RAM should read relative to the host's
// total capacity, not as raw MB or % of one core - "that's the whole
// objective of our app - LIGHTWEIGHT". These two are static per machine, so
// they're set once at startup rather than recomputed per scrape; Grafana
// divides process_resident_memory_bytes / process_cpu_user_seconds_total
// (both from collectDefaultMetrics above) by these to get host-relative %.
const systemTotalMemoryBytes = new client.Gauge({
  name: 'system_total_memory_bytes',
  help: 'Total physical RAM on this host, for computing ArmourAPI RAM usage relative to host capacity',
  registers: [registry],
});
systemTotalMemoryBytes.set(os.totalmem());

const systemCpuCount = new client.Gauge({
  name: 'system_cpu_count',
  help: 'Logical CPU core count on this host, for computing ArmourAPI CPU usage relative to host capacity',
  registers: [registry],
});
systemCpuCount.set(os.cpus().length);

export const requestCounter = new client.Counter({
  name: 'armourapi_requests_total',
  help: 'Total requests seen by ArmourAPI',
  labelNames: ['route', 'decision'],
  registers: [registry],
});

export const blockedCounter = new client.Counter({
  name: 'armourapi_blocked_total',
  help: 'Total requests blocked by ArmourAPI, by attack category',
  labelNames: ['category'],
  registers: [registry],
});

export const requestLatency = new client.Histogram({
  name: 'armourapi_request_latency_ms',
  help: 'Request latency added by ArmourAPI in milliseconds',
  // "scanner" (13.4, Parameters.rtf.doc's per-stage Latency Profiler ask):
  // createGatePreHandler observes once per scanner in the chain already, so
  // labeling by which one (fast-filter/blocklist/rate-limiter/coraza/...)
  // costs nothing new to collect - it was already being thrown away.
  labelNames: ['route', 'scanner'],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 5, 10, 25, 50, 100, 250, 500],
  registers: [registry],
});
