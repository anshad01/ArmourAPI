// Bounded in-memory history of flagged (blocked) requests, backing
// GET /api/v1/security/threats ("a list of flagged suspicious requests,
// including anomaly scores and rule violations" per the doc). In-memory
// and per-instance is fine for a single-gateway demo/capstone deployment;
// a multi-instance deployment would move this to Redis/a real store.
const MAX_ENTRIES = 500;
const entries = [];
let nextId = 1;

export function recordThreat(event) {
  entries.push({ id: nextId++, timestamp: Date.now(), ...event });
  if (entries.length > MAX_ENTRIES) entries.shift();
}

export function listThreats({ limit = 100, category } = {}) {
  const filtered = category ? entries.filter((e) => e.category === category) : entries;
  return filtered.slice(-limit).reverse(); // most recent first
}
