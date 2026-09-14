import { config } from '../config.js';
import { registry } from '../metrics/registry.js';
import { block, listMemoryBlocklist } from '../rate-limiter/blocklist.js';
import { listThreats } from './threat-store.js';
import { subscribeTraffic } from './traffic-bus.js';

// ARM-01 audit finding: these three routes had no authentication at all -
// any anonymous caller could write arbitrary blocklist entries (a real DoS
// against legitimate IPs/accounts) or read live threat/traffic data. A
// shared-secret header is enough for this project's scope; a WebSocket
// handshake can't carry a custom header from browser JS, so the traffic feed
// also accepts the key as a query param.
function isAuthorized(request) {
  const key = request.headers['x-admin-key'] ?? request.query?.key;
  return key === config.adminApiKey;
}

function requireAdminKey(request, reply, done) {
  if (!isAuthorized(request)) {
    reply.code(401).send({ error: 'unauthorized', reason: 'missing or invalid X-Admin-Key' });
    return;
  }
  done();
}

// ArmourAPI's own admin/security API (registered as static routes, so they take
// precedence over the /api/v1/* proxy wildcard even though they share the prefix).
export async function registerSecurityApi(fastify) {
  // Left open: this is the Prometheus scrape target, conventionally trusted
  // at the network layer rather than gated per-request, and it carries no
  // write capability or per-request attack detail the way the other three do.
  fastify.get('/api/v1/security/metrics', async (_req, reply) => {
    reply.type(registry.contentType).send(await registry.metrics());
  });

  // "A list of flagged suspicious requests, including anomaly scores and
  // rule violations" - backed by threat-store.js, populated by every block
  // decision in proxy/routes.js's createGatePreHandler.
  fastify.get('/api/v1/security/threats', { preHandler: requireAdminKey }, async (request) => {
    const limit = request.query?.limit ? Number(request.query.limit) : undefined;
    const category = request.query?.category;
    return {
      threats: listThreats({ limit, category }),
      blocklisted: listMemoryBlocklist(),
    };
  });

  fastify.post('/api/v1/security/blocklist', { preHandler: requireAdminKey }, async (request, reply) => {
    const { ip, userId, reason } = request.body ?? {};
    if (!ip && !userId) {
      return reply.code(400).send({ error: 'ip or userId required' });
    }
    if (ip) await block('ip', ip, { reason: reason || 'manual' });
    if (userId) await block('account', userId, { reason: reason || 'manual' });
    return { blocklisted: { ip, userId, reason } };
  });

  // "Feeds the live-stream traffic map ... useful for demoing" - every
  // allow/block decision from proxy/routes.js is pushed here in real time.
  // preHandler still runs on the initial HTTP upgrade request before the
  // socket is handed off, so an unauthorized caller never gets upgraded.
  fastify.get('/api/v1/security/traffic', { websocket: true, preHandler: requireAdminKey }, (socket) => {
    const unsubscribe = subscribeTraffic((event) => {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(event));
      }
    });
    socket.on('close', unsubscribe);
  });
}
