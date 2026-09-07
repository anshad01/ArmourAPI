import { registry } from '../metrics/registry.js';
import { block, listMemoryBlocklist } from '../rate-limiter/blocklist.js';
import { listThreats } from './threat-store.js';
import { subscribeTraffic } from './traffic-bus.js';

// ArmourAPI's own admin/security API (registered as static routes, so they take
// precedence over the /api/v1/* proxy wildcard even though they share the prefix).
export async function registerSecurityApi(fastify) {
  fastify.get('/api/v1/security/metrics', async (_req, reply) => {
    reply.type(registry.contentType).send(await registry.metrics());
  });

  // "A list of flagged suspicious requests, including anomaly scores and
  // rule violations" - backed by threat-store.js, populated by every block
  // decision in proxy/routes.js's createGatePreHandler.
  fastify.get('/api/v1/security/threats', async (request) => {
    const limit = request.query?.limit ? Number(request.query.limit) : undefined;
    const category = request.query?.category;
    return {
      threats: listThreats({ limit, category }),
      blocklisted: listMemoryBlocklist(),
    };
  });

  fastify.post('/api/v1/security/blocklist', async (request, reply) => {
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
  fastify.get('/api/v1/security/traffic', { websocket: true }, (socket) => {
    const unsubscribe = subscribeTraffic((event) => {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(event));
      }
    });
    socket.on('close', unsubscribe);
  });
}
