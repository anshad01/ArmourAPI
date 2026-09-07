import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import websocket from '@fastify/websocket';
import { config } from './config.js';
import { logger } from './logging/logger.js';
import { createWafAdapter } from './waf/adapter.js';
import { registerProxyRoutes } from './proxy/routes.js';
import { registerSecurityApi } from './security-api/routes.js';
import { registerAuthApi } from './auth/routes.js';
import { hardenCookiesOnSend } from './auth/session-hooks.js';
import { registerDemoPage } from './demo/routes.js';

const fastify = Fastify({ loggerInstance: logger });

await fastify.register(helmet);
await fastify.register(websocket);

// FR6: hardens Set-Cookie headers on every response regardless of route -
// upstreams (Juice Shop et al.) don't necessarily set Secure/HttpOnly/
// SameSite on their own cookies.
fastify.addHook('onSend', hardenCookiesOnSend);

fastify.get('/healthz', async () => ({ status: 'ok' }));

// FR9: WAF_ENGINE env var swaps engines without touching the pipeline (default: coraza).
const wafAdapter = await createWafAdapter();
logger.info(`WAF engine: ${wafAdapter.name}`);

await registerSecurityApi(fastify);
await registerAuthApi(fastify);
await registerDemoPage(fastify);
await registerProxyRoutes(fastify, { adapter: wafAdapter });

async function shutdown(signal) {
  logger.info(`${signal} received, shutting down`);
  await fastify.close();
  await wafAdapter.close?.();
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

try {
  await fastify.listen({ port: config.port, host: '0.0.0.0' });
  logger.info(`ArmourAPI listening on :${config.port}`);
} catch (err) {
  logger.error(err);
  process.exit(1);
}
