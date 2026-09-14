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

// ARM-03 audit finding: with no bodyLimit set, an oversized payload reached
// Coraza's WASM transaction before anything rejected it cleanly, leaking its
// internal "memoryLimit reached while writing" error verbatim to the client.
// 2MB is comfortably above any real payload this gateway's routes expect.
const BODY_LIMIT_BYTES = 2 * 1024 * 1024;

const fastify = Fastify({ loggerInstance: logger, bodyLimit: BODY_LIMIT_BYTES });

fastify.setErrorHandler((err, request, reply) => {
  // FST_ERR_CTP_BODY_TOO_LARGE covers Fastify's own built-in body parsers;
  // ARMOURAPI_BODY_TOO_LARGE covers the proxied routes' raw-stream body,
  // which bypasses that parser entirely (see proxy/body-buffer.js) - both
  // need the same clean 413 instead of leaking an internal error message.
  if (err.code === 'FST_ERR_CTP_BODY_TOO_LARGE' || err.code === 'ARMOURAPI_BODY_TOO_LARGE') {
    reply.code(413).send({ error: 'payload too large', maxBytes: err.maxBytes ?? BODY_LIMIT_BYTES });
    return;
  }
  reply.send(err);
});

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

if (config.adminApiKey === 'change-me-admin-key') {
  logger.warn('ADMIN_API_KEY not set - using the insecure default. Set it before any real deployment.');
}

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
