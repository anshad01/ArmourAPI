import httpProxy from '@fastify/http-proxy';
import { config } from '../config.js';
import { logDecision } from '../logging/logger.js';
import { requestCounter, blockedCounter, requestLatency } from '../metrics/registry.js';
import { createGraphqlGuard } from '../graphql-guard/index.js';
import {
  createBlocklistGuard,
  createGlobalRateLimitGuard,
  createLoginGuard,
  recordLoginOutcome,
} from '../rate-limiter/index.js';
import { createSchemaGuard } from '../validation/index.js';
import { createTokenGuard } from '../auth/token-guard.js';
import { createFastFilter } from '../waf/fast-filter.js';
import { attachSessionOnLoginSuccess } from '../auth/session-hooks.js';
import { recordThreat } from '../security-api/threat-store.js';
import { publishTraffic } from '../security-api/traffic-bus.js';

// FR1: intercept all traffic via reverse proxy before it reaches app logic.
// Path routing per the doc: /app/* -> Juice Shop, /graphql/* -> DVGA, /api/v1/* -> AndroGoat/POS backend.
//
// Any scanner (WAF adapter, GraphQL guard, rate limiter, ...) implements
// scan(request) -> { allow, category?, reason? } and gets wrapped into a
// preHandler here, so multiple scanners chain on the same route. Cheap
// checks (blocklist, rate limit) run before expensive ones (WAF transaction).
function createGatePreHandler(scanner) {
  return async function preHandler(request, reply) {
    const start = process.hrtime.bigint();
    const result = await scanner.scan(request);
    const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;

    requestLatency.observe({ route: request.routeOptions?.url || request.url, scanner: scanner.name }, latencyMs);

    if (!result.allow) {
      requestCounter.inc({ route: request.url, decision: 'block' });
      blockedCounter.inc({ category: result.category || 'unknown' });
      logDecision({
        ip: request.ip,
        method: request.method,
        url: request.url,
        decision: 'block',
        category: result.category,
        latencyMs,
        scanner: scanner.name,
      });
      // Phase 9: GET /security/threats history + the live traffic feed.
      recordThreat({
        ip: request.ip,
        method: request.method,
        url: request.url,
        category: result.category,
        reason: result.reason,
        anomalyScore: result.anomalyScore ?? null,
        scanner: scanner.name,
        latencyMs,
      });
      publishTraffic({
        ip: request.ip,
        method: request.method,
        url: request.url,
        decision: 'block',
        category: result.category,
        scanner: scanner.name,
        latencyMs,
      });
      // Distinguishes "ArmourAPI rejected this before it reached the
      // upstream" from a real 401/403 the upstream itself returned, so
      // recordLoginOutcome doesn't double-count a blocklist rejection as
      // another credential-stuffing failure and escalate the block forever.
      request.armourapiBlockedByGate = true;
      reply.code(403).send({ error: 'blocked', category: result.category, reason: result.reason });
      return;
    }

    // Only log/count the final "allow" once the whole chain passes, not per
    // scanner - otherwise one allowed request logs N times for N scanners.
    if (scanner.isLast) {
      requestCounter.inc({ route: request.url, decision: 'allow' });
      logDecision({
        ip: request.ip,
        method: request.method,
        url: request.url,
        decision: 'allow',
        latencyMs,
        scanner: scanner.name,
      });
      publishTraffic({
        ip: request.ip,
        method: request.method,
        url: request.url,
        decision: 'allow',
        scanner: scanner.name,
        latencyMs,
      });
    }
  };
}

function chain(...scanners) {
  scanners[scanners.length - 1].isLast = true;
  return scanners.map(createGatePreHandler);
}

export async function registerProxyRoutes(fastify, { adapter }) {
  // "Mode 1: Fast Inline Drop" (Parameters.rtf.doc) - runs first, ahead of
  // even the blocklist check, matching the doc's own pipeline order
  // (ingestion -> fast-path regex -> deeper stages). Catches only
  // near-certain attack signatures, so it never spends a Coraza transaction
  // on the obvious cases.
  const fastFilter = createFastFilter();
  const blocklistGuard = createBlocklistGuard();
  const rateLimitGuard = createGlobalRateLimitGuard();
  const graphqlGuard = createGraphqlGuard();
  const loginGuard = createLoginGuard();
  const schemaGuard = createSchemaGuard();
  const tokenGuard = createTokenGuard();

  await fastify.register(httpProxy, {
    upstream: config.targets.juiceShop,
    prefix: '/app',
    preHandler: chain(fastFilter, blocklistGuard, rateLimitGuard, adapter),
  });

  await fastify.register(httpProxy, {
    upstream: config.targets.dvga,
    prefix: '/graphql',
    // FR3 checks run before the generic WAF scan, so a malformed/oversized
    // query is rejected cheaply without spending a WAF transaction on it.
    preHandler: chain(fastFilter, blocklistGuard, rateLimitGuard, graphqlGuard, adapter),
  });

  // Registered ahead of the general /api/v1 prefix below so the login-
  // specific chain + onResponse tracker apply to this one endpoint; Fastify
  // routes by specificity regardless of registration order, but keeping the
  // narrower route first here mirrors that for readability.
  await fastify.register(async (instance) => {
    instance.addHook('onResponse', recordLoginOutcome);
    // FR6: mints ArmourAPI's own short-lived session on a successful login,
    // on top of whatever the upstream's own response looks like.
    instance.addHook('onSend', attachSessionOnLoginSuccess);
    await instance.register(httpProxy, {
      upstream: config.targets.androgoat,
      prefix: '/api/v1/auth/login',
      // FR5 runs before loginGuard/WAF: reject a malformed/injected login
      // body cheaply before spending a WAF transaction or touching the
      // credential-stuffing counters.
      preHandler: chain(fastFilter, blocklistGuard, rateLimitGuard, schemaGuard, loginGuard, adapter),
    });
  });

  await fastify.register(httpProxy, {
    upstream: config.targets.androgoat,
    prefix: '/api/v1',
    // FR6 (auth) runs before FR5 (schema) - standard gateway ordering is
    // authenticate first, then validate payload shape, then WAF-scan
    // content. tokenGuard/schemaGuard both no-op (allow: true) on paths
    // they don't have a rule for, so /products stays public.
    preHandler: chain(fastFilter, blocklistGuard, rateLimitGuard, tokenGuard, schemaGuard, adapter),
  });
}
