import { demoPageHtml } from './page.js';

export async function registerDemoPage(fastify) {
  // helmet's default CSP blocks the page's inline <script> (its trigger
  // buttons) - this is a local presenter aid, not a proxied/security-
  // sensitive route, so CSP is relaxed just here rather than weakened
  // globally for the real API.
  fastify.get('/demo', { helmet: { contentSecurityPolicy: false } }, async (_request, reply) => {
    reply.type('text/html').send(demoPageHtml);
  });
}
