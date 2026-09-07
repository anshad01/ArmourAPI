import { bufferRequestBody } from '../proxy/body-buffer.js';

/**
 * FR9 fallback WAF engine: the official owasp/modsecurity-crs:nginx image
 * (genuinely NGINX + ModSecurity + OWASP CRS, not a reimplementation),
 * used purely as a decision oracle - same shape as coraza-adapter.js. This
 * adapter sends it the same request ArmourAPI received and reads back
 * allow/block from the response status; it never sits in the real traffic
 * path to Juice Shop/DVGA/AndroGoat (see docker-compose.yml's comment on
 * the httpbin "backend" it proxies allowed requests to, which is discarded
 * here - only the status code matters).
 *
 * Unlike Coraza's in-process WASM transaction, ModSecurity's default deny
 * action returns a plain nginx 403 page with no structured rule/category
 * info - this adapter reports a generic category rather than faking
 * rule-level detail it doesn't actually have. That's an honest limitation
 * of a black-box HTTP-status-only integration, not a bug to paper over.
 */

const HOP_BY_HOP_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'keep-alive',
  'upgrade',
]);

export function createNginxModSecurityAdapter({
  baseUrl = process.env.NGINX_MODSECURITY_URL || 'http://localhost:8081',
  timeoutMs = 5000,
  // Security-conservative default: if the fallback WAF itself is
  // unreachable, block rather than silently letting everything through
  // unchecked. Matches Coraza's own mode:'block' philosophy.
  failOpen = false,
} = {}) {
  return {
    name: 'nginx-modsecurity',

    async scan(request) {
      const bodyBuffer = await bufferRequestBody(request);
      const headers = {};
      for (const [key, value] of Object.entries(request.headers ?? {})) {
        if (HOP_BY_HOP_HEADERS.has(key.toLowerCase())) continue;
        headers[key] = Array.isArray(value) ? value.join(', ') : String(value);
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const res = await fetch(`${baseUrl}${request.url}`, {
          method: request.method,
          headers,
          body: bodyBuffer && bodyBuffer.length > 0 ? bodyBuffer : undefined,
          signal: controller.signal,
        });
        // Drain the body so the connection can be released back to the pool.
        await res.arrayBuffer();

        if (res.status === 403) {
          return {
            allow: false,
            category: 'waf-block',
            reason: 'Blocked by NGINX + ModSecurity + OWASP CRS (fallback engine)',
          };
        }
        return { allow: true };
      } catch (err) {
        request.log?.warn({ err: err.message }, 'nginx-modsecurity adapter unreachable');
        return failOpen
          ? { allow: true }
          : { allow: false, category: 'waf-error', reason: 'Fallback WAF engine unreachable' };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
