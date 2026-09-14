import { bufferRequestBody } from '../proxy/body-buffer.js';

/**
 * "Mode 1: Fast Inline Drop" (Jay's Parameters.rtf.doc, 2026-09-14): a small
 * set of high-confidence signature patterns checked in-process, before a
 * Coraza WASM transaction is ever spent. Deliberately narrow - this has no
 * anomaly scoring or nuance the way Coraza does, so it only fires on
 * patterns that are essentially never legitimate traffic (classic SQLi
 * tautologies, <script> tags, shell metacharacter chains). Anything not
 * caught here still falls through to Coraza unchanged - this is an
 * additional fast tripwire, not a replacement for the real WAF transaction.
 */

const SIGNATURES = [
  { category: 'sqli', pattern: /'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+/i, reason: "SQL tautology (' OR 1=1 style)" },
  { category: 'sqli', pattern: /\bunion\s+select\b/i, reason: 'UNION SELECT' },
  { category: 'sqli', pattern: /;\s*(drop|delete)\s+(table|from)\b/i, reason: 'Destructive SQL statement' },
  { category: 'xss', pattern: /<script[\s>]/i, reason: '<script> tag' },
  { category: 'xss', pattern: /<img[^>]+onerror\s*=/i, reason: 'onerror handler injection' },
  { category: 'cmd-injection', pattern: /;\s*(cat|ls|whoami|rm|wget|curl)\s/i, reason: 'shell command chaining' },
  { category: 'cmd-injection', pattern: /\$\([^)]+\)/, reason: 'command substitution $(...)' },
];

function scanText(text) {
  for (const sig of SIGNATURES) {
    if (sig.pattern.test(text)) return sig;
  }
  return null;
}

// request.url is the raw, percent-encoded string (e.g. %27%20OR...) - every
// signature above looks for literal characters ('<, ', $(), so scanning the
// undecoded form matches nothing and everything silently falls through to
// Coraza. Decode before scanning; also scan the raw form afterward in case
// decoding fails (malformed encoding) or double-encoding is used to evade -
// belt and suspenders, not a substitute for Coraza's own normalization.
function decodeBestEffort(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

export function createFastFilter() {
  return {
    name: 'fast-filter',

    async scan(request) {
      const rawUrl = request.url || '';
      const urlHit = scanText(decodeBestEffort(rawUrl)) || scanText(rawUrl);
      if (urlHit) {
        return { allow: false, category: urlHit.category, reason: `Fast-filter: ${urlHit.reason}` };
      }

      const bodyBuffer = await bufferRequestBody(request);
      if (bodyBuffer && bodyBuffer.length > 0) {
        const bodyHit = scanText(bodyBuffer.toString('utf8'));
        if (bodyHit) {
          return { allow: false, category: bodyHit.category, reason: `Fast-filter: ${bodyHit.reason}` };
        }
      }

      return { allow: true };
    },
  };
}
