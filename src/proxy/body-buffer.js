import { Readable } from 'node:stream';

// ARM-03 audit finding: @fastify/http-proxy's raw-stream body bypasses
// Fastify's own bodyLimit entirely (that only guards the built-in JSON body
// parser, which proxied routes never use), so an oversized body was reaching
// Coraza's WAF transaction uncapped and dying with its own internal
// "memoryLimit reached" error, leaked verbatim to the client. This is the
// one place every scanner's body access actually goes through, so the cap
// belongs here.
const MAX_BODY_BYTES = 2 * 1024 * 1024;

export class BodyTooLargeError extends Error {
  constructor(maxBytes) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.code = 'ARMOURAPI_BODY_TOO_LARGE';
    this.maxBytes = maxBytes;
  }
}

/**
 * @fastify/http-proxy hands back the raw, unconsumed request stream as
 * `request.body` (so it can pipe it upstream without re-encoding). Any
 * preHandler that needs to inspect the body must consume that stream once -
 * so this buffers it, then replaces request.body with a fresh Readable of the
 * same bytes so later preHandlers (and eventually the proxy) still see the
 * exact original payload. Safe to call more than once in a preHandler chain:
 * a stream already replaced by a previous call is just re-buffered from the
 * fresh Readable.
 */
export async function bufferRequestBody(request) {
  // Cached from an earlier preHandler in the same chain (e.g. the GraphQL
  // guard already buffered it before the WAF adapter runs) - reuse instead
  // of re-consuming the restored stream a second time.
  if (request.armourapiBody !== undefined) return request.armourapiBody;

  const raw = request.body;
  let buffer;
  if (!raw || typeof raw.pipe !== 'function') {
    buffer = typeof raw === 'string' || Buffer.isBuffer(raw) ? Buffer.from(raw) : undefined;
    if (buffer && buffer.length > MAX_BODY_BYTES) throw new BodyTooLargeError(MAX_BODY_BYTES);
  } else {
    const chunks = [];
    let total = 0;
    for await (const chunk of raw) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) throw new BodyTooLargeError(MAX_BODY_BYTES);
      chunks.push(chunk);
    }
    buffer = Buffer.concat(chunks);
    request.body = buffer.length > 0 ? Readable.from(buffer) : undefined;
  }

  request.armourapiBody = buffer;
  return buffer;
}
