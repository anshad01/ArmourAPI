import { Readable } from 'node:stream';

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
  } else {
    const chunks = [];
    for await (const chunk of raw) chunks.push(chunk);
    buffer = Buffer.concat(chunks);
    request.body = buffer.length > 0 ? Readable.from(buffer) : undefined;
  }

  request.armourapiBody = buffer;
  return buffer;
}
