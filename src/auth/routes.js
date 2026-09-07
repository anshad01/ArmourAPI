import { verifyToken, revokeToken } from './jwt.js';

// FR6 revocation list: lets a client (or an admin, in a fuller build) end an
// ArmourAPI-issued session early. Registered as a static route so it takes
// precedence over the /api/v1/* proxy wildcard, same pattern as security-api.
export async function registerAuthApi(fastify) {
  fastify.post('/api/v1/auth/logout', async (request, reply) => {
    const header = request.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    if (!token) return reply.code(400).send({ error: 'Missing bearer token' });

    let claims;
    try {
      claims = verifyToken(token);
    } catch {
      return reply.code(400).send({ error: 'Invalid token' });
    }

    const remainingSeconds = Math.max(1, claims.exp - Math.floor(Date.now() / 1000));
    await revokeToken(claims.jti, remainingSeconds);
    return { revoked: true };
  });
}
