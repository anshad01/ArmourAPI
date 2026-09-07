import { verifyToken, isTokenRevoked } from './jwt.js';

// Sensitive POS endpoints that require a valid ArmourAPI-issued session
// (per the doc's endpoint table: catalog browsing and login itself stay
// public, everything that touches money, stock, or a specific customer's
// data requires auth).
const PROTECTED_ROUTES = [
  { methods: ['POST'], pattern: /^\/api\/v1\/checkout\/?$/ },
  { methods: ['POST'], pattern: /^\/api\/v1\/discounts\/apply\/?$/ },
  { methods: ['PUT', 'PATCH'], pattern: /^\/api\/v1\/inventory\/[^/]+\/?$/ },
  { methods: ['GET'], pattern: /^\/api\/v1\/orders\/[^/]+\/?$/ },
];

function requiresAuth(method, path) {
  return PROTECTED_ROUTES.some((route) => route.methods.includes(method) && route.pattern.test(path));
}

export function createTokenGuard() {
  return {
    name: 'token-guard',

    async scan(request) {
      const path = request.url.split('?')[0];
      if (!requiresAuth(request.method, path)) return { allow: true };

      const header = request.headers.authorization;
      const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
      if (!token) {
        return { allow: false, category: 'auth-missing', reason: 'Missing bearer token' };
      }

      let claims;
      try {
        claims = verifyToken(token);
      } catch (err) {
        return { allow: false, category: 'auth-invalid', reason: `Invalid or expired token: ${err.message}` };
      }

      if (claims.type !== 'access') {
        return { allow: false, category: 'auth-invalid', reason: 'Not an access token' };
      }
      if (await isTokenRevoked(claims.jti)) {
        return { allow: false, category: 'auth-revoked', reason: 'Token has been revoked' };
      }

      request.armourapiUser = { sub: claims.sub, role: claims.role, jti: claims.jti };
      return { allow: true };
    },
  };
}
