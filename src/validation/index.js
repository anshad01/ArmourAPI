import { bufferRequestBody } from '../proxy/body-buffer.js';
import { loginSchema, checkoutSchema, discountApplySchema, inventoryUpdateSchema } from './schemas.js';

// Endpoint -> schema routing, per the doc's named FR5 targets. Unlisted
// endpoints pass through untouched - this guard only validates where a
// schema has been defined, it's not a generic body-shape enforcer.
const RULES = [
  { methods: ['POST'], pattern: /^\/api\/v1\/auth\/login\/?$/, schema: loginSchema },
  { methods: ['POST'], pattern: /^\/api\/v1\/checkout\/?$/, schema: checkoutSchema },
  { methods: ['POST'], pattern: /^\/api\/v1\/discounts\/apply\/?$/, schema: discountApplySchema },
  { methods: ['PUT', 'PATCH'], pattern: /^\/api\/v1\/inventory\/[^/]+\/?$/, schema: inventoryUpdateSchema },
];

function matchRule(method, path) {
  return RULES.find((rule) => rule.methods.includes(method) && rule.pattern.test(path));
}

export function createSchemaGuard() {
  return {
    name: 'schema-guard',

    async scan(request) {
      const path = request.url.split('?')[0];
      const rule = matchRule(request.method, path);
      if (!rule) return { allow: true };

      const bodyBuffer = await bufferRequestBody(request);
      let parsed;
      try {
        parsed = bodyBuffer && bodyBuffer.length > 0 ? JSON.parse(bodyBuffer.toString('utf8')) : {};
      } catch {
        return { allow: false, category: 'schema-violation', reason: 'Request body is not valid JSON' };
      }

      const result = rule.schema.safeParse(parsed);
      if (!result.success) {
        const issue = result.error.issues[0];
        const reason = issue ? `${issue.path.join('.') || '(root)'}: ${issue.message}` : 'Schema validation failed';
        return { allow: false, category: 'schema-violation', reason };
      }
      return { allow: true };
    },
  };
}
