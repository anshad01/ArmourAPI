/**
 * WAF adapter interface (FR9 - swappable WAF engine without redesigning the pipeline).
 * Any adapter must implement: scan(request) -> { allow: boolean, category?: string, reason?: string }
 * and may optionally implement: close()
 *
 * Adapters:
 *  - coraza-adapter.js           (Coraza + OWASP CRS v4, primary - Phase 3)
 *  - nginx-modsecurity-adapter.js (NGINX + ModSecurity + CRS, documented fallback - Phase 12.3)
 */

// Passthrough placeholder - useful for local dev without WAF overhead, or if
// both real adapters are unavailable.
export function createPassthroughAdapter() {
  return {
    name: 'passthrough',
    async scan(_request) {
      return { allow: true };
    },
  };
}

// FR9: select the WAF engine by config/env without touching the proxy pipeline.
export async function createWafAdapter(engine = process.env.WAF_ENGINE || 'coraza') {
  switch (engine) {
    case 'coraza': {
      const { createCorazaAdapter } = await import('./coraza-adapter.js');
      return createCorazaAdapter();
    }
    case 'nginx-modsecurity': {
      const { createNginxModSecurityAdapter } = await import('./nginx-modsecurity-adapter.js');
      return createNginxModSecurityAdapter();
    }
    case 'passthrough':
      return createPassthroughAdapter();
    default:
      throw new Error(`Unknown WAF_ENGINE "${engine}"`);
  }
}
