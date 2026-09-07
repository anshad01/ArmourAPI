import os from 'node:os';
import { createWAFPool } from '@coraza/core';
import { recommended } from '@coraza/coreruleset';
import { bufferRequestBody } from '../proxy/body-buffer.js';

/**
 * @coraza/core is preview/experimental (0.1.0-preview.*, community project,
 * not an official OWASP release - see Risk Register item 1). Verified working
 * against SQLi/XSS test payloads before wiring in; two field-name mismatches
 * versus the published docs were found by reading node_modules/@coraza/core/dist/*.d.ts
 * directly: RequestInfo.url (not .uri), and headers must be [key, value][]
 * tuples (not a plain object).
 */

// Best-effort CRS rule-ID -> human category mapping, for log/metric labeling
// only. Does not affect the WAF's own allow/block decision.
const CATEGORY_RANGES = [
  [911000, 911999, 'method-enforcement'],
  [913000, 913999, 'scanner-detection'],
  [920000, 921999, 'protocol-violation'],
  [930000, 930999, 'path-traversal'],
  [931000, 931999, 'rfi'],
  [932000, 933999, 'rce'],
  [934000, 934999, 'generic-attack'],
  [941000, 941999, 'xss'],
  [942000, 942999, 'sqli'],
  [943000, 943999, 'session-fixation'],
  [944000, 944999, 'java-attack'],
];

const ATTACK_SIGNATURE_RANGE = [930000, 944999];

function categoryFor(ruleId) {
  const hit = CATEGORY_RANGES.find(([lo, hi]) => ruleId >= lo && ruleId <= hi);
  return hit ? hit[2] : 'anomaly';
}

function pickReportingRule(matchedRules, interruptionRuleId) {
  const specific = matchedRules.filter((r) => r.severity >= 0 && r.severity <= 4);
  // Prefer a genuine attack-signature rule (930xxx-944xxx) over generic
  // protocol-enforcement noise, so e.g. an XSS payload logs as "xss" and
  // not as an incidental protocol rule that happened to fire first.
  const attackRule = specific.find(
    (r) => r.id >= ATTACK_SIGNATURE_RANGE[0] && r.id <= ATTACK_SIGNATURE_RANGE[1],
  );
  return attackRule || specific.find((r) => r.id !== interruptionRuleId) || null;
}

const ANOMALY_SCORE_PATTERN = /Total Score: (\d+)/;

// CRS's blocking rules (949110 inbound / 959100 outbound) summarize the
// request's total anomaly score in their message - surfaced separately so
// GET /security/threats can report it (doc: "including anomaly scores").
function extractAnomalyScore(matchedRules) {
  for (const rule of matchedRules) {
    const match = ANOMALY_SCORE_PATTERN.exec(rule.message || '');
    if (match) return Number(match[1]);
  }
  return null;
}

// CRS's default allowed_request_content_type does not include application/json,
// so every JSON POST/PUT gets blocked by rule 920420 out of the box. The usual
// fix is a crs-setup.conf tx.allowed_request_content_type override, but
// @coraza/coreruleset's `extra` option only appends AFTER the CRS rule files
// load - by then 920420 has already run once against the request, so a
// setvar override there is too late (confirmed by testing: it did not take
// effect). Disabling the rule outright works because SecRuleRemoveById is a
// config-time removal, not order-dependent. ArmourAPI is fronting a JSON API
// (FR5) by design, so this rule provides no value here regardless.
//
// Same problem, different rule: CRS's default allowed-methods policy (rule
// 911100) doesn't include PATCH, so PUT/PATCH /api/v1/inventory/{id} - a
// real endpoint in the doc's own API table - was being blocked outright.
// Found by the Phase 10 attack corpus (a "should pass" PATCH request never
// made it past this rule); no prior phase's testing had exercised a
// schema-valid PATCH request all the way through to the WAF layer.
const CRS_TUNING = ['SecRuleRemoveById 920420', 'SecRuleRemoveById 911100'].join('\n');

// Defaulting to os.availableParallelism() (one WASM worker per core) is what
// drove idle RAM to ~1.4GB in Phase 11 benchmarking, ~6x over NFR2's <256MB
// target, before a single request. Configurable so pool size (concurrency
// headroom) can be traded off against the RAM budget instead of that
// decision being made implicitly by whatever core count the host happens
// to have.
const DEFAULT_WAF_POOL_SIZE = Math.min(4, os.availableParallelism());

export async function createCorazaAdapter({ mode = 'block' } = {}) {
  const size = Number(process.env.WAF_POOL_SIZE) || DEFAULT_WAF_POOL_SIZE;
  const pool = await createWAFPool({
    rules: recommended({ extra: CRS_TUNING }),
    mode,
    size,
  });

  return {
    name: 'coraza',

    async scan(request) {
      const tx = await pool.newTransaction();
      try {
        const headers = Object.entries(request.headers ?? {}).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(', ') : String(value),
        ]);

        const bodyBuffer = await bufferRequestBody(request);
        const body = bodyBuffer && bodyBuffer.length > 0 ? bodyBuffer.toString('utf8') : undefined;

        await tx.processRequestBundle(
          { method: request.method, url: request.url, headers, remoteAddr: request.ip },
          body,
        );

        const interruption = await tx.interruption();
        if (!interruption) {
          return { allow: true };
        }

        const matchedRules = await tx.matchedRules();
        const reportingRule = pickReportingRule(matchedRules, interruption.ruleId);

        return {
          allow: false,
          category: categoryFor(reportingRule ? reportingRule.id : interruption.ruleId),
          reason: reportingRule?.message || `CRS rule ${interruption.ruleId} (${interruption.action})`,
          anomalyScore: extractAnomalyScore(matchedRules),
        };
      } finally {
        await tx.close();
      }
    },

    async close() {
      await pool.destroy();
    },
  };
}
