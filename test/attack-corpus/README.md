# ArmourAPI Attack Corpus

Versioned attack corpus, one folder per row of the threat matrix (doc Section 4.3, "API Security & Threat Matrix"). This is the corpus described in Section 6 ("Attack Corpus & Baseline-vs-Protected Methodology") - kept in-repo so it's reproducible, per the Charter's reproducibility requirement.

## Contents

- `armourapi-attack-corpus.postman_collection.json` - Postman/Newman collection, 8 folders + a setup step that logs in and captures an ArmourAPI session token.
- `environments/protected.postman_environment.json` - points at ArmourAPI (`localhost:8080`). **Runnable today.**
- `environments/baseline.postman_environment.json` - points at the three real targets directly, for when Docker/the testbeds are up. **Not runnable yet** - see "Baseline mode" below.
- `k6/credential-stuffing.js`, `k6/scraping-spike.js` - the two scenarios Section 3.3 explicitly names k6 for (a ramping-VU login-attempt spike and a constant-arrival-rate catalog-scrape burst), since a handful of sequential Postman requests can't realistically trigger rate-limiter behavior the way a real burst does.

## Running the "protected" corpus (works now, no Docker needed)

```bash
# 1. Start ArmourAPI (needs *some* upstream for /auth/login to succeed and issue
#    a token - point ANDROGOAT_URL at a real backend, or any stand-in that
#    returns 2xx for POST /, since ArmourAPI mints its own session on top of
#    a successful upstream response regardless of what that response contains)
npm start

# 2. Run the collection
npx newman run test/attack-corpus/armourapi-attack-corpus.postman_collection.json \
  -e test/attack-corpus/environments/protected.postman_environment.json
```

```bash
# k6 (separate install - it's a standalone Go binary, not an npm package;
# https://k6.io/docs/get-started/installation/ - independent of Docker)
k6 run -e BASE_URL=http://localhost:8080 test/attack-corpus/k6/credential-stuffing.js
k6 run -e BASE_URL=http://localhost:8080 test/attack-corpus/k6/scraping-spike.js
```

## Baseline mode (needs Docker + the real testbeds)

The doc's methodology is: run the corpus twice, once direct-to-target ("baseline", no ArmourAPI) and once through the gateway ("protected"), then diff the results. That diff is the Validation Test Report deliverable.

**Baseline isn't a simple environment swap for this collection**, because ArmourAPI strips its own routing prefix before forwarding (`/app/*` → Juice Shop's root, `/graphql/*` → DVGA's root, `/api/v1/*` → the POS backend's root). A request that's `{{base_url}}/app/rest/products/search` in protected mode is `{{juice_shop_base}}/rest/products/search` directly against Juice Shop - different path, not just a different host. The `baseline.postman_environment.json` file defines `juice_shop_base` / `dvga_base` / `androgoat_base` for this, but the collection's requests aren't currently duplicated with baseline-shaped paths.

When Docker is available, the straightforward way to get real baseline numbers: duplicate this collection, strip ArmourAPI's prefix from each request's path per the mapping above, point each folder at its corresponding `*_base` variable, and run it against the containers directly (no ArmourAPI in front). Until then, this corpus only proves what ArmourAPI itself does with each attack class - not the "successfully exploited when unprotected" half of the before/after table.

## Coverage status - read before reporting results

Not every folder represents a fully mitigated attack class. Flagged explicitly in the collection's test scripts, summarized here so results don't get overclaimed (the doc's own Risk Register calls this out specifically - "Overclaiming 'blocks OWASP Top 10' broadly"):

| # | Class | Status | Why |
|---|---|---|---|
| 1 | BOLA/IDOR | **Partial** | Requires *a* valid token (FR6), but does not verify the token's subject owns the requested object - no ownership-matching authorization layer built. |
| 2 | Mass Assignment / Price Tampering | **Mitigated** | `.strict()` schemas (Phase 6) reject the extra field outright. |
| 3 | Brute Force / Credential Stuffing | **Mitigated** | Rate limiter + escalating blocklist (Phase 5). |
| 4 | Credential/Token Theft & Hijacking | **Partial** | Explicit revocation works (Phase 7); "Impossible Travel" / device-fingerprint anomaly detection from the doc's scenario is not implemented. |
| 5 | BFLA | **Not mitigated** | `token-guard.js` checks token validity, not role-appropriateness. `request.armourapiUser.role` is populated for a future RBAC layer but nothing enforces it yet. |
| 6 | SSRF | **Untested** | The doc's scenario is a webhook/receipt-delivery URL field; no such endpoint exists in the current build (not in Section 3's endpoint table). The corpus request only checks the discount-code schema's regex, which is a different mechanism, not SSRF egress filtering. |
| 7 | API Abuse / Scraping | **Mitigated** (generic) | Global rate limiter (Phase 5) throttles by request volume; the doc's more specific ideas (API-key query-tier quotas, PoW challenges) aren't built. |
| 8 | Injection (SQLi/NoSQLi/XSS) | **Mitigated** | Coraza + OWASP CRS (Phase 3) for SQLi/XSS; typed `zod` schemas (Phase 6) incidentally block NoSQL-injection-via-object payloads. |
