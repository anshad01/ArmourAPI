// One-click demo aid for live presentations - NOT a dashboard (Grafana stays
// the dashboard, per FR10). This just gives a presenter a big button per
// attack instead of typing commands live. Protected-mode buttons fetch
// ArmourAPI itself (same-origin, works right now). Baseline-mode links open
// the real target directly in a new tab (needs Docker - the real testbeds
// aren't running yet, so those links won't show anything meaningful until
// then).
export const demoPageHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ArmourAPI Live Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }
  h1 { margin-bottom: 0.25rem; }
  .sub { color: #94a3b8; margin-top: 0; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .card h2 { margin-top: 0; font-size: 1.05rem; }
  .card p { color: #94a3b8; font-size: 0.9rem; }
  button, .link-btn { background: #2563eb; color: white; border: none; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.95rem; cursor: pointer; margin-right: 0.5rem; text-decoration: none; display: inline-block; }
  button:hover, .link-btn:hover { background: #1d4ed8; }
  .link-btn.secondary { background: #475569; }
  .link-btn.secondary:hover { background: #334155; }
  pre { background: #0b1220; border: 1px solid #334155; border-radius: 6px; padding: 0.75rem; overflow-x: auto; font-size: 0.85rem; margin-top: 0.75rem; white-space: pre-wrap; word-break: break-word; }
  .result { font-weight: 600; margin-top: 0.75rem; }
  .result.blocked { color: #f87171; }
  .result.allowed { color: #4ade80; }
  .result.pending { color: #facc15; }
  .badge { display: inline-block; font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 999px; margin-left: 0.5rem; }
  .badge.protected { background: #14532d; color: #86efac; }
  .badge.baseline { background: #7c2d12; color: #fdba74; }
</style>
</head>
<body>
  <h1>ArmourAPI Live Demo</h1>
  <p class="sub">Click a button to fire a real attack at ArmourAPI. Results appear below each card.</p>

  <div class="card">
    <h2>SQL Injection <span class="badge protected">protected</span></h2>
    <p>Sends <code>' OR '1'='1</code> in a product-search query through ArmourAPI.</p>
    <button onclick="fireGet('sqli', '/app/rest/products/search?q=%27%20OR%20%271%27%3D%271')">Trigger SQLi</button>
    <a class="link-btn secondary" target="_blank" href="http://localhost:3000/rest/products/search?q=%27%20OR%20%271%27%3D%271">Same attack, baseline (direct to Juice Shop, needs Docker)</a>
    <div id="sqli-result"></div>
  </div>

  <div class="card">
    <h2>XSS in JSON body <span class="badge protected">protected</span></h2>
    <p>Sends <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> as a discount code.</p>
    <button onclick="firePost('xss', '/api/v1/discounts/apply', { code: '<script>alert(1)</script>' }, true)">Trigger XSS</button>
    <p style="font-size:0.8rem;color:#64748b">(logs in first to get a session - needs a reachable upstream, i.e. Docker, or this shows auth-missing/500 instead)</p>
    <div id="xss-result"></div>
  </div>

  <div class="card">
    <h2>GraphQL introspection abuse <span class="badge protected">protected</span></h2>
    <p>Asks DVGA to dump its entire schema via <code>{ __schema { types { name } } }</code>.</p>
    <button onclick="firePost('gql', '/graphql', { query: '{ __schema { types { name } } }' })">Trigger introspection query</button>
    <div id="gql-result"></div>
  </div>

  <div class="card">
    <h2>NoSQL injection via login <span class="badge protected">protected</span></h2>
    <p>Sends an object instead of a string password (<code>{"$ne": null}</code>) - a classic NoSQL-injection shape. No login needed to trigger this one - it's ArmourAPI's own schema layer rejecting the shape before anything is forwarded, so there's no "baseline" comparison to show (this isn't a Juice Shop/DVGA feature being attacked).</p>
    <button onclick="firePost('nosql', '/api/v1/auth/login', { email: 'x@test.com', password: { '$ne': null } })">Trigger NoSQL injection</button>
    <div id="nosql-result"></div>
  </div>

  <div class="card">
    <h2>Brute-force login <span class="badge protected">protected</span></h2>
    <p>Fires 7 rapid failed logins for the same account. Watch the 7th get auto-blocklisted.</p>
    <button onclick="fireBruteForce()">Trigger 7 login attempts</button>
    <div id="brute-result"></div>
  </div>

  <div class="card">
    <h2>Scraping burst <span class="badge protected">protected</span></h2>
    <p>Fires 30 rapid catalog requests to show the rate limiter engage.</p>
    <button onclick="fireScrapeBurst()">Trigger 30 rapid requests</button>
    <div id="scrape-result"></div>
  </div>

  <script>
    // /api/v1/discounts/apply requires an ArmourAPI session (Phase 7's
    // token-guard) - without one, the XSS button would get blocked for the
    // wrong reason (auth-missing instead of the XSS attempt itself), which
    // would confuse an audience watching the labeled reason on screen. Log
    // in once, lazily, and reuse the token for any button that needs it.
    let cachedToken = null;
    async function ensureToken() {
      if (cachedToken) return cachedToken;
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'demo-presenter@armourapi.local', password: 'demo-only' }),
      });
      cachedToken = res.headers.get('X-ArmourAPI-Access-Token');
      return cachedToken;
    }

    function render(id, label, res, body) {
      const el = document.getElementById(id);
      const blocked = res.status === 403;
      el.innerHTML =
        '<div class="result ' + (blocked ? 'blocked' : 'allowed') + '">' +
        (blocked ? '\\u{1F6D1} BLOCKED' : '\\u2705 ALLOWED') +
        ' \\u2014 HTTP ' + res.status + '</div>' +
        '<pre>' + JSON.stringify(body, null, 2) + '</pre>';
    }

    async function fireGet(id, path) {
      document.getElementById(id + '-result').innerHTML = '<div class="result pending">sending...</div>';
      const res = await fetch(path);
      let body; try { body = await res.json(); } catch { body = { note: 'non-JSON response' }; }
      render(id + '-result', id, res, body);
    }

    async function firePost(id, path, payload, needsAuth) {
      document.getElementById(id + '-result').innerHTML = '<div class="result pending">sending...</div>';
      const headers = { 'Content-Type': 'application/json' };
      if (needsAuth) {
        const token = await ensureToken();
        if (token) headers['Authorization'] = 'Bearer ' + token;
      }
      const res = await fetch(path, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });
      let body; try { body = await res.json(); } catch { body = { note: 'non-JSON response' }; }
      render(id + '-result', id, res, body);
    }

    async function fireBruteForce() {
      const el = document.getElementById('brute-result');
      el.innerHTML = '<div class="result pending">firing 7 attempts...</div>';
      const lines = [];
      for (let i = 1; i <= 7; i++) {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'demo-victim@armourapi.local', password: 'guess-' + i }),
        });
        lines.push('attempt ' + i + ': HTTP ' + res.status + (res.status === 403 ? ' \\u{1F6D1} BLOCKLISTED' : ''));
      }
      el.innerHTML = '<pre>' + lines.join('\\n') + '</pre>';
    }

    async function fireScrapeBurst() {
      const el = document.getElementById('scrape-result');
      el.innerHTML = '<div class="result pending">firing 30 requests...</div>';
      let allowed = 0, blocked = 0;
      await Promise.all(Array.from({ length: 30 }, () =>
        fetch('/api/v1/products').then((res) => { res.status === 403 ? blocked++ : allowed++; })
      ));
      el.innerHTML = '<div class="result ' + (blocked > 0 ? 'blocked' : 'allowed') + '">' +
        allowed + ' allowed, ' + blocked + ' blocked' + (blocked > 0 ? ' \\u{1F6D1} rate limiter engaged' : '') + '</div>';
    }
  </script>
</body>
</html>`;
