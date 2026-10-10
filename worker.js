// =============================================================================
// DevSec Toolbox — Cloudflare Worker backend.
// Serves the static site (via ASSETS binding) and powers the "live" scanners:
//   POST /api/sca      — dependency vulnerability scan (OSV.dev)
//   GET  /api/headers  — website security-header scan (SSRF-guarded fetch)
//   GET  /api/dns      — DNS + email-security lookup (DNS-over-HTTPS)
//   GET  /api/stats    — anonymous aggregate usage stats (D1)
// KV (CACHE) caches responses; D1 (DB) stores ONLY anonymous aggregate counters.
// No user content (manifests, URLs, findings linked to a user) is ever stored.
// =============================================================================

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': '*' };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (p.startsWith('/api/')) {
      if (request.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type' } });
      try {
        if (p === '/api/sca' && request.method === 'POST') return await apiSca(request, env, ctx);
        if (p === '/api/headers') return await apiHeaders(url, env, ctx);
        if (p === '/api/dns') return await apiDns(url, env, ctx);
        if (p === '/api/stats') return await apiStats(env);
        return json({ error: 'Unknown endpoint' }, 404);
      } catch (e) {
        return json({ error: String((e && e.message) || e) }, 500);
      }
    }
    // Everything else = the static site.
    return env.ASSETS.fetch(request);
  }
};

// ---------- helpers ----------
async function bump(env, ctx, updates) {
  // updates: { key: delta } on the stats table. Best-effort, non-blocking.
  const stmts = Object.entries(updates).map(([k, d]) => env.DB.prepare('UPDATE stats SET v = v + ? WHERE k = ?').bind(d, k));
  ctx.waitUntil(env.DB.batch(stmts).catch(() => {}));
}
async function bumpFindings(env, ctx, ids, kind) {
  if (!ids.length) return;
  const now = Math.floor(Date.now() / 1000);
  const stmts = ids.slice(0, 25).map(id => env.DB.prepare('INSERT INTO findings (id, kind, n, last_seen) VALUES (?, ?, 1, ?) ON CONFLICT(id) DO UPDATE SET n = n + 1, last_seen = ?').bind(id, kind, now, now));
  ctx.waitUntil(env.DB.batch(stmts).catch(() => {}));
}

// ======================= SCA — OSV.dev =======================
async function apiSca(request, env, ctx) {
  const body = await request.json().catch(() => null);
  const queries = body && Array.isArray(body.queries) ? body.queries : null;
  if (!queries || !queries.length) return json({ error: 'Send { queries: [{ package:{name,ecosystem}, version }] }' }, 400);
  if (queries.length > 600) return json({ error: 'Too many packages (max 600).' }, 413);

  // cache whole-scan result
  const cacheKey = 'sca:' + await sha1(JSON.stringify(queries));
  const cached = await env.CACHE.get(cacheKey);
  if (cached) return new Response(cached, { headers: { ...JSON_HEADERS, 'x-cache': 'HIT' } });

  // 1) batch query OSV (single subrequest for all packages)
  const batchRes = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries })
  });
  if (!batchRes.ok) return json({ error: 'OSV query failed (' + batchRes.status + ')' }, 502);
  const batch = await batchRes.json();
  const results = batch.results || [];

  // collect unique vuln ids
  const idSet = new Set();
  results.forEach(r => (r.vulns || []).forEach(v => idSet.add(v.id)));
  const ids = [...idSet].slice(0, 45); // cap detail fetches (subrequest budget)

  // 2) fetch details per vuln (cached in KV)
  const details = {};
  await Promise.all(ids.map(async id => {
    const k = 'vuln:' + id;
    let d = await env.CACHE.get(k, 'json');
    if (!d) {
      const r = await fetch('https://api.osv.dev/v1/vulns/' + encodeURIComponent(id));
      if (r.ok) { const full = await r.json(); d = slimVuln(full); ctx.waitUntil(env.CACHE.put(k, JSON.stringify(d), { expirationTtl: 604800 })); }
    }
    if (d) details[id] = d;
  }));

  // 3) assemble per-package findings
  const out = [];
  let vulnCount = 0;
  results.forEach((r, i) => {
    const q = queries[i] || {};
    const pkg = (q.package && q.package.name) || '?';
    const eco = (q.package && q.package.ecosystem) || '';
    const vulns = (r.vulns || []).map(v => details[v.id] || { id: v.id });
    if (vulns.length) { vulnCount += vulns.length; out.push({ name: pkg, version: q.version || '', ecosystem: eco, vulns }); }
  });

  const resp = {
    scanned: queries.length,
    vulnerable: out.length,
    vulns: vulnCount,
    results: out.sort((a, b) => worst(b.vulns) - worst(a.vulns))
  };
  ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(resp), { expirationTtl: 3600 }));
  await bump(env, ctx, { scans_sca: 1, packages_scanned: queries.length, vulns_found: vulnCount });
  bumpFindings(env, ctx, [...idSet], 'sca');
  return new Response(JSON.stringify(resp), { headers: { ...JSON_HEADERS, 'x-cache': 'MISS' } });
}

function slimVuln(v) {
  let fixed = '';
  (v.affected || []).some(a => (a.ranges || []).some(rg => (rg.events || []).some(e => { if (e.fixed) { fixed = e.fixed; return true; } return false; })));
  let score = 0, sevText = '';
  (v.severity || []).forEach(s => { const m = /\/AV:/.test(s.score) ? cvssFromVector(s.score) : parseFloat(s.score); if (!isNaN(m) && m > score) score = m; });
  if (score) sevText = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
  const cve = (v.aliases || []).find(a => /^CVE-/.test(a));
  return { id: v.id, cve: cve || '', summary: (v.summary || v.details || '').slice(0, 220), severity: sevText, score: score || null, fixed };
}
function worst(vulns) { return Math.max(0, ...vulns.map(v => v.score || 0)); }
// minimal CVSS v3 base from vector (for ranking only; approximate)
function cvssFromVector(vec) {
  const m = {}; vec.split('/').forEach(p => { const [k, val] = p.split(':'); if (k && val) m[k] = val; });
  const AV = { N: .85, A: .62, L: .55, P: .2 }[m.AV] || .85, AC = { L: .77, H: .44 }[m.AC] || .77;
  const S = m.S === 'C'; const PR = { N: .85, L: S ? .68 : .62, H: S ? .5 : .27 }[m.PR] || .85, UI = { N: .85, R: .62 }[m.UI] || .85;
  const g = c => ({ H: .56, L: .22, N: 0 }[c] || 0); const isc = 1 - (1 - g(m.C)) * (1 - g(m.I)) * (1 - g(m.A));
  const imp = S ? 7.52 * (isc - .029) - 3.25 * Math.pow(isc - .02, 15) : 6.42 * isc;
  const exp = 8.22 * AV * AC * PR * UI; if (imp <= 0) return 0;
  const raw = Math.min((S ? 1.08 : 1) * (imp + exp), 10); return Math.ceil(raw * 10) / 10;
}

// ======================= Website security headers =======================
function isBlockedHost(h) {
  h = h.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h === 'metadata.google.internal') return true;
  if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(h)) {
    const o = h.split('.').map(Number);
    if (o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168) || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 169 && o[1] === 254) || o[0] === 0) return true;
  }
  if (h === '::1' || h.startsWith('fd') || h.startsWith('fe80')) return true;
  return false;
}
async function apiHeaders(url, env, ctx) {
  let target = (url.searchParams.get('url') || '').trim();
  if (!target) return json({ error: 'Provide ?url=' }, 400);
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
  let u; try { u = new URL(target); } catch { return json({ error: 'Invalid URL' }, 400); }
  if (!/^https?:$/.test(u.protocol)) return json({ error: 'Only http/https allowed' }, 400);
  if (isBlockedHost(u.hostname)) return json({ error: 'Target host is not allowed (private/internal address).' }, 403);

  const cacheKey = 'hdr:' + u.href;
  const cached = await env.CACHE.get(cacheKey);
  if (cached) return new Response(cached, { headers: { ...JSON_HEADERS, 'x-cache': 'HIT' } });

  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 9000);
  let res;
  try { res = await fetch(u.href, { method: 'GET', redirect: 'follow', signal: ctl.signal, headers: { 'user-agent': 'DevSecToolbox-Scanner/1.0 (+https://devsec.ksatriabintangsamudra.com)' } }); }
  catch (e) { clearTimeout(t); return json({ error: 'Could not reach the site: ' + ((e && e.name === 'AbortError') ? 'timed out' : (e.message || 'fetch failed')) }, 502); }
  clearTimeout(t);

  const H = name => res.headers.get(name) || '';
  const finalUrl = res.url || u.href;
  const https = finalUrl.startsWith('https://');
  const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : (H('set-cookie') ? [H('set-cookie')] : []);
  const checks = [
    chk('Strict-Transport-Security', H('strict-transport-security'), v => /max-age=\d{5,}/.test(v), 'Enforce HTTPS: max-age=63072000; includeSubDomains; preload.', 20),
    chk('Content-Security-Policy', H('content-security-policy'), v => v && !/unsafe-inline/.test(v), 'Define a CSP; avoid unsafe-inline / unsafe-eval.', 25, v => v && /unsafe-inline|unsafe-eval/.test(v)),
    chk('X-Content-Type-Options', H('x-content-type-options'), v => /nosniff/i.test(v), 'Set to "nosniff".', 10),
    chk('X-Frame-Options', H('x-frame-options'), v => /deny|sameorigin/i.test(v), 'Set DENY/SAMEORIGIN (or CSP frame-ancestors).', 10),
    chk('Referrer-Policy', H('referrer-policy'), v => !!v, 'Set e.g. strict-origin-when-cross-origin.', 10),
    chk('Permissions-Policy', H('permissions-policy'), v => !!v, 'Restrict powerful features (camera, geolocation…).', 10),
  ];
  let got = 0, total = 0;
  checks.forEach(c => { total += c.weight; got += c.points; });
  if (!https) got = Math.max(0, got - 15);
  const pct = Math.round(got / total * 100);
  const grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 60 ? 'C' : pct >= 40 ? 'D' : 'F';
  const cookieFlags = cookies.slice(0, 8).map(c => ({ name: (c.split('=')[0] || '').slice(0, 40), secure: /;\s*secure/i.test(c), httpOnly: /;\s*httponly/i.test(c), sameSite: (c.match(/samesite=(\w+)/i) || [])[1] || '—' }));
  const resp = {
    url: finalUrl, status: res.status, https, redirected: finalUrl !== u.href,
    server: H('server'), poweredBy: H('x-powered-by'), grade, score: pct,
    checks: checks.map(c => ({ name: c.name, state: c.state, value: c.value.slice(0, 180), tip: c.tip })),
    cookies: cookieFlags
  };
  ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(resp), { expirationTtl: 600 }));
  await bump(env, ctx, { scans_headers: 1, sites_scanned: 1 });
  return new Response(JSON.stringify(resp), { headers: { ...JSON_HEADERS, 'x-cache': 'MISS' } });
}
function chk(name, value, ok, tip, weight, warnFn) {
  let state = 'fail', points = 0;
  if (value) { if (warnFn && warnFn(value)) { state = 'warn'; points = weight * 0.5; } else if (ok(value)) { state = 'pass'; points = weight; } else { state = 'warn'; points = weight * 0.4; } }
  return { name, value: value || '', state, tip, weight, points };
}

// ======================= DNS + email security =======================
async function doh(name, type) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) return { answers: [], ad: false };
  const j = await r.json();
  return { answers: (j.Answer || []).map(a => ({ type: a.type, data: (a.data || '').replace(/^"|"$/g, '') })), ad: !!j.AD, status: j.Status };
}
async function apiDns(url, env, ctx) {
  let domain = (url.searchParams.get('domain') || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return json({ error: 'Provide a valid ?domain=' }, 400);
  const selector = (url.searchParams.get('selector') || '').trim().replace(/[^a-z0-9._-]/gi, '');

  const cacheKey = 'dns:' + domain + '|' + selector;
  const cached = await env.CACHE.get(cacheKey);
  if (cached) return new Response(cached, { headers: { ...JSON_HEADERS, 'x-cache': 'HIT' } });

  const [a, aaaa, mx, ns, txt, caa, dmarc, dkim] = await Promise.all([
    doh(domain, 'A'), doh(domain, 'AAAA'), doh(domain, 'MX'), doh(domain, 'NS'),
    doh(domain, 'TXT'), doh(domain, 'CAA'), doh('_dmarc.' + domain, 'TXT'),
    selector ? doh(selector + '._domainkey.' + domain, 'TXT') : Promise.resolve({ answers: [] })
  ]);
  const txts = txt.answers.map(x => x.data);
  const spf = txts.find(t => /^v=spf1/i.test(t)) || '';
  const dmarcRec = dmarc.answers.map(x => x.data).find(t => /^v=DMARC1/i.test(t)) || '';
  const dmarcPolicy = (dmarcRec.match(/p=(\w+)/i) || [])[1] || '';
  const resp = {
    domain,
    records: {
      A: a.answers.map(x => x.data), AAAA: aaaa.answers.map(x => x.data),
      MX: mx.answers.map(x => x.data).sort(), NS: ns.answers.map(x => x.data), CAA: caa.answers.map(x => x.data), TXT: txts
    },
    email: {
      spf: spf || null,
      dmarc: dmarcRec || null,
      dmarcPolicy: dmarcPolicy || null,
      dkim: selector ? (dkim.answers.map(x => x.data).join('') || null) : undefined
    },
    dnssec: a.ad,
    summary: {
      spf: !!spf,
      dmarc: !!dmarcRec,
      dmarcStrong: /p=(reject|quarantine)/i.test(dmarcRec),
      dnssec: a.ad,
      caa: caa.answers.length > 0,
      mx: mx.answers.length > 0
    }
  };
  ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(resp), { expirationTtl: 3600 }));
  await bump(env, ctx, { scans_dns: 1 });
  return new Response(JSON.stringify(resp), { headers: { ...JSON_HEADERS, 'x-cache': 'MISS' } });
}

// ======================= stats =======================
async function apiStats(env) {
  const stats = {}; const top = [];
  try {
    const s = await env.DB.prepare('SELECT k, v FROM stats').all();
    (s.results || []).forEach(r => stats[r.k] = r.v);
    const f = await env.DB.prepare('SELECT id, n FROM findings ORDER BY n DESC LIMIT 10').all();
    (f.results || []).forEach(r => top.push({ id: r.id, n: r.n }));
  } catch (e) { /* table may be empty */ }
  return json({ stats, top });
}

// ---------- sha1 (cache keys) ----------
async function sha1(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
