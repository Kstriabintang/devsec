#!/usr/bin/env node
// =============================================================================
// DevSec Toolbox — static site generator.
// Reads tool metadata straight from app.js (single source of truth) and emits:
//   - index.html (home)                 - <id>/index.html for every tool
//   - arsenal/index.html (DevSecOps dir) - sitemap.xml
// Static HTML is for first paint + SEO; app.js takes over on load. English only.
//
// Run:  node build.mjs
// =============================================================================
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const BASE = 'https://devsec.ksatriabintangsamudra.com';
const VER = 'v18';
const GSV = 'ZlDKMH0Zt-Piim2iJGkBhoYrzPu76yamyCvyOlsnF5c'; // Google Search Console
const THEME = '#080b12';
const OG = `${BASE}/docs/home.png`;

const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// --- group order + CSS slugs (must match app.js GROUPS/SLUG) ---
const GROUPS = ['Scanners', 'Security', 'Encode / Decode', 'Format & Data', 'Generator', 'Converters'];
const SLUG = { 'Scanners': 'scanners', 'Security': 'keamanan', 'Encode / Decode': 'encode', 'Format & Data': 'format', 'Generator': 'generator', 'Converters': 'konversi' };

// --- extract tool metadata from app.js (id, grp, emoji, name, desc) ---
function extractTools() {
  const src = readFileSync(join(ROOT, 'app.js'), 'utf8');
  const re = /\{\s*id:\s*'([^']+)',\s*grp:\s*'([^']+)',\s*e:\s*'((?:\\'|[^'])*)',\s*(?:live:\s*true,\s*)?name:\s*'((?:\\'|[^'])*)',\s*desc:\s*'((?:\\'|[^'])*)'/g;
  const out = []; let m;
  const unq = s => s.replace(/\\'/g, "'");
  while ((m = re.exec(src)) !== null) out.push({ id: m[1], grp: unq(m[2]), e: unq(m[3]), name: unq(m[4]), desc: unq(m[5]) });
  return out;
}

const urlFor = id => id === 'home' ? `${BASE}/` : `${BASE}/${id}/`;
const gdot = g => `<span class="gdot" data-grp="${SLUG[g]}"></span>`;

// --- sidebar nav (full), with a given active tool + Arsenal link ---
function navHtml(tools, activeId) {
  const activeGrp = (tools.find(t => t.id === activeId) || {}).grp;
  let h = `<a class="nlink navhome${activeId === 'home' ? ' on' : ''}" data-id="home" href="${BASE}/"><span class="e">🏠</span> Home</a>`;
  for (const g of GROUPS) {
    const arr = tools.filter(t => t.grp === g);
    if (!arr.length) continue;
    const open = g === activeGrp;
    h += `<button type="button" class="grp${open ? ' open' : ''}" data-g="${SLUG[g]}" aria-expanded="${open}"><span class="gdot" data-grp="${SLUG[g]}"></span><span class="grp-name">${esc(g)}</span><span class="grp-cnt">${arr.length}</span><svg class="grp-chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></button>`;
    h += `<div class="grp-items${open ? ' open' : ''}" data-g="${SLUG[g]}">` + arr.map(t => `<a class="nlink${t.id === activeId ? ' on' : ''}" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span> ${esc(t.name)}</a>`).join('') + `</div>`;
  }
  // DevSecOps Arsenal (special directory view)
  h += `<a class="nlink navhome${activeId === 'arsenal' ? ' on' : ''}" data-id="arsenal" href="${BASE}/arsenal/" style="margin-top:8px"><span class="e">📚</span> DevSecOps Arsenal</a>`;
  return h;
}

function head({ title, desc, canonical, type = 'website', rel = '', jsonld = [] }) {
  const css = `${rel}style.css?${VER}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta name="robots" content="index,follow">
<meta name="google-site-verification" content="${GSV}">
<meta name="theme-color" content="${THEME}">
<link rel="canonical" href="${canonical}">
<meta property="og:type" content="${type}">
<meta property="og:site_name" content="DevSec Toolbox">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${OG}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2288%22>🧰</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="${css}">
${jsonld.map(j => `<script type="application/ld+json">${JSON.stringify(j)}</script>`).join('\n')}
</head>`;
}

function shell({ dataTool, h1, rel, navInner, mainInner }) {
  return `<body data-tool="${dataTool}">
<div class="app">
  <aside class="side" id="side">
    <a class="brand" href="${BASE}/" style="text-decoration:none;color:inherit"><span class="m">🧰</span><div><b>DevSec Toolbox</b><small>dev &amp; security tools</small></div></a>
    <div class="search"><input id="search" type="text" placeholder="Search tools… (e.g. jwt, hash)"></div>
    <nav class="nav" id="nav">${navInner}</nav>
    <div class="side-foot">🔒 <b>100% in your browser.</b> No data is sent to any server.</div>
  </aside>
  <main class="main">
    <div class="topbar">
      <button class="menutgl" id="menutgl" type="button" aria-label="Menu">☰</button>
      <h1 id="ttl">${esc(h1)}</h1>
      <span class="priv"><svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg> on-device</span>
    </div>
    ${mainInner}
  </main>
</div>
<div class="toast" id="toast">Copied ✓</div>
<script src="${rel}vendor/qrcode.js"></script>
<script type="module" src="${rel}app.js?${VER}"></script>
</body>
</html>`;
}

// --- home ---
function buildHome(tools) {
  const counts = Object.fromEntries(GROUPS.map(g => [g, tools.filter(t => t.grp === g).length]));
  const card = t => `<a class="hcard" data-grp="${SLUG[t.grp]}" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span><span class="hc-t"><b>${esc(t.name)}</b><span class="hc-d">${esc(t.desc)}</span></span><span class="hc-go">→</span></a>`;
  const grid = GROUPS.map(g => `<div class="home-grp">${gdot(g)}${esc(g)} <span class="hg-cnt">${counts[g]}</span></div><div class="home-grid">${tools.filter(t => t.grp === g).map(card).join('')}</div>`).join('');
  const chips = `<button class="chip on" data-g="all" type="button">All <span class="cnt">${tools.length}</span></button>` + GROUPS.map(g => `<button class="chip" data-g="${esc(g)}" type="button">${esc(g)} <span class="cnt">${counts[g]}</span></button>`).join('');
  const title = 'DevSec Toolbox — Free Developer & Security Tools (100% in Your Browser)';
  const desc = `A premium collection of ${tools.length}+ free developer & security tools that run entirely in your browser: JWT decoder, AES encryption, hashing, HMAC, JSON, regex, QR, secret scanner, and more. No server, no data sent anywhere.`;
  const jsonld = [
    { '@context': 'https://schema.org', '@type': 'WebSite', '@id': `${BASE}/#website`, url: `${BASE}/`, name: 'DevSec Toolbox', inLanguage: 'en' },
    { '@context': 'https://schema.org', '@type': 'WebApplication', '@id': `${BASE}/#app`, name: 'DevSec Toolbox', url: `${BASE}/`, applicationCategory: 'DeveloperApplication', operatingSystem: 'Any (web browser)', browserRequirements: 'Requires JavaScript', inLanguage: 'en', description: desc, offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' }, featureList: tools.map(t => t.name) },
    { '@context': 'https://schema.org', '@type': 'ItemList', name: 'DevSec Toolbox tools', itemListElement: tools.map((t, i) => ({ '@type': 'ListItem', position: i + 1, url: urlFor(t.id), name: t.name })) },
  ];
  const mainInner = `<div class="wrap"><div class="desc" id="desc"></div><div id="tool"><div class="home-hero">
    <div class="home-eyebrow">🧰 ${tools.length} tools · 100% in your browser · free</div>
    <h2>Developer &amp; security tools <span class="g">that just work</span> — right in your browser.</h2>
    <p>From JWT decoding, AES encryption, hashing &amp; HMAC to QR, regex, secret scanning &amp; converters — everything runs <b>inside your browser</b>, with no server and no data ever leaving your device. Free, for everyone.</p>
    <div class="home-search"><svg class="hs-ic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.2-4.2"/></svg><input id="hsearch" type="text" placeholder="Search tools… e.g. jwt, hash, qr, color, csv"><kbd>/</kbd></div>
    <div class="home-badges"><span class="hb">🔒 <b>On-device</b></span><span class="hb">⚡ <b>Instant</b></span><span class="hb">✅ <b>Tested</b></span><span class="hb">🆓 <b>No ads</b></span></div>
  </div>
  <div class="home-filter" id="hfilter">${chips}</div>
  <div id="hgrid">${grid}</div>
  <div class="home-foot">Built by <a href="https://ksatriabintangsamudra.my.id">Ksatria Bintang Samudra</a> · <a href="https://github.com/Kstriabintang/devsec" rel="noopener">source code</a> · every tool runs locally in your browser.</div></div></div>`;
  const html = head({ title, desc, canonical: `${BASE}/`, jsonld }) + shell({ dataTool: 'home', h1: 'Home', rel: '', navInner: navHtml(tools, 'home'), mainInner });
  writeFileSync(join(ROOT, 'index.html'), html);
}

// --- a tool page ---
function buildTool(tools, t) {
  const title = `${t.name} — Free Online Tool (100% in Browser) | DevSec Toolbox`;
  const desc = `${t.desc} Runs 100% in your browser — instant, private, free, no data sent to any server.`;
  const canonical = urlFor(t.id);
  const jsonld = [
    { '@context': 'https://schema.org', '@type': 'SoftwareApplication', name: t.name, url: canonical, applicationCategory: 'DeveloperApplication', operatingSystem: 'Any (web browser)', inLanguage: 'en', description: desc, isPartOf: { '@id': `${BASE}/#app` }, offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' } },
    { '@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: [{ '@type': 'ListItem', position: 1, name: 'DevSec Toolbox', item: `${BASE}/` }, { '@type': 'ListItem', position: 2, name: t.name, item: canonical }] },
  ];
  const mainInner = `<div class="wrap"><div class="desc" id="desc">${esc(t.desc)}</div><div id="tool"><div class="purpose"><span class="pi">${t.e}</span><div class="pt">${esc(t.desc)}</div></div></div></div>`;
  const html = head({ title, desc, canonical, rel: '../', jsonld }) + shell({ dataTool: t.id, h1: t.name, rel: '../', navInner: navHtml(tools, t.id), mainInner });
  const dir = join(ROOT, t.id);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'index.html'), html);
}

// --- arsenal directory page ---
function buildArsenal(tools) {
  const title = 'DevSecOps Arsenal — Curated Directory of the Best DevSecOps Tools | DevSec Toolbox';
  const desc = 'A curated directory of the best open-source DevSecOps tools — SAST, DAST, SCA, secrets detection, container, IaC, cloud & supply-chain security. Searchable, categorized, with links.';
  const canonical = `${BASE}/arsenal/`;
  const jsonld = [
    { '@context': 'https://schema.org', '@type': 'CollectionPage', name: 'DevSecOps Arsenal', url: canonical, inLanguage: 'en', description: desc, isPartOf: { '@id': `${BASE}/#website` } },
    { '@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: [{ '@type': 'ListItem', position: 1, name: 'DevSec Toolbox', item: `${BASE}/` }, { '@type': 'ListItem', position: 2, name: 'DevSecOps Arsenal', item: canonical }] },
  ];
  const mainInner = `<div class="wrap"><div class="desc" id="desc">A curated directory of the best DevSecOps tools.</div><div id="tool"><p class="arsenal-intro">Loading the curated catalogue…</p></div></div>`;
  const html = head({ title, desc, canonical, rel: '../', jsonld }) + shell({ dataTool: 'arsenal', h1: 'DevSecOps Arsenal', rel: '../', navInner: navHtml(tools, 'arsenal'), mainInner });
  const dir = join(ROOT, 'arsenal');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'index.html'), html);
}

// --- sitemap ---
function buildSitemap(tools) {
  const now = new Date().toISOString().slice(0, 10);
  const urls = [`${BASE}/`, `${BASE}/arsenal/`, ...tools.map(t => urlFor(t.id))];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    urls.map(u => `  <url><loc>${u}</loc><lastmod>${now}</lastmod><changefreq>monthly</changefreq><priority>${u === BASE + '/' ? '1.0' : '0.7'}</priority></url>`).join('\n') +
    `\n</urlset>\n`;
  writeFileSync(join(ROOT, 'sitemap.xml'), xml);
}

// --- run ---
const tools = extractTools();
if (tools.length < 30) { console.error(`✗ Only extracted ${tools.length} tools — aborting (check app.js regex).`); process.exit(1); }
buildHome(tools);
tools.forEach(t => buildTool(tools, t));
buildArsenal(tools);
buildSitemap(tools);
console.log(`✓ Generated: index.html + ${tools.length} tool pages + arsenal + sitemap (${VER}).`);
console.log(`  Tools: ${tools.map(t => t.id).join(', ')}`);
