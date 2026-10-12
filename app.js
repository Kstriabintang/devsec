// DevSec Toolbox — developer & security tools, 100% in-browser (no network).
// Each tool has a "tujuan" (what it's for & when to use it) + example. All verified against standard values.
const $ = (s, r = document) => r.querySelector(s);
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = new TextEncoder();
const fire = inp => inp.dispatchEvent(new Event('input', { bubbles: true }));

// App root (e.g. "/devsec/") — computed from app.js location so path-based routes work.
const BASE = new URL('.', import.meta.url).pathname;
// jsQR is lazy-loaded — only when the "QR Reader" tool is opened.
let _jsqr;
function loadJsQR() { return _jsqr || (_jsqr = new Promise((res, rej) => { const s = document.createElement('script'); s.src = new URL('vendor/jsqr.min.js', import.meta.url).href; s.onload = () => res(window.jsQR); s.onerror = () => rej(new Error('failed to load scanner')); document.head.appendChild(s); })); }
// Cleanup: tools that attach global listeners register them here so they're removed on tool switch.
let _cleanup = null;
function onCleanup(fn) { _cleanup = fn; }
function runCleanup() { if (_cleanup) { try { _cleanup(); } catch (e) { } _cleanup = null; } }

function toast(msg = 'Copied ✓') { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('on'), 1400); }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast()).catch(() => toast('Copy failed')); }
function withCopy(outEl, getText) { const b = el('button', 'copy', 'Copy'); b.type = 'button'; b.addEventListener('click', () => copy(typeof getText === 'function' ? getText() : outEl.innerText)); outEl.appendChild(b); return outEl; }

// ---------- global progress bar (top of screen) — NProgress-style, lightweight ----------
const dsTop = (() => { const b = el('div', 'ds-top', '<i></i>'); (document.body || document.documentElement).appendChild(b); return b; })();
const dsBar = dsTop.firstElementChild;
const prog = {
  _v: 0, _t: 0,
  start(indeterminate) { clearTimeout(this._t); this._v = 0.08; dsTop.classList.toggle('indet', !!indeterminate); dsTop.classList.add('on'); if (!indeterminate) dsBar.style.width = '8%'; },
  set(frac) { if (!dsTop.classList.contains('on')) this.start(false); dsTop.classList.remove('indet'); this._v = Math.max(this._v, Math.min(0.985, frac)); dsBar.style.width = (this._v * 100).toFixed(1) + '%'; },
  done() { clearTimeout(this._t); dsTop.classList.remove('indet'); dsBar.style.width = '100%'; this._t = setTimeout(() => { dsTop.classList.remove('on'); dsBar.style.width = '0'; }, 300); },
  pulse() { this.start(true); clearTimeout(this._t); this._t = setTimeout(() => this.done(), 260); }
};
// Show a "processing" status inside a .out + global progress bar, then run the async fn.
async function withProc(outEl, label, fn) {
  outEl.classList.remove('empty');
  outEl.innerHTML = `<div class="proc"><span class="spinner"></span>${esc(label || 'Processing…')}</div>`;
  prog.start(true);
  await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); // let the UI repaint
  try { const r = await fn(); prog.done(); return r; }
  catch (e) { prog.done(); throw e; }
}
// Read a file into an ArrayBuffer with real progress events (for large files).
function readFileProgress(file, onFrac) { return new Promise((res, rej) => { const r = new FileReader(); r.onprogress = e => { if (e.lengthComputable && onFrac) onFrac(e.loaded / e.total); }; r.onload = () => res(r.result); r.onerror = () => rej(new Error('failed to read file')); r.readAsArrayBuffer(file); }); }

// ---------- crypto utils ----------
async function sha(algo, dataStrOrBuf) { const data = typeof dataStrOrBuf === 'string' ? enc.encode(dataStrOrBuf) : dataStrOrBuf; const buf = await crypto.subtle.digest(algo, data); return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hmacSha256(key, msg) { const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const sig = await crypto.subtle.sign('HMAC', k, enc.encode(msg)); return new Uint8Array(sig); }
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64url = u8 => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlToStr = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; try { return decodeURIComponent(escape(atob(s))); } catch (e) { return atob(s); } };
function md5(str) { function rl(n, s) { return (n << s) | (n >>> (32 - s)); } function au(x, y) { const l = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xFFFF); } function cmn(q, a, b, x, s, t) { return au(rl(au(au(a, q), au(x, t)), s), b); } const FF = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t); const GG = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t); const HH = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t); const II = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t); function tb(s) { const b = unescape(encodeURIComponent(s)); const n = []; for (let i = 0; i < b.length * 8; i += 8) n[i >> 5] |= (b.charCodeAt(i / 8) & 0xFF) << (i % 32); return n; } function bh(n) { let s = ''; for (let i = 0; i < n.length * 4; i++) s += ((n[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF).toString(16) + ((n[i >> 2] >> ((i % 4) * 8)) & 0xF).toString(16); return s; } const x = tb(str), len = unescape(encodeURIComponent(str)).length * 8; x[len >> 5] |= 0x80 << (len % 32); x[(((len + 64) >>> 9) << 4) + 14] = len; let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878; for (let i = 0; i < x.length; i += 16) { const oa = a, ob = b, oc = c, od = d; a = FF(a, b, c, d, x[i], 7, -680876936); d = FF(d, a, b, c, x[i + 1], 12, -389564586); c = FF(c, d, a, b, x[i + 2], 17, 606105819); b = FF(b, c, d, a, x[i + 3], 22, -1044525330); a = FF(a, b, c, d, x[i + 4], 7, -176418897); d = FF(d, a, b, c, x[i + 5], 12, 1200080426); c = FF(c, d, a, b, x[i + 6], 17, -1473231341); b = FF(b, c, d, a, x[i + 7], 22, -45705983); a = FF(a, b, c, d, x[i + 8], 7, 1770035416); d = FF(d, a, b, c, x[i + 9], 12, -1958414417); c = FF(c, d, a, b, x[i + 10], 17, -42063); b = FF(b, c, d, a, x[i + 11], 22, -1990404162); a = FF(a, b, c, d, x[i + 12], 7, 1804603682); d = FF(d, a, b, c, x[i + 13], 12, -40341101); c = FF(c, d, a, b, x[i + 14], 17, -1502002290); b = FF(b, c, d, a, x[i + 15], 22, 1236535329); a = GG(a, b, c, d, x[i + 1], 5, -165796510); d = GG(d, a, b, c, x[i + 6], 9, -1069501632); c = GG(c, d, a, b, x[i + 11], 14, 643717713); b = GG(b, c, d, a, x[i], 20, -373897302); a = GG(a, b, c, d, x[i + 5], 5, -701558691); d = GG(d, a, b, c, x[i + 10], 9, 38016083); c = GG(c, d, a, b, x[i + 15], 14, -660478335); b = GG(b, c, d, a, x[i + 4], 20, -405537848); a = GG(a, b, c, d, x[i + 9], 5, 568446438); d = GG(d, a, b, c, x[i + 14], 9, -1019803690); c = GG(c, d, a, b, x[i + 3], 14, -187363961); b = GG(b, c, d, a, x[i + 8], 20, 1163531501); a = GG(a, b, c, d, x[i + 13], 5, -1444681467); d = GG(d, a, b, c, x[i + 2], 9, -51403784); c = GG(c, d, a, b, x[i + 7], 14, 1735328473); b = GG(b, c, d, a, x[i + 12], 20, -1926607734); a = HH(a, b, c, d, x[i + 5], 4, -378558); d = HH(d, a, b, c, x[i + 8], 11, -2022574463); c = HH(c, d, a, b, x[i + 11], 16, 1839030562); b = HH(b, c, d, a, x[i + 14], 23, -35309556); a = HH(a, b, c, d, x[i + 1], 4, -1530992060); d = HH(d, a, b, c, x[i + 4], 11, 1272893353); c = HH(c, d, a, b, x[i + 7], 16, -155497632); b = HH(b, c, d, a, x[i + 10], 23, -1094730640); a = HH(a, b, c, d, x[i + 13], 4, 681279174); d = HH(d, a, b, c, x[i], 11, -358537222); c = HH(c, d, a, b, x[i + 3], 16, -722521979); b = HH(b, c, d, a, x[i + 6], 23, 76029189); a = HH(a, b, c, d, x[i + 9], 4, -640364487); d = HH(d, a, b, c, x[i + 12], 11, -421815835); c = HH(c, d, a, b, x[i + 15], 16, 530742520); b = HH(b, c, d, a, x[i + 2], 23, -995338651); a = II(a, b, c, d, x[i], 6, -198630844); d = II(d, a, b, c, x[i + 7], 10, 1126891415); c = II(c, d, a, b, x[i + 14], 15, -1416354905); b = II(b, c, d, a, x[i + 5], 21, -57434055); a = II(a, b, c, d, x[i + 12], 6, 1700485571); d = II(d, a, b, c, x[i + 3], 10, -1894986606); c = II(c, d, a, b, x[i + 10], 15, -1051523); b = II(b, c, d, a, x[i + 1], 21, -2054922799); a = II(a, b, c, d, x[i + 8], 6, 1873313359); d = II(d, a, b, c, x[i + 15], 10, -30611744); c = II(c, d, a, b, x[i + 6], 15, -1560198380); b = II(b, c, d, a, x[i + 13], 21, 1309151649); a = II(a, b, c, d, x[i + 4], 6, -145523070); d = II(d, a, b, c, x[i + 11], 10, -1120210379); c = II(c, d, a, b, x[i + 2], 15, 718787259); b = II(b, c, d, a, x[i + 9], 21, -343485551); a = au(a, oa); b = au(b, ob); c = au(c, oc); d = au(d, od); } return bh([a, b, c, d]); }

const setOut = (out, txt) => { out.textContent = txt || '—'; out.classList.toggle('empty', !txt); if (txt) withCopy(out, () => txt); };
const setErr = (out, msg) => { out.innerHTML = '<span class="pill err">' + esc(msg) + '</span>'; out.classList.remove('empty'); };

// ================= TOOL REGISTRY =================
const TOOLS = [
  // ---------- SECURITY ----------
  { id: 'jwt', grp: 'Security', e: '🎫', name: 'JWT Decoder & Verify', desc: 'Decode a JWT and (optionally) verify its HS256 signature.',
    tujuan: '<b>What it\'s for:</b> JWTs are used for login sessions & API authorization. This tool reads a token\'s contents (who, role, when it expires) and can <b>verify</b> whether a token is genuine/untampered (HS256) using your secret. <b>When:</b> debugging authentication or inspecting a suspicious token — everything runs in the browser, the token is never sent.',
    contoh(root) { $('#in', root).value = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik5hZGlhIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE3NjcyMjU2MDB9.3Toql3l7Wzn3f0dW8kK5m0dW3Zt6xO2xU5aQ2vFqk1o'; $('#sec', root).value = ''; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JWT token</label><textarea id="in" placeholder="eyJhbGciOi..."></textarea>
        <label class="lbl" style="margin-top:12px">Secret (optional — for HS256 verification)</label><input class="f" id="sec" placeholder="HMAC secret">
        <div class="cardrow" style="margin-top:14px"><div><label class="lbl">Header</label><div class="out empty" id="h">—</div></div><div><label class="lbl">Payload</label><div class="out empty" id="p">—</div></div></div>
        <div id="verify" style="margin-top:12px"></div><div id="claims"></div>`;
      const run = async () => {
        const t = $('#in', root).value.trim(), H = $('#h', root), P = $('#p', root), C = $('#claims', root), V = $('#verify', root);
        C.innerHTML = ''; V.innerHTML = '';
        if (!t) { H.textContent = P.textContent = '—'; H.classList.add('empty'); P.classList.add('empty'); return; }
        const parts = t.split('.'); if (parts.length < 2) return setErr(H, 'Not a valid JWT (needs header.payload.signature)');
        let hd, pl;
        try { hd = JSON.parse(b64urlToStr(parts[0])); pl = JSON.parse(b64urlToStr(parts[1])); } catch (e) { return setErr(H, 'Decode failed: ' + e.message); }
        H.textContent = JSON.stringify(hd, null, 2); H.classList.remove('empty'); withCopy(H, () => JSON.stringify(hd, null, 2));
        P.textContent = JSON.stringify(pl, null, 2); P.classList.remove('empty'); withCopy(P, () => JSON.stringify(pl, null, 2));
        const now = Math.floor(Date.now() / 1000), fmt = s => new Date(s * 1000).toLocaleString(), rows = [];
        if (hd.alg) rows.push(['Algorithm', hd.alg]);
        if (pl.iat) rows.push(['Issued at (iat)', fmt(pl.iat)]);
        if (pl.exp) rows.push(['Expires (exp)', fmt(pl.exp) + (pl.exp > now ? '  ✓ still valid' : '  ✕ EXPIRED')]);
        if (pl.sub) rows.push(['Subject (sub)', pl.sub]); if (pl.iss) rows.push(['Issuer (iss)', pl.iss]);
        if (rows.length) C.innerHTML = '<label class="lbl" style="margin-top:14px">Claims</label>' + rows.map(r => `<div class="kv"><span class="k">${esc(r[0])}</span><span class="v">${esc(r[1])}</span></div>`).join('');
        const sec = $('#sec', root).value;
        if (sec && parts[2]) {
          if (hd.alg !== 'HS256') { V.innerHTML = '<span class="pill warn">Auto-verification is HS256-only (this token is ' + esc(hd.alg || '?') + ')</span>'; return; }
          const sig = await hmacSha256(sec, parts[0] + '.' + parts[1]);
          const ok = b64url(sig) === parts[2];
          V.innerHTML = ok ? '<span class="pill ok">✓ Signature VALID — token is genuine</span>' : '<span class="pill err">✕ Signature does NOT match — forged token / wrong secret</span>';
        }
      };
      $('#in', root).addEventListener('input', run); $('#sec', root).addEventListener('input', run);
    } },

  { id: 'jwtgen', grp: 'Security', e: '🏷️', name: 'JWT Generator (HS256)', desc: 'Create & sign an HS256 JWT from a payload + secret.',
    tujuan: '<b>What it\'s for:</b> create an <b>HS256</b>-signed JWT from your payload (claims) &amp; secret — to test APIs/authorization without a backend. <b>When:</b> you need a quick test token. The payload &amp; secret never leave the browser. <b>Note:</b> never paste a real production secret into any online tool.',
    contoh(root) { $('#pl', root).value = '{\n  "sub": "1234567890",\n  "name": "Nadia",\n  "role": "admin"\n}'; $('#sec', root).value = 'secret'; fire($('#pl', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Payload (JSON)</label><textarea id="pl" style="min-height:120px" placeholder='{"sub":"123","role":"admin"}'></textarea>
        <div class="row" style="margin-top:10px"><label class="chk"><input type="checkbox" id="iat" checked> Add iat (now)</label><label class="chk"><input type="checkbox" id="exp"> Add exp (+1 hour)</label></div>
        <label class="lbl" style="margin-top:8px">Secret (HMAC)</label><input class="f" id="sec" placeholder="secret">
        <label class="lbl" style="margin-top:12px">JWT token</label><div class="out empty" id="out">—</div>
        <div class="note">The result can be checked directly in the <b>JWT Decoder &amp; Verify</b> tool (paste the token + the same secret).</div>`;
      const b64urlJson = o => b64url(enc.encode(JSON.stringify(o)));
      const run = async () => {
        const out = $('#out', root), raw = $('#pl', root).value.trim(); if (!raw) { out.textContent = '—'; out.classList.add('empty'); return; }
        let pl; try { pl = JSON.parse(raw); } catch (e) { return setErr(out, 'Payload is not valid JSON: ' + e.message); }
        if (typeof pl !== 'object' || Array.isArray(pl) || pl === null) return setErr(out, 'Payload must be an object {…}');
        const sec = $('#sec', root).value; if (!sec) return setErr(out, 'Enter the HMAC secret first');
        const now = Math.floor(Date.now() / 1000); if ($('#iat', root).checked) pl.iat = now; if ($('#exp', root).checked) pl.exp = now + 3600;
        const signingInput = b64urlJson({ alg: 'HS256', typ: 'JWT' }) + '.' + b64urlJson(pl);
        const token = signingInput + '.' + b64url(await hmacSha256(sec, signingInput));
        out.classList.remove('empty'); out.textContent = token; withCopy(out, () => token);
      };
      root.querySelectorAll('textarea,input').forEach(x => x.addEventListener('input', run));
    } },

  { id: 'aes', grp: 'Security', e: '🔒', name: 'AES Encryption', desc: 'Encrypt & decrypt text with AES-256-GCM + a password (PBKDF2).',
    tujuan: '<b>What it\'s for:</b> lock secret text (notes, API keys, messages) with <b>AES-256-GCM</b> — a strong encryption standard. The key is derived from your password via <b>PBKDF2 (150,000 iterations)</b> + a random salt, so only someone who knows the password can unlock it. <b>When:</b> sending sensitive text over an insecure channel. Everything runs in the browser — the text &amp; password never leave.',
    contoh(root) { $('#pass', root).value = 'secret123'; $('#in', root).value = 'This is a secret message to test 🔐'; $('#m button[data-m=enc]', root).click(); $('#go', root).click(); },
    body(root) {
      let mode = 'enc';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="enc" class="on">Encrypt</button><button data-m="dec">Decrypt</button></div></div>
        <label class="lbl">Password</label><input class="f" id="pass" type="text" placeholder="secret password">
        <label class="lbl" style="margin-top:12px" id="inl">Text</label><textarea id="in" placeholder="text…"></textarea>
        <button class="btn acc" id="go" type="button" style="margin-top:12px">Run</button>
        <label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>
        <div class="note">Output format: Base64 of <span class="mono">salt(16) + iv(12) + ciphertext</span>. To decrypt, paste that entire Base64 back &amp; the same password.</div>`;
      const setMode = m => { mode = m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b.dataset.m === m)); $('#inl', root).textContent = m === 'enc' ? 'Text (plaintext)' : 'Encrypted Base64'; };
      $('#m', root).addEventListener('click', e => { if (e.target.dataset.m) setMode(e.target.dataset.m); });
      async function deriveKey(pass, salt) { const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']); return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }
      $('#go', root).addEventListener('click', async () => {
        const pass = $('#pass', root).value, v = $('#in', root).value, out = $('#out', root), btn = $('#go', root);
        if (!pass) return setErr(out, 'Enter a password first'); if (!v) return setErr(out, 'Enter some text first');
        btn.classList.add('loading'); const label = btn.textContent; btn.textContent = mode === 'enc' ? 'Encrypting…' : 'Decrypting…';
        try {
          await withProc(out, mode === 'enc' ? 'Deriving key (PBKDF2 · 150,000 iterations) & encrypting…' : 'Deriving key & decrypting…', async () => {
            if (mode === 'enc') {
              const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
              const key = await deriveKey(pass, salt);
              const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(v)));
              const bundle = new Uint8Array(28 + ct.length); bundle.set(salt, 0); bundle.set(iv, 16); bundle.set(ct, 28);
              setOut(out, b64(bundle));
            } else {
              const raw = unb64(v.trim().replace(/\s+/g, '')); const salt = raw.slice(0, 16), iv = raw.slice(16, 28), ct = raw.slice(28);
              const key = await deriveKey(pass, salt);
              const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
              setOut(out, new TextDecoder().decode(pt));
            }
          });
        } catch (e) { setErr(out, mode === 'dec' ? 'Decryption failed — wrong password or corrupted data' : e.message); }
        finally { btn.classList.remove('loading'); btn.textContent = label; }
      });
    } },

  { id: 'hash', grp: 'Security', e: '#️⃣', name: 'Text Hash', desc: 'Compute MD5, SHA-1, SHA-256, SHA-512 of text at once.',
    tujuan: '<b>What it\'s for:</b> a digital "fingerprint" of a piece of text. Same hash = same content; a tiny change = a completely different hash. <b>When:</b> checking integrity, storing a checksum, or comparing data. Note: MD5 &amp; SHA-1 are now <b>insecure for security purposes</b> (collision-prone) — use SHA-256+.',
    contoh(root) { $('#in', root).value = 'abc'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Text</label><textarea id="in" placeholder="Type text…"></textarea><div id="out" style="margin-top:14px"></div>`;
      const run = async () => { const v = $('#in', root).value, out = $('#out', root); if (!v) { out.innerHTML = '<div class="out empty">—</div>'; return; } const [s1, s256, s512] = await Promise.all([sha('SHA-1', v), sha('SHA-256', v), sha('SHA-512', v)]); const items = [['MD5', md5(v)], ['SHA-1', s1], ['SHA-256', s256], ['SHA-512', s512]]; out.innerHTML = items.map(([k, h]) => `<label class="lbl">${k}</label><div class="out">${esc(h)}<button class="copy" data-c="${esc(h)}">Copy</button></div>`).join(''); out.querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c))); };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'hashfile', grp: 'Security', e: '📂', name: 'Hash File', desc: 'Compute SHA-256/SHA-1/SHA-512 of a file (integrity check).',
    tujuan: '<b>What it\'s for:</b> confirm that a file you downloaded is <b>intact &amp; unaltered</b> — compare its hash against the one published by the author. <b>When:</b> after downloading an installer, ISO, or software release. The file is processed locally, never uploaded anywhere.',
    body(root) {
      root.innerHTML = `<div class="drop" id="drop"><div class="big">Drop a file here</div><div>or click to choose · file not uploaded</div></div>
        <input type="file" id="file" style="display:none"><div id="meta" class="note"></div><div id="out" style="margin-top:12px"></div>`;
      const drop = $('#drop', root), file = $('#file', root);
      const run = async f => {
        if (!f) return;
        const mb = f.size / 1048576;
        $('#meta', root).innerHTML = `<b>${esc(f.name)}</b> · ${mb >= 1 ? mb.toFixed(2) + ' MB' : (f.size / 1024).toFixed(1) + ' KB'}`;
        const out = $('#out', root);
        out.innerHTML = `<div class="progress-lbl"><span>Reading file…</span><span id="pct">0%</span></div><div class="progress"><i id="pbar"></i></div>`;
        prog.start(false);
        let buf;
        try {
          buf = await readFileProgress(f, frac => { const p = Math.round(frac * 100); const bar = $('#pbar', out), pc = $('#pct', out); if (bar) bar.style.width = (frac * 90) + '%'; if (pc) pc.textContent = p + '%'; prog.set(frac * 0.9); });
        } catch (e) { prog.done(); return setErr(out, e.message); }
        out.innerHTML = `<div class="proc"><span class="spinner"></span>Computing hash (SHA-256 · SHA-1 · SHA-512)…</div>`;
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        const [s256, s1, s512] = await Promise.all([sha('SHA-256', buf), sha('SHA-1', buf), sha('SHA-512', buf)]);
        prog.done();
        const items = [['SHA-256', s256], ['SHA-1', s1], ['SHA-512', s512]];
        out.innerHTML = items.map(([k, h]) => `<label class="lbl">${k}</label><div class="out">${esc(h)}<button class="copy" data-c="${esc(h)}">Copy</button></div>`).join('');
        out.querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c)));
      };
      drop.addEventListener('click', () => file.click());
      file.addEventListener('change', e => run(e.target.files[0]));
      drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', () => drop.classList.remove('over'));
      drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); run(e.dataTransfer.files[0]); });
    } },

  { id: 'hmac', grp: 'Security', e: '🔑', name: 'HMAC-SHA256', desc: 'Compute HMAC-SHA256 of a message using a secret key.',
    tujuan: '<b>What it\'s for:</b> prove a message really came from someone who knows the secret &amp; was not altered (message authentication). <b>When:</b> signing webhooks, verifying payment callbacks, or API signatures.',
    contoh(root) { $('#key', root).value = 'secret-key'; $('#in', root).value = 'important message'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Secret key</label><input class="f" id="key" placeholder="secret key"><label class="lbl" style="margin-top:12px">Message</label><textarea id="in" placeholder="message…"></textarea><label class="lbl" style="margin-top:12px">HMAC-SHA256 (hex)</label><div class="out empty" id="out">—</div>`;
      const run = async () => { const k = $('#key', root).value, m = $('#in', root).value, out = $('#out', root); if (!k || !m) { setOut(out, ''); return; } setOut(out, hex(await hmacSha256(k, m))); };
      $('#key', root).addEventListener('input', run); $('#in', root).addEventListener('input', run);
    } },

  { id: 'password', grp: 'Security', e: '🎲', name: 'Password Generator', desc: 'Generate strong random (cryptographic) passwords + entropy meter.',
    tujuan: '<b>What it\'s for:</b> generate truly random, hard-to-guess passwords using a cryptographic generator (not Math.random). <b>When:</b> whenever you need a new password/key. The longer &amp; more varied, the higher the entropy.',
    body(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Length</label><input class="f" id="len" type="number" value="16" min="4" max="128" style="width:100px">
        <label class="chk"><input type="checkbox" id="up" checked> A-Z</label><label class="chk"><input type="checkbox" id="lo" checked> a-z</label><label class="chk"><input type="checkbox" id="nu" checked> 0-9</label><label class="chk"><input type="checkbox" id="sy" checked> symbols</label>
        <button class="btn acc" id="gen" type="button">Generate</button></div>
        <div class="out empty big" id="out" style="margin-top:12px">—</div><div id="meter" class="note"></div>`;
      const run = () => { let set = ''; if ($('#up', root).checked) set += 'ABCDEFGHJKLMNPQRSTUVWXYZ'; if ($('#lo', root).checked) set += 'abcdefghijkmnpqrstuvwxyz'; if ($('#nu', root).checked) set += '23456789'; if ($('#sy', root).checked) set += '!@#$%^&*()-_=+[]{};:,.?'; const out = $('#out', root); if (!set) { out.textContent = 'Select at least one character type'; return; } const len = Math.max(4, Math.min(128, +$('#len', root).value || 16)); const rnd = crypto.getRandomValues(new Uint32Array(len)); let pw = ''; for (let i = 0; i < len; i++) pw += set[rnd[i] % set.length]; setOut(out, pw); const bits = Math.round(len * Math.log2(set.length)); const lvl = bits < 50 ? ['Weak', 'err'] : bits < 80 ? ['Fair', 'warn'] : ['Strong', 'ok']; $('#meter', root).innerHTML = `Entropy ≈ <b>${bits} bits</b> · <span class="pill ${lvl[1]}">${lvl[0]}</span>`; };
      root.querySelectorAll('input').forEach(x => x.addEventListener('input', run)); $('#gen', root).addEventListener('click', run); run();
    } },

  { id: 'pwcheck', grp: 'Security', e: '🛡️', name: 'Password Strength', desc: 'Estimate password strength & how long it would take to crack.',
    tujuan: '<b>What it\'s for:</b> gauge how secure a password is — estimate its entropy &amp; how long it would take to guess by brute force. <b>When:</b> checking a password before using it. The password is never sent anywhere; this is a rough estimate for education, not a guarantee.',
    contoh(root) { $('#in', root).value = 'P@ssw0rd2024'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Password</label><input class="f" id="in" type="text" placeholder="type a password to assess"><div id="out" style="margin-top:14px"></div>`;
      const COMMON = ['password', 'qwerty', '123456', 'admin', '111111', 'iloveyou', 'welcome', 'letmein', 'monkey', 'dragon', 'abc123', 'p@ssw0rd'];
      const run = () => {
        const v = $('#in', root).value, out = $('#out', root); if (!v) { out.innerHTML = ''; return; }
        let pool = 0; if (/[a-z]/.test(v)) pool += 26; if (/[A-Z]/.test(v)) pool += 26; if (/[0-9]/.test(v)) pool += 10; if (/[^a-zA-Z0-9]/.test(v)) pool += 33;
        let bits = v.length * Math.log2(pool || 1);
        const warns = [];
        if (COMMON.some(c => v.toLowerCase().includes(c))) { bits = Math.min(bits, 14); warns.push('Contains a common password'); }
        if (/^(.)\1+$/.test(v)) { bits = Math.min(bits, 10); warns.push('Repeated characters'); }
        if (/^(0123456789|abcdefghijklmnopqrstuvwxyz|qwertyuiop)/i.test(v)) { bits = Math.min(bits, 15); warns.push('Sequential pattern'); }
        if (v.length < 8) warns.push('Too short (< 8 characters)');
        const guesses = Math.pow(2, bits) / 2, perSec = 1e10, secs = guesses / perSec;
        const human = s => s < 1 ? 'instantly' : s < 60 ? Math.round(s) + ' seconds' : s < 3600 ? Math.round(s / 60) + ' minutes' : s < 86400 ? Math.round(s / 3600) + ' hours' : s < 31536000 ? Math.round(s / 86400) + ' days' : s < 3.15e9 ? Math.round(s / 31536000) + ' years' : (s / 31536000).toExponential(1) + ' years';
        const lvl = bits < 40 ? ['Very Weak', 'err'] : bits < 60 ? ['Weak', 'err'] : bits < 80 ? ['Fair', 'warn'] : bits < 100 ? ['Strong', 'ok'] : ['Very Strong', 'ok'];
        out.innerHTML = `<div class="kv"><span class="k">Strength</span><span class="v"><span class="pill ${lvl[1]}">${lvl[0]}</span></span></div>
          <div class="kv"><span class="k">Entropy</span><span class="v">${Math.round(bits)} bits</span></div>
          <div class="kv"><span class="k">Length</span><span class="v">${v.length} characters</span></div>
          <div class="kv"><span class="k">Estimated time to crack</span><span class="v">${human(secs)}</span></div>
          ${warns.length ? '<div class="note" style="margin-top:10px">⚠️ ' + warns.map(esc).join(' · ') + '</div>' : ''}
          <div class="note">Assumes 10 billion guesses/second (offline attack). Educational estimate.</div>`;
      };
      $('#in', root).addEventListener('input', run);
    } },

  // ---------- ENCODE / DECODE ----------
  { id: 'base64', grp: 'Encode / Decode', e: '🔡', name: 'Base64', desc: 'Encode & decode Base64 text (UTF-8 & URL-safe).',
    tujuan: '<b>What it\'s for:</b> turn text/binary into transport-safe text (only A–Z, 0–9, +/). <b>When:</b> embedding data in a URL, JSON, JWT, data URI, or email. Base64 is <b>not encryption</b> — anyone can decode it.',
    contoh(root) { $('#in', root).value = 'Hello World 🌍'; fire($('#in', root)); },
    body(root) {
      let mode = 'encode', us = false;
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div><label class="chk"><input type="checkbox" id="us"> URL-safe</label></div><label class="lbl">Input</label><textarea id="in" placeholder="Type text…"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { let r; if (mode === 'encode') { r = btoa(unescape(encodeURIComponent(v))); if (us) r = r.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); } else { let s = v.trim(); if (us || /[-_]/.test(s)) s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; r = decodeURIComponent(escape(atob(s))); } setOut(out, r); } catch (e) { setErr(out, 'Invalid input'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#us', root).addEventListener('change', e => { us = e.target.checked; run(); }); $('#in', root).addEventListener('input', run);
    } },

  { id: 'url', grp: 'Encode / Decode', e: '🔗', name: 'URL Encode', desc: 'Encode & decode URL components (encodeURIComponent).',
    tujuan: '<b>What it\'s for:</b> make text safe inside a URL — spaces, &amp;, ?, / become %XX. <b>When:</b> building a query string or link parameters by hand.',
    contoh(root) { $('#in', root).value = 'name=Alex & city=Berlin?'; fire($('#in', root)); },
    body(root) { let mode = 'encode'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in" placeholder="text or URL…"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`; const run = () => { const v = $('#in', root).value, out = $('#out', root); try { setOut(out, mode === 'encode' ? encodeURIComponent(v) : decodeURIComponent(v)); } catch (e) { setErr(out, 'Invalid input'); } }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  { id: 'htmlent', grp: 'Encode / Decode', e: '🏷️', name: 'HTML Entities', desc: 'Encode & decode HTML entities to display < > & on the web.',
    tujuan: '<b>What it\'s for:</b> display special characters (&lt; &gt; &amp; " \') as text in HTML without being treated as tags — preventing broken markup &amp; XSS. <b>When:</b> showing code/user text on a web page.',
    contoh(root) { $('#in', root).value = '<a href="x">Tom & Jerry</a>'; fire($('#in', root)); },
    body(root) { let mode = 'encode'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`; const ta = document.createElement('textarea'); const run = () => { const v = $('#in', root).value, out = $('#out', root); let r; if (mode === 'encode') r = v.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); else { ta.innerHTML = v; r = ta.value; } setOut(out, r); }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  { id: 'escape', grp: 'Encode / Decode', e: '⤵️', name: 'Escape String', desc: 'Escape & unescape JSON/JS-style strings (\\n, \\t, \\uXXXX).',
    tujuan: '<b>What it\'s for:</b> turn multi-line/special-character text into a single safe line to drop into code/JSON, and back again. <b>When:</b> pasting multi-line text into a code string or JSON file.',
    contoh(root) { $('#in', root).value = 'Line 1\nLine 2\t"quote"'; fire($('#in', root)); },
    body(root) { let mode = 'escape'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="escape" class="on">Escape</button><button data-m="unescape">Unescape</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`; const run = () => { const v = $('#in', root).value, out = $('#out', root); try { setOut(out, mode === 'escape' ? JSON.stringify(v).slice(1, -1) : JSON.parse('"' + v.replace(/"/g, '\\"') + '"')); } catch (e) { setErr(out, 'Cannot unescape'); } }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  { id: 'datauri', grp: 'Encode / Decode', e: '🖼️', name: 'Data URI (Base64 Image)', desc: 'Convert image ↔ base64 Data URI to embed in HTML/CSS.',
    tujuan: '<b>What it\'s for:</b> turn a small image (icon/logo) into a base64 <b>Data URI</b> so it can be pasted directly into HTML/CSS with no separate file — saving a request. It also works the other way: display &amp; download an image from a Data URI. <b>When:</b> embedding an inline icon, or inspecting a Data URI\'s contents. Everything is processed locally.',
    body(root) {
      let mode = 'encode';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Image → Data URI</button><button data-m="decode">Data URI → Image</button></div></div>
        <div id="encbox"><div class="drop" id="drop"><div class="big">Drop an image here</div><div>or click to choose · small icons are ideal · not uploaded</div></div><input type="file" id="file" accept="image/*" style="display:none"></div>
        <div id="decbox" style="display:none"><label class="lbl">Data URI</label><textarea id="din" placeholder="data:image/png;base64,iVBOR…"></textarea></div>
        <div id="preview"></div>`;
      const preview = $('#preview', root);
      function showEncoded(dataUri, size) {
        const kb = (size / 1024).toFixed(1), chars = dataUri.length;
        preview.innerHTML = `<div class="uri-prev"><img alt="preview"></div>
          <div class="note">Original size ${kb} KB · Data URI ${chars.toLocaleString('en')} characters${chars > 1e5 ? ' · <span class="pill warn">fairly large for inline</span>' : ''}</div>
          <label class="lbl" style="margin-top:12px">Data URI</label><div class="out" id="out2"></div>
          <div class="row" style="margin-top:10px"><button class="btn sm" data-c="css" type="button">Copy CSS url()</button><button class="btn sm" data-c="img" type="button">Copy &lt;img&gt;</button></div>`;
        preview.querySelector('.uri-prev img').src = dataUri;
        const out = $('#out2', preview); out.textContent = dataUri; withCopy(out, () => dataUri);
        preview.querySelector('[data-c=css]').addEventListener('click', () => copy(`background-image:url("${dataUri}");`));
        preview.querySelector('[data-c=img]').addEventListener('click', () => copy(`<img src="${dataUri}" alt="">`));
      }
      const handleFile = f => { if (!f || !f.type.startsWith('image/')) { preview.innerHTML = '<span class="pill err">Not an image file</span>'; return; } const r = new FileReader(); r.onload = () => showEncoded(r.result, f.size); r.readAsDataURL(f); };
      const drop = $('#drop', root), file = $('#file', root);
      drop.addEventListener('click', () => file.click());
      file.addEventListener('change', e => handleFile(e.target.files[0]));
      drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', () => drop.classList.remove('over'));
      drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); handleFile(e.dataTransfer.files[0]); });
      const decode = () => { const v = $('#din', root).value.trim(); if (!v) { preview.innerHTML = ''; return; } if (!/^data:image\//i.test(v)) { preview.innerHTML = '<span class="pill err">Must start with data:image/…</span>'; return; } preview.innerHTML = `<div class="uri-prev"><img alt="preview"></div><div class="row" style="margin-top:10px"><button class="btn sm" id="dl" type="button">⭳ Download image</button></div>`; const img = preview.querySelector('.uri-prev img'); img.onerror = () => { const w = preview.querySelector('.uri-prev'); if (w) w.innerHTML = '<span class="pill err">Invalid Data URI</span>'; }; img.src = v; const dl = $('#dl', preview); dl.addEventListener('click', () => { const a = document.createElement('a'); a.href = v; a.download = 'image'; a.click(); }); };
      $('#din', root).addEventListener('input', decode);
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); $('#encbox', root).style.display = mode === 'encode' ? '' : 'none'; $('#decbox', root).style.display = mode === 'decode' ? '' : 'none'; preview.innerHTML = ''; });
    } },

  // ---------- FORMAT & DATA ----------
  { id: 'json', grp: 'Format & Data', e: '📦', name: 'JSON Formatter', desc: 'Beautify, minify, & validate JSON with error messages.',
    tujuan: '<b>What it\'s for:</b> tidy up messy JSON so it\'s easy to read, compact it for production, and check whether it\'s valid. <b>When:</b> reading an API response or editing a config file.',
    contoh(root) { $('#in', root).value = '{"name":"Alex","age":25,"skills":["JS","Go"],"active":true}'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><button class="btn acc sm" id="fmt" type="button">Beautify</button><button class="btn sm" id="min" type="button">Minify</button><span id="stat"></span></div><label class="lbl">JSON</label><textarea id="in" style="min-height:180px" placeholder='{"hello":"world"}'></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`; const parse = () => { const v = $('#in', root).value.trim(), stat = $('#stat', root); if (!v) { stat.innerHTML = ''; return null; } try { const o = JSON.parse(v); stat.innerHTML = '<span class="pill ok">Valid</span>'; return o; } catch (e) { stat.innerHTML = '<span class="pill err">' + esc(e.message) + '</span>'; return undefined; } }; const show = (o, sp) => { const out = $('#out', root); if (o === undefined) return setErr(out, 'Invalid JSON'); if (o === null) { setOut(out, ''); return; } setOut(out, JSON.stringify(o, null, sp)); }; $('#fmt', root).addEventListener('click', () => show(parse(), 2)); $('#min', root).addEventListener('click', () => show(parse(), 0)); $('#in', root).addEventListener('input', () => { const o = parse(); if (o && o !== undefined) show(o, 2); }); } },

  { id: 'regex', grp: 'Format & Data', e: '🔍', name: 'Regex Tester', desc: 'Test regex, highlight matches, view capture groups.',
    tujuan: '<b>What it\'s for:</b> test a text search pattern (regular expression) live — see what it matches before using it in code. <b>When:</b> building validation (email, phone), parsing logs, or find-and-replace.',
    contoh(root) { $('#pat', root).value = '\\b\\w+@\\w+\\.\\w+\\b'; $('#in', root).value = 'contact: andi@mail.com and budi@web.id'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><div style="flex:1;min-width:200px"><label class="lbl">Pattern</label><input class="f" id="pat" placeholder="\\d+"></div><div><label class="lbl">Flags</label><input class="f" id="fl" value="g" style="width:90px"></div></div><label class="lbl">Test text</label><textarea id="in"></textarea><div class="row" style="margin-top:12px"><span id="stat"></span></div><label class="lbl">Highlights</label><div class="out empty" id="hl">—</div><div id="groups"></div>`; const run = () => { const pat = $('#pat', root).value, fl = $('#fl', root).value, txt = $('#in', root).value, stat = $('#stat', root), hlEl = $('#hl', root), gEl = $('#groups', root); gEl.innerHTML = ''; if (!pat) { stat.innerHTML = ''; hlEl.textContent = '—'; hlEl.classList.add('empty'); return; } let re; try { re = new RegExp(pat, fl.includes('g') ? fl : fl + 'g'); } catch (e) { return setErr(stat, e.message); } let m, count = 0, last = 0, html = '', groups = []; try { while ((m = re.exec(txt)) !== null) { count++; html += esc(txt.slice(last, m.index)) + '<mark>' + esc(m[0] || '') + '</mark>'; last = m.index + (m[0].length || 0); if (m.length > 1) groups.push(m.slice(1)); if (!re.global) break; if (m[0] === '') re.lastIndex++; if (count > 5000) break; } } catch (e) { return setErr(stat, e.message); } html += esc(txt.slice(last)); stat.innerHTML = count ? `<span class="pill ok">${count} matches</span>` : '<span class="pill warn">No matches</span>'; hlEl.innerHTML = html || '—'; hlEl.classList.toggle('empty', !txt); if (groups.length) gEl.innerHTML = '<label class="lbl" style="margin-top:14px">Groups (first match)</label>' + groups[0].map((g, i) => `<div class="kv"><span class="k">Group ${i + 1}</span><span class="v">${esc(g == null ? '(empty)' : g)}</span></div>`).join(''); }; root.querySelectorAll('input,textarea').forEach(x => x.addEventListener('input', run)); } },

  { id: 'diff', grp: 'Format & Data', e: '↔️', name: 'Text Diff', desc: 'Compare two texts line by line (added/removed).',
    tujuan: '<b>What it\'s for:</b> see the difference between two versions of text — lines added (green) &amp; removed (red). <b>When:</b> comparing configs, document revisions, or two responses.',
    contoh(root) { $('#a', root).value = 'line one\nline two\nline three'; $('#b', root).value = 'line one\nline TWO changed\nline three\nline four'; fire($('#a', root)); },
    body(root) {
      root.innerHTML = `<div class="cardrow"><div><label class="lbl">Text A (old)</label><textarea id="a"></textarea></div><div><label class="lbl">Text B (new)</label><textarea id="b"></textarea></div></div><label class="lbl" style="margin-top:12px">Differences</label><div class="out empty" id="out">—</div>`;
      const run = () => {
        const A = $('#a', root).value.split('\n'), B = $('#b', root).value.split('\n'), out = $('#out', root);
        if (!$('#a', root).value && !$('#b', root).value) { out.textContent = '—'; out.classList.add('empty'); return; }
        const n = A.length, m = B.length, dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
        for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
        let i = 0, j = 0, rows = [];
        while (i < n && j < m) { if (A[i] === B[j]) { rows.push(['same', A[i]]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { rows.push(['del', A[i++]]); } else { rows.push(['add', B[j++]]); } }
        while (i < n) rows.push(['del', A[i++]]); while (j < m) rows.push(['add', B[j++]]);
        const sign = { same: '  ', add: '+ ', del: '- ' };
        out.classList.remove('empty');
        out.innerHTML = rows.map(([t, l]) => `<div class="diffline ${t}">${esc(sign[t] + l)}</div>`).join('') || '<span class="pill ok">Identical</span>';
      };
      $('#a', root).addEventListener('input', run); $('#b', root).addEventListener('input', run);
    } },

  { id: 'numbase', grp: 'Format & Data', e: '🔢', name: 'Number Base Converter', desc: 'Convert numbers between binary, octal, decimal, hexadecimal.',
    tujuan: '<b>What it\'s for:</b> convert numbers between base 2/8/10/16 (supports large numbers via BigInt). <b>When:</b> working with bitmasks, hex colors, memory addresses, or flags.',
    contoh(root) { $('#in', root).value = '255'; $('#from', root).value = '10'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="row"><div style="flex:1"><label class="lbl">Number</label><input class="f" id="in" placeholder="255"></div><div><label class="lbl">From base</label><select class="f" id="from"><option value="2">Binary (2)</option><option value="8">Octal (8)</option><option value="10" selected>Decimal (10)</option><option value="16">Hex (16)</option></select></div></div><div id="out" style="margin-top:14px"></div>`;
      const run = () => { const v = $('#in', root).value.trim().replace(/^0[xob]/i, ''), base = +$('#from', root).value, out = $('#out', root); if (!v) { out.innerHTML = ''; return; } try { let n = 0n; const B = BigInt(base); for (const ch of v.toLowerCase()) { if (ch === '_') continue; const d = parseInt(ch, base); if (isNaN(d) || d >= base) throw new Error('digit "' + ch + '" invalid for base ' + base); n = n * B + BigInt(d); } out.innerHTML = [['Binary', n.toString(2)], ['Octal', n.toString(8)], ['Decimal', n.toString(10)], ['Hex', n.toString(16).toUpperCase()]].map(([k, val]) => `<div class="kv"><span class="k">${k}</span><span class="v" style="cursor:pointer" data-c="${val}">${esc(val)} ⧉</span></div>`).join(''); out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c))); } catch (e) { setErr(out, e.message); } };
      $('#in', root).addEventListener('input', run); $('#from', root).addEventListener('change', run);
    } },

  { id: 'jsoncsv', grp: 'Format & Data', e: '📊', name: 'JSON → CSV', desc: 'Convert a JSON array of objects into a CSV table (Excel-ready).',
    tujuan: '<b>What it\'s for:</b> turn JSON data (an array of objects) into CSV that opens in Excel / Google Sheets. Columns are taken from the union of all keys; object/array values are written as JSON; commas &amp; quotes are escaped per the RFC 4180 standard. <b>When:</b> exporting an API response or data to a spreadsheet.',
    contoh(root) { $('#in', root).value = '[{"name":"Alex","age":25,"city":"Berlin"},{"name":"Ben","age":30,"city":"Tokyo","hobby":"chess"}]'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JSON (array of objects)</label><textarea id="in" style="min-height:150px" placeholder='[{"a":1,"b":2}]'></textarea>
        <div class="row" style="margin-top:10px"><label class="chk"><input type="checkbox" id="semi"> Semicolon separator (;)</label><button class="btn sm" id="dl" type="button">⭳ Download CSV</button><span id="stat"></span></div>
        <label class="lbl" style="margin-top:6px">CSV</label><div class="out empty" id="out">—</div>`;
      let lastCsv = '';
      const cell = (v, sep) => { if (v == null) return ''; let s = typeof v === 'object' ? JSON.stringify(v) : String(v); if (s.includes('"') || s.includes(sep) || s.includes('\n') || s.includes('\r')) s = '"' + s.replace(/"/g, '""') + '"'; return s; };
      const run = () => {
        const raw = $('#in', root).value.trim(), out = $('#out', root), stat = $('#stat', root); lastCsv = '';
        if (!raw) { out.textContent = '—'; out.classList.add('empty'); stat.innerHTML = ''; return; }
        let data; try { data = JSON.parse(raw); } catch (e) { return setErr(out, 'Invalid JSON: ' + e.message); }
        if (!Array.isArray(data)) data = [data];
        if (!data.length) return setErr(out, 'Empty array');
        const sep = $('#semi', root).checked ? ';' : ',';
        const keys = []; for (const row of data) { if (row && typeof row === 'object' && !Array.isArray(row)) for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k); }
        if (!keys.length) return setErr(out, 'Need an array of objects {…}');
        const lines = [keys.map(k => cell(k, sep)).join(sep)];
        for (const row of data) lines.push(keys.map(k => cell(row ? row[k] : '', sep)).join(sep));
        lastCsv = lines.join('\r\n'); out.classList.remove('empty'); out.textContent = lastCsv; withCopy(out, () => lastCsv);
        stat.innerHTML = `<span class="pill ok">${data.length} rows · ${keys.length} columns</span>`;
      };
      $('#dl', root).addEventListener('click', () => { if (!lastCsv) return; const blob = new Blob(['﻿' + lastCsv], { type: 'text/csv;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'data.csv'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); });
      $('#in', root).addEventListener('input', run); $('#semi', root).addEventListener('change', run);
    } },

  { id: 'csvjson', grp: 'Format & Data', e: '🧾', name: 'CSV → JSON', desc: 'Convert CSV (with a header) into a JSON array of objects.',
    tujuan: '<b>What it\'s for:</b> turn CSV data (from Excel/Sheets/an export) into a JSON array of objects ready to use in code/an API. The parser handles quotes, commas inside cells, &amp; newlines inside cells (RFC 4180). <b>When:</b> importing spreadsheet data into an app.',
    contoh(root) { $('#in', root).value = 'name,age,city\nAlex,25,Berlin\n"Ben, S.T.",30,Tokyo'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">CSV</label><textarea id="in" style="min-height:150px" placeholder="a,b,c&#10;1,2,3"></textarea>
        <div class="row" style="margin-top:10px"><label class="lbl" style="margin:0">Separator</label><select class="f" id="sep" style="width:130px"><option value="auto">Auto-detect</option><option value=",">Comma ,</option><option value=";">Semicolon ;</option><option value="\t">Tab</option></select>
        <label class="chk"><input type="checkbox" id="hdr" checked> First row = header</label><label class="chk"><input type="checkbox" id="typ" checked> Detect numbers & booleans</label><span id="stat"></span></div>
        <label class="lbl" style="margin-top:6px">JSON</label><div class="out empty" id="out">—</div>`;
      const parseCSV = (text, sep) => { const rows = []; let row = [], f = '', i = 0, q = false; while (i < text.length) { const c = text[i]; if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i += 2; continue; } q = false; i++; continue; } f += c; i++; continue; } if (c === '"') { q = true; i++; continue; } if (c === sep) { row.push(f); f = ''; i++; continue; } if (c === '\n') { row.push(f); rows.push(row); row = []; f = ''; i++; continue; } if (c === '\r') { i++; continue; } f += c; i++; } if (f !== '' || row.length) { row.push(f); rows.push(row); } return rows; };
      const coerce = v => { if (!$('#typ', root).checked) return v; const t = v.trim(); if (t === '') return ''; if (/^-?\d+(\.\d+)?$/.test(t) && t.length < 16) return Number(t); if (/^(true|false)$/i.test(t)) return t.toLowerCase() === 'true'; if (/^null$/i.test(t)) return null; return v; };
      const run = () => {
        const raw = $('#in', root).value, out = $('#out', root), stat = $('#stat', root); if (!raw.trim()) { out.textContent = '—'; out.classList.add('empty'); stat.innerHTML = ''; return; }
        let sep = $('#sep', root).value; if (sep === 'auto') { const first = raw.split('\n')[0]; sep = [[',', (first.match(/,/g) || []).length], [';', (first.match(/;/g) || []).length], ['\t', (first.match(/\t/g) || []).length]].sort((a, b) => b[1] - a[1])[0][0]; }
        const rows = parseCSV(raw.replace(/\n+$/, ''), sep); if (!rows.length) return setErr(out, 'Empty CSV');
        let result;
        if ($('#hdr', root).checked) { const keys = rows[0]; result = rows.slice(1).map(r => { const o = {}; keys.forEach((k, i) => o[k] = coerce(r[i] == null ? '' : r[i])); return o; }); }
        else result = rows.map(r => r.map(coerce));
        out.classList.remove('empty'); out.textContent = JSON.stringify(result, null, 2); withCopy(out, () => JSON.stringify(result, null, 2));
        stat.innerHTML = `<span class="pill ok">${result.length} rows</span>`;
      };
      root.querySelectorAll('textarea,select,input').forEach(x => x.addEventListener('input', run)); $('#sep', root).addEventListener('change', run);
    } },

  { id: 'jsonyaml', grp: 'Format & Data', e: '🧩', name: 'JSON → YAML', desc: 'Convert JSON into clean, valid YAML.',
    tujuan: '<b>What it\'s for:</b> convert JSON into <b>YAML</b> — a more readable config format (used by Docker Compose, Kubernetes, CI/CD, etc.). <b>When:</b> copying JSON data into a YAML config file. Runs in the browser.',
    contoh(root) { $('#in', root).value = '{"name":"devsec","version":3,"active":true,"tags":["dev","security"],"meta":{"author":"Ksatria","tools":62}}'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JSON</label><textarea id="in" style="min-height:150px" placeholder='{"a":1}'></textarea><label class="lbl" style="margin-top:12px">YAML</label><div class="out empty" id="out">—</div>`;
      const scalar = v => { if (v === null) return 'null'; if (typeof v === 'boolean' || typeof v === 'number') return String(v); const s = String(v); if (s === '') return "''"; if (/[:#\[\]{}&*!|>'"%@`,]/.test(s) || /^[\s-?]/.test(s) || /\s$/.test(s) || /^(true|false|null|yes|no|on|off|~)$/i.test(s) || /^[-+]?[\d.]/.test(s) && /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return JSON.stringify(s); return s; };
      const dump = (v, ind) => {
        const pad = '  '.repeat(ind);
        if (v === null || typeof v !== 'object') return scalar(v);
        if (Array.isArray(v)) { if (!v.length) return '[]'; return '\n' + v.map(it => { if (it !== null && typeof it === 'object' && (Array.isArray(it) ? it.length : Object.keys(it).length)) { const block = dump(it, ind + 1).replace(/^\n/, ''); const lines = block.split('\n'); return pad + '- ' + lines[0].slice((ind + 1) * 2) + (lines.length > 1 ? '\n' + lines.slice(1).join('\n') : ''); } return pad + '- ' + dump(it, ind + 1); }).join('\n'); }
        const keys = Object.keys(v); if (!keys.length) return '{}';
        return '\n' + keys.map(k => { const val = v[k], key = scalar(k); if (val !== null && typeof val === 'object' && (Array.isArray(val) ? val.length : Object.keys(val).length)) return pad + key + ':' + dump(val, ind + 1); return pad + key + ': ' + dump(val, ind + 1); }).join('\n');
      };
      const run = () => { const raw = $('#in', root).value.trim(), out = $('#out', root); if (!raw) { out.textContent = '—'; out.classList.add('empty'); return; } let data; try { data = JSON.parse(raw); } catch (e) { return setErr(out, 'Invalid JSON: ' + e.message); } const y = dump(data, 0).replace(/^\n/, ''); out.classList.remove('empty'); out.textContent = y || '(empty)'; withCopy(out, () => y); };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'yamljson', grp: 'Format & Data', e: '🔃', name: 'YAML → JSON', desc: 'Convert YAML (common subset) into JSON.',
    tujuan: '<b>What it\'s for:</b> convert <b>YAML</b> (maps, lists, list-of-maps, scalars, comments) into JSON. <b>When:</b> copying a YAML config into JSON. Supports a common YAML subset; advanced features (anchors, multi-line blocks <span class="mono">|</span>/<span class="mono">&gt;</span>, flow style) are not yet supported and will return an error message rather than a wrong result.',
    contoh(root) { $('#in', root).value = 'name: devsec\nversion: 3\nactive: true\ntags:\n  - dev\n  - security\nmeta:\n  author: Ksatria\n  tools: 62\nusers:\n  - name: Alex\n    role: admin\n  - name: Ben\n    role: editor'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">YAML</label><textarea id="in" style="min-height:170px" placeholder="key: value&#10;list:&#10;  - a&#10;  - b"></textarea><label class="lbl" style="margin-top:12px">JSON</label><div class="out empty" id="out">—</div>`;
      const findComment = s => { let q = null; for (let i = 0; i < s.length; i++) { const c = s[i]; if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return i; } return -1; };
      const unquote = s => { s = s.trim(); if (s[0] === '"' && s.endsWith('"')) { try { return JSON.parse(s); } catch (_) { return s.slice(1, -1); } } if (s[0] === "'" && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'"); return s; };
      const scalar = s => { s = s.trim(); if (s === '' || s === '~' || s === 'null') return null; if ((s[0] === '"' && s.endsWith('"')) || (s[0] === "'" && s.endsWith("'"))) return unquote(s); if (s === 'true') return true; if (s === 'false') return false; if (/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return Number(s); if (/^\[.*\]$|^\{.*\}$/.test(s)) { try { return JSON.parse(s); } catch (_) { } } return s; };
      const matchKey = s => s.match(/^("(?:[^"\\]|\\.)*"|'[^']*'|[^:]+?)\s*:\s*(.*)$/);
      const parse = src => {
        const lines = [];
        for (let raw of src.replace(/\r\n?/g, '\n').replace(/\t/g, '  ').split('\n')) { if (/^\s*#/.test(raw) || raw.trim() === '') continue; const h = findComment(raw); let line = h >= 0 ? raw.slice(0, h) : raw; line = line.replace(/\s+$/, ''); if (line.trim() === '') continue; lines.push({ indent: line.match(/^ */)[0].length, text: line.trim() }); }
        let pos = 0;
        const node = minInd => { if (pos >= lines.length) return null; const ind = lines[pos].indent; if (ind < minInd) return null; return (lines[pos].text === '-' || lines[pos].text.startsWith('- ')) ? list(ind) : map(ind); };
        const list = ind => { const arr = []; while (pos < lines.length && lines[pos].indent === ind && (lines[pos].text === '-' || lines[pos].text.startsWith('- '))) { const rest = lines[pos].text === '-' ? '' : lines[pos].text.slice(2); if (rest === '') { pos++; arr.push(node(ind + 1)); } else if (matchKey(rest)) { lines[pos] = { indent: ind + 2, text: rest }; arr.push(map(ind + 2)); } else { pos++; arr.push(scalar(rest)); } } return arr; };
        const map = ind => { const obj = {}; while (pos < lines.length && lines[pos].indent === ind && !(lines[pos].text === '-' || lines[pos].text.startsWith('- '))) { const m = matchKey(lines[pos].text); if (!m) throw new Error('invalid line: "' + lines[pos].text + '"'); const key = unquote(m[1].trim()), val = m[2]; if (val === '') { pos++; const c = node(ind + 1); obj[key] = c === null ? null : c; } else { pos++; obj[key] = scalar(val); } } return obj; };
        const r = node(0); if (pos < lines.length) throw new Error('inconsistent indentation near: "' + lines[pos].text + '"'); return r === null ? {} : r;
      };
      const run = () => { const raw = $('#in', root).value, out = $('#out', root); if (!raw.trim()) { out.textContent = '—'; out.classList.add('empty'); return; } let data; try { data = parse(raw); } catch (e) { return setErr(out, 'Unsupported / invalid YAML: ' + e.message); } const j = JSON.stringify(data, null, 2); out.classList.remove('empty'); out.textContent = j; withCopy(out, () => j); };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'jsonts', grp: 'Format & Data', e: '🧠', name: 'JSON → TypeScript', desc: 'Generate TypeScript interfaces from sample JSON.',
    tujuan: '<b>What it\'s for:</b> auto-generate <b>TypeScript</b> type definitions (interfaces) from sample JSON data — saving time &amp; avoiding typos when modeling an API response. <b>When:</b> starting an API integration in a TypeScript project. Processed in the browser.',
    contoh(root) { $('#in', root).value = '{"id":1,"name":"Nadia","active":true,"roles":["admin","editor"],"profile":{"age":25,"city":"Berlin"},"tags":[]}'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JSON</label><textarea id="in" style="min-height:150px" placeholder='{"a":1}'></textarea><div class="row" style="margin-top:10px"><label class="lbl" style="margin:0">Root name</label><input class="f" id="rn" value="Root" style="width:160px"></div><label class="lbl" style="margin-top:10px">TypeScript</label><div class="out empty" id="out">—</div>`;
      const pascal = s => { s = String(s).replace(/[^a-zA-Z0-9]+/g, ' ').trim(); if (!s) return 'X'; return s.split(' ').map(w => w[0].toUpperCase() + w.slice(1)).join('').replace(/^([0-9])/, '_$1'); };
      const singular = s => s.replace(/ies$/, 'y').replace(/([^s])s$/, '$1') || s;
      const isId = k => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k);
      const gen = (data, rootName) => {
        const defs = [], byName = new Map();
        const typeOf = (v, hint) => {
          if (v === null) return 'any';
          if (Array.isArray(v)) { if (!v.length) return 'any[]'; const ts = [...new Set(v.map(x => typeOf(x, singular(hint))))]; return (ts.length === 1 ? ts[0] : '(' + ts.join(' | ') + ')') + '[]'; }
          if (typeof v === 'object') return makeIf(v, hint);
          if (typeof v === 'number') return 'number';
          if (typeof v === 'boolean') return 'boolean';
          if (typeof v === 'string') return 'string';
          return 'any';
        };
        const makeIf = (obj, hint) => {
          const keys = Object.keys(obj), sig = JSON.stringify(keys);
          let nm = pascal(hint || 'Obj'), base = nm, n = 2;
          while (byName.has(nm) && byName.get(nm) !== sig) { nm = base + (n++); }
          if (byName.has(nm)) return nm;
          byName.set(nm, sig); const idx = defs.length; defs.push('');
          const fields = keys.length ? keys.map(k => `  ${isId(k) ? k : JSON.stringify(k)}: ${typeOf(obj[k], k)};`).join('\n') : '  [key: string]: any;';
          defs[idx] = `interface ${nm} {\n${fields}\n}`; return nm;
        };
        const rootType = typeOf(data, rootName);
        let head = ''; if (Array.isArray(data) || typeof data !== 'object' || data === null) head = `type ${pascal(rootName)} = ${rootType};\n\n`;
        return head + defs.join('\n\n');
      };
      const run = () => { const raw = $('#in', root).value.trim(), out = $('#out', root); if (!raw) { out.textContent = '—'; out.classList.add('empty'); return; } let data; try { data = JSON.parse(raw); } catch (e) { return setErr(out, 'Invalid JSON: ' + e.message); } const ts = gen(data, $('#rn', root).value.trim() || 'Root'); out.classList.remove('empty'); out.textContent = ts; withCopy(out, () => ts); };
      $('#in', root).addEventListener('input', run); $('#rn', root).addEventListener('input', run);
    } },

  // ---------- GENERATOR ----------
  { id: 'uuid', grp: 'Generator', e: '🆔', name: 'UUID Generator', desc: 'Generate random (cryptographic) UUID v4s, one or many.',
    tujuan: '<b>What it\'s for:</b> generate unique identifiers (IDs) for database records, requests, or files with no risk of collision. <b>When:</b> you need a random primary key/ID that\'s practically globally unique.',
    body(root) { root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Count</label><input class="f" id="n" type="number" value="5" min="1" max="500" style="width:100px"><button class="btn acc" id="gen" type="button">Generate</button></div><div class="out empty" id="out" style="margin-top:12px">—</div>`; const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16, v = c === 'x' ? r : (r & 0x3 | 0x8); return v.toString(16); })); const run = () => { const n = Math.max(1, Math.min(500, +$('#n', root).value || 1)); setOut($('#out', root), Array.from({ length: n }, uuid).join('\n')); }; $('#gen', root).addEventListener('click', run); run(); } },

  { id: 'qr', grp: 'Generator', e: '📱', name: 'QR Code Generator', desc: 'Generate a QR code from text/URL & download as PNG.',
    tujuan: '<b>What it\'s for:</b> turn text, a URL, WiFi, or a contact into a QR that a phone camera can scan. <b>When:</b> sharing a link on a poster/business card, or pairing devices quickly. Generated locally (offline).',
    contoh(root) { $('#in', root).value = 'https://ksatriabintangsamudra.my.id'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Text / URL</label><textarea id="in" placeholder="https://…"></textarea>
        <div class="row" style="margin-top:10px"><label class="lbl" style="margin:0">Error correction</label><select class="f" id="ec" style="width:150px"><option value="L">L (7%)</option><option value="M" selected>M (15%)</option><option value="Q">Q (25%)</option><option value="H">H (30%)</option></select>
        <button class="btn sm" id="dl" type="button">⭳ Download PNG</button></div>
        <div id="qrbox"></div><div id="err" class="note"></div>`;
      let lastCanvas = null;
      const run = () => {
        const v = $('#in', root).value, box = $('#qrbox', root), err = $('#err', root); box.innerHTML = ''; err.textContent = ''; lastCanvas = null;
        if (!v) { box.style.display = 'none'; return; }
        box.style.display = 'flex';
        try {
          const qr = qrcode(0, $('#ec', root).value); qr.addData(v); qr.make();
          const count = qr.getModuleCount(), size = 260, cell = Math.floor(size / (count + 2)), pad = cell, dim = cell * count + pad * 2;
          const cv = document.createElement('canvas'); cv.width = cv.height = dim; const ctx = cv.getContext('2d');
          ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, dim, dim); ctx.fillStyle = '#000';
          for (let r = 0; r < count; r++) for (let c = 0; c < count; c++) if (qr.isDark(r, c)) ctx.fillRect(pad + c * cell, pad + r * cell, cell, cell);
          cv.style.width = cv.style.height = '260px'; box.appendChild(cv); lastCanvas = cv;
        } catch (e) { box.style.display = 'none'; err.innerHTML = '<span class="pill err">Text too long for a QR code</span>'; }
      };
      $('#dl', root).addEventListener('click', () => { if (!lastCanvas) return; const a = document.createElement('a'); a.href = lastCanvas.toDataURL('image/png'); a.download = 'qrcode.png'; a.click(); });
      $('#in', root).addEventListener('input', run); $('#ec', root).addEventListener('change', run);
    } },

  { id: 'qrdecode', grp: 'Generator', e: '📷', name: 'QR Reader (Image)', desc: 'Upload an image containing a QR code to read its text/URL.',
    tujuan: '<b>What it\'s for:</b> read the contents of a QR code from an image (screenshot / photo) right in the browser — no camera &amp; <b>without uploading the image</b> to a server. <b>When:</b> checking where a QR points before opening it, or pulling text from a QR shown on screen.',
    body(root) {
      root.innerHTML = `<div class="drop" id="drop"><div class="big">Drop a QR image here</div><div>or click to choose · paste (Ctrl/⌘+V) also works · image not uploaded</div></div>
        <input type="file" id="file" accept="image/*" style="display:none"><div id="out" style="margin-top:12px"></div>`;
      const drop = $('#drop', root), file = $('#file', root), out = $('#out', root);
      async function decode(src) {
        out.innerHTML = '<div class="out empty">scanning…</div>';
        let jsQR; try { jsQR = await loadJsQR(); } catch (e) { return setErr(out, 'Failed to load QR scanner'); }
        const img = new Image();
        img.onload = () => {
          const max = 1200, sc = Math.min(1, max / Math.max(img.width, img.height));
          const w = Math.max(1, Math.round(img.width * sc)), h = Math.max(1, Math.round(img.height * sc));
          const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
          const ctx = cv.getContext('2d'); ctx.drawImage(img, 0, 0, w, h);
          const data = ctx.getImageData(0, 0, w, h);
          const code = jsQR(data.data, w, h);
          if (!code) return setErr(out, 'No QR code could be read in this image — try a clearer/larger image');
          const txt = code.data, isUrl = /^https?:\/\//i.test(txt);
          out.innerHTML = `<label class="lbl">QR contents</label><div class="out">${esc(txt)}<button class="copy" data-c="${esc(txt)}">Copy</button></div>${isUrl ? `<div class="note">🔗 This is a link — check it before opening.</div>` : ''}`;
          out.querySelector('[data-c]').addEventListener('click', () => copy(txt));
        };
        img.onerror = () => setErr(out, 'Failed to load image'); img.src = src;
      }
      const handleFile = f => { if (!f || !f.type.startsWith('image/')) return; const r = new FileReader(); r.onload = () => decode(r.result); r.readAsDataURL(f); };
      drop.addEventListener('click', () => file.click());
      file.addEventListener('change', e => handleFile(e.target.files[0]));
      drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', () => drop.classList.remove('over'));
      drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); handleFile(e.dataTransfer.files[0]); });
      const onPaste = e => { const it = [...((e.clipboardData || {}).items || [])].find(i => i.type.startsWith('image/')); if (it) handleFile(it.getAsFile()); };
      addEventListener('paste', onPaste); onCleanup(() => removeEventListener('paste', onPaste));
    } },

  { id: 'lorem', grp: 'Generator', e: '📄', name: 'Lorem Ipsum', desc: 'Generate placeholder text (words/sentences/paragraphs).',
    tujuan: '<b>What it\'s for:</b> fill a design/mockup with sample text so the layout looks real before the actual content exists. <b>When:</b> prototyping a UI or template.',
    body(root) {
      const W = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum'.split(' ');
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Count</label><input class="f" id="n" type="number" value="3" min="1" max="50" style="width:90px"><div class="seg" id="u"><button data-u="para" class="on">Paragraphs</button><button data-u="kal">Sentences</button><button data-u="kata">Words</button></div><button class="btn acc" id="gen" type="button">Generate</button></div><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      let unit = 'para'; const rnd = n => W[Math.floor(Math.random() * W.length)];
      const sentence = () => { const len = 8 + Math.floor(Math.random() * 8); let s = Array.from({ length: len }, rnd).join(' '); return s[0].toUpperCase() + s.slice(1) + '.'; };
      const para = () => Array.from({ length: 4 + Math.floor(Math.random() * 3) }, sentence).join(' ');
      const run = () => { const n = Math.max(1, Math.min(50, +$('#n', root).value || 1)); let r; if (unit === 'kata') r = Array.from({ length: n }, rnd).join(' '); else if (unit === 'kal') r = Array.from({ length: n }, sentence).join(' '); else r = Array.from({ length: n }, para).join('\n\n'); setOut($('#out', root), r); };
      $('#u', root).addEventListener('click', e => { if (!e.target.dataset.u) return; unit = e.target.dataset.u; [...$('#u', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#gen', root).addEventListener('click', run); run();
    } },

  { id: 'meta', grp: 'Generator', e: '🔖', name: 'Meta Tag & Open Graph', desc: 'Generate SEO, Open Graph, & Twitter Card tags + preview.',
    tujuan: '<b>What it\'s for:</b> generate <b>SEO</b> &amp; <b>social share</b> tags (Open Graph / Twitter Card) for a page\'s &lt;head&gt; — title, description, and preview image when a link is shared. <b>When:</b> preparing a page to look clean on Google &amp; social media.',
    contoh(root) { $('#mt', root).value = 'DevSec Toolbox — Developer & Security Tools'; $('#md', root).value = '31 free developer & security tools, 100% in the browser.'; $('#mu', root).value = 'https://devsec.ksatriabintangsamudra.com/'; $('#mi', root).value = 'https://devsec.ksatriabintangsamudra.com/docs/home.png'; $('#ms', root).value = 'DevSec Toolbox'; fire($('#mt', root)); },
    body(root) {
      root.innerHTML = `<div class="cardrow"><div><label class="lbl">Title</label><input class="f" id="mt" placeholder="Page title"></div><div><label class="lbl">Site name</label><input class="f" id="ms" placeholder="Site Name"></div></div>
        <label class="lbl" style="margin-top:12px">Description</label><textarea id="md" style="min-height:64px" placeholder="Short description (±155 characters)"></textarea>
        <div class="cardrow" style="margin-top:12px"><div><label class="lbl">URL</label><input class="f" id="mu" placeholder="https://…"></div><div><label class="lbl">Image / OG image (URL)</label><input class="f" id="mi" placeholder="https://…/og.png"></div></div>
        <label class="lbl" style="margin-top:14px">Google preview</label><div id="gprev" class="serp"></div><div id="mcount" class="note"></div>
        <label class="lbl" style="margin-top:12px">Tags for &lt;head&gt;</label><div class="out empty" id="out">—</div>`;
      const gv = id => $('#' + id, root).value.trim();
      const run = () => {
        const t = gv('mt'), d = gv('md'), u = gv('mu'), img = gv('mi'), s = gv('ms'), out = $('#out', root), e = x => x.replace(/"/g, '&quot;');
        if (!t && !d) { out.textContent = '—'; out.classList.add('empty'); $('#gprev', root).innerHTML = '<div class="serp-empty">Enter a title & description to see a preview…</div>'; $('#mcount', root).innerHTML = ''; return; }
        const L = [];
        if (t) L.push(`<title>${e(t)}</title>`);
        if (d) L.push(`<meta name="description" content="${e(d)}">`);
        if (u) L.push(`<link rel="canonical" href="${e(u)}">`);
        L.push('<meta property="og:type" content="website">');
        if (s) L.push(`<meta property="og:site_name" content="${e(s)}">`);
        if (t) L.push(`<meta property="og:title" content="${e(t)}">`);
        if (d) L.push(`<meta property="og:description" content="${e(d)}">`);
        if (u) L.push(`<meta property="og:url" content="${e(u)}">`);
        if (img) L.push(`<meta property="og:image" content="${e(img)}">`);
        L.push(`<meta name="twitter:card" content="${img ? 'summary_large_image' : 'summary'}">`);
        if (t) L.push(`<meta name="twitter:title" content="${e(t)}">`);
        if (d) L.push(`<meta name="twitter:description" content="${e(d)}">`);
        if (img) L.push(`<meta name="twitter:image" content="${e(img)}">`);
        const text = L.join('\n'); setOut(out, text);
        let host = u || 'example.com'; try { host = new URL(u).host + new URL(u).pathname.replace(/\/$/, ''); } catch (_) { }
        const dlen = d.length;
        $('#gprev', root).innerHTML = `<div class="serp-url">${esc(host)}</div><div class="serp-title">${esc(t || 'Page title')}</div><div class="serp-desc">${esc((d || 'The description will appear here.').slice(0, 160))}${dlen > 160 ? '…' : ''}</div>`;
        $('#mcount', root).innerHTML = `Title ${t.length} · Description ${dlen} characters ${dlen > 160 ? '<span class="pill warn">>160, may be truncated</span>' : dlen && dlen < 70 ? '<span class="pill warn">a bit short</span>' : dlen ? '<span class="pill ok">ideal length</span>' : ''}`;
      };
      root.querySelectorAll('input,textarea').forEach(x => x.addEventListener('input', run));
    } },

  // ---------- CONVERTERS ----------
  { id: 'timestamp', grp: 'Converters', e: '⏱️', name: 'Timestamp', desc: 'Convert Unix timestamp ↔ date (local & UTC).',
    tujuan: '<b>What it\'s for:</b> translate a Unix time number (seconds since 1970) into a readable date, and back again. <b>When:</b> reading a timestamp from a database, log, or token (iat/exp).',
    contoh(root) { $('#now', root).click(); },
    body(root) { root.innerHTML = `<div class="row"><button class="btn acc sm" id="now" type="button">Now</button></div><label class="lbl">Unix timestamp (seconds/milliseconds)</label><input class="f" id="ts" placeholder="1735689600"><div id="o1" style="margin-top:6px"></div><label class="lbl" style="margin-top:16px">Date (any format)</label><input class="f" id="dt" placeholder="2026-08-25 14:30"><div id="o2" style="margin-top:6px"></div>`; const fromTs = () => { const v = $('#ts', root).value.trim(), o = $('#o1', root); if (!v || isNaN(+v)) { o.innerHTML = ''; return; } let n = +v; if (v.length <= 11) n *= 1000; const d = new Date(n); if (isNaN(d)) return setErr(o, 'Invalid'); o.innerHTML = `<div class="kv"><span class="k">Local</span><span class="v">${esc(d.toLocaleString())}</span></div><div class="kv"><span class="k">UTC</span><span class="v">${esc(d.toUTCString())}</span></div><div class="kv"><span class="k">ISO 8601</span><span class="v">${esc(d.toISOString())}</span></div>`; }; const fromDt = () => { const v = $('#dt', root).value.trim(), o = $('#o2', root); if (!v) { o.innerHTML = ''; return; } const d = new Date(v); if (isNaN(d)) return setErr(o, 'Cannot parse'); o.innerHTML = `<div class="kv"><span class="k">Unix (seconds)</span><span class="v">${Math.floor(d.getTime() / 1000)}</span></div><div class="kv"><span class="k">Unix (ms)</span><span class="v">${d.getTime()}</span></div>`; }; $('#ts', root).addEventListener('input', fromTs); $('#dt', root).addEventListener('input', fromDt); $('#now', root).addEventListener('click', () => { $('#ts', root).value = Math.floor(Date.now() / 1000); fromTs(); }); } },

  { id: 'cron', grp: 'Converters', e: '📅', name: 'Cron Parser', desc: 'Explain a cron expression & show the next 5 run times.',
    tujuan: '<b>What it\'s for:</b> understand what a cron expression means (e.g. <span class="mono">0 9 * * 1</span>) and when it will actually run. <b>When:</b> setting up a cron job/scheduled task so the schedule is correct.',
    contoh(root) { $('#in', root).value = '0 9 * * 1-5'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Cron expression (minute hour day-of-month month day-of-week)</label><input class="f" id="in" placeholder="0 9 * * 1-5"><div id="desc2" style="margin-top:10px"></div><label class="lbl" style="margin-top:14px">Next 5 run times</label><div class="out empty" id="out">—</div>`;
      const NM = ['minute (0-59)', 'hour (0-23)', 'day of month (1-31)', 'month (1-12)', 'day of week (0-6, Sun=0)'];
      const parseField = (f, min, max) => { const set = new Set(); for (const part of f.split(',')) { let step = 1, range = part; const sl = part.split('/'); if (sl.length === 2) { range = sl[0]; step = +sl[1]; } let lo, hi; if (range === '*') { lo = min; hi = max; } else if (range.includes('-')) { const [a, b] = range.split('-'); lo = +a; hi = +b; } else { lo = hi = +range; } if (isNaN(lo) || isNaN(hi) || isNaN(step) || step < 1) throw new Error('invalid part: "' + part + '"'); for (let v = lo; v <= hi; v += step) if (v >= min && v <= max) set.add(v); } return set; };
      const run = () => {
        const v = $('#in', root).value.trim(), out = $('#out', root), d2 = $('#desc2', root); d2.innerHTML = '';
        if (!v) { out.textContent = '—'; out.classList.add('empty'); return; }
        const f = v.split(/\s+/); if (f.length !== 5) return setErr(out, 'Must be 5 space-separated parts (minute hour day-of-month month day-of-week)');
        let sets; try { sets = [parseField(f[0], 0, 59), parseField(f[1], 0, 23), parseField(f[2], 1, 31), parseField(f[3], 1, 12), parseField(f[4], 0, 6)]; } catch (e) { return setErr(out, e.message); }
        d2.innerHTML = f.map((x, i) => `<div class="kv"><span class="k">${NM[i]}</span><span class="v">${esc(x)}</span></div>`).join('');
        const runs = []; const dt = new Date(); dt.setSeconds(0, 0); dt.setMinutes(dt.getMinutes() + 1);
        for (let guard = 0; guard < 366 * 24 * 60 && runs.length < 5; guard++) { const dow = dt.getDay(); if (sets[0].has(dt.getMinutes()) && sets[1].has(dt.getHours()) && sets[2].has(dt.getDate()) && sets[3].has(dt.getMonth() + 1) && sets[4].has(dow)) runs.push(new Date(dt).toLocaleString()); dt.setMinutes(dt.getMinutes() + 1); }
        out.classList.remove('empty'); out.textContent = runs.length ? runs.join('\n') : 'No scheduled runs in the next year'; if (runs.length) withCopy(out, () => runs.join('\n'));
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'urlparse', grp: 'Converters', e: '🧭', name: 'URL Parser', desc: 'Break a URL into its parts + a query table.',
    tujuan: '<b>What it\'s for:</b> dissect a URL into protocol, host, port, path, query parameters, and fragment. <b>When:</b> debugging a link, checking tracking parameters, or analyzing a suspicious URL.',
    contoh(root) { $('#in', root).value = 'https://user@shop.example.com:8443/products/42?ref=promo&utm_source=ig#reviews'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<label class="lbl">URL</label><input class="f" id="in" placeholder="https://…"><div id="out" style="margin-top:14px"></div>`; const run = () => { const v = $('#in', root).value.trim(), out = $('#out', root); if (!v) { out.innerHTML = ''; return; } let u; try { u = new URL(v); } catch (e) { return setErr(out, 'Invalid URL'); } const rows = [['Protocol', u.protocol.replace(':', '')], ['Host', u.hostname], ['Port', u.port || '(default)'], ['Path', u.pathname], ['Fragment', u.hash.replace('#', '') || '(empty)'], ['Origin', u.origin]]; let html = rows.map(r => `<div class="kv"><span class="k">${r[0]}</span><span class="v">${esc(r[1])}</span></div>`).join(''); const params = [...u.searchParams.entries()]; if (params.length) html += '<label class="lbl" style="margin-top:14px">Query parameters</label>' + params.map(([k, val]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join(''); out.innerHTML = html; }; $('#in', root).addEventListener('input', run); } },

  { id: 'text', grp: 'Converters', e: '📝', name: 'Text & Case', desc: 'Change capitalization, slugify, count words, sort/uniq/reverse.',
    tujuan: '<b>What it\'s for:</b> quick text transforms — change upper/lowercase, build a URL slug, count words, sort or remove duplicate lines. <b>When:</b> tidying a list, making a slug, or preparing data.',
    contoh(root) { $('#in', root).value = 'Hello Beautiful World'; fire($('#in', root)); const b = root.querySelector('[data-op="slug"]'); if (b) b.click(); },
    body(root) { root.innerHTML = `<label class="lbl">Text</label><textarea id="in"></textarea><div class="row" style="margin-top:12px">${['UPPER', 'lower', 'Title Case', 'camelCase', 'snake_case', 'kebab-case', 'slug', 'Reverse lines', 'Sort A-Z', 'Remove duplicates'].map(x => `<button class="btn sm" data-op="${x}">${x}</button>`).join('')}</div><div id="stat" class="note"></div><label class="lbl" style="margin-top:10px">Result</label><div class="out empty" id="out">—</div>`; const words = s => (s.trim().match(/\S+/g) || []).length; const stat = () => { const v = $('#in', root).value; $('#stat', root).innerHTML = `${v.length} characters · ${words(v)} words · ${v ? v.split(/\n/).length : 0} lines`; }; const ops = { 'UPPER': s => s.toUpperCase(), 'lower': s => s.toLowerCase(), 'Title Case': s => s.replace(/\w\S*/g, t => t[0].toUpperCase() + t.slice(1).toLowerCase()), 'camelCase': s => s.toLowerCase().replace(/[^a-z0-9]+(.)/g, (_, c) => c.toUpperCase()), 'snake_case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, ''), 'kebab-case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''), 'slug': s => s.trim().toLowerCase().normalize('NFKD').replace(/[^\w\s-]/g, '').replace(/[\s_]+/g, '-').replace(/^-+|-+$/g, ''), 'Reverse lines': s => s.split('\n').reverse().join('\n'), 'Sort A-Z': s => s.split('\n').sort((a, b) => a.localeCompare(b)).join('\n'), 'Remove duplicates': s => [...new Set(s.split('\n'))].join('\n') }; root.querySelectorAll('[data-op]').forEach(b => b.addEventListener('click', () => setOut($('#out', root), ops[b.dataset.op]($('#in', root).value)))); $('#in', root).addEventListener('input', stat); stat(); } },

  { id: 'color', grp: 'Converters', e: '🎨', name: 'Color Converter', desc: 'Convert colors between HEX, RGB, and HSL.',
    tujuan: '<b>What it\'s for:</b> convert color codes between the formats used in CSS/design. <b>When:</b> matching a color from Figma to CSS, or adjusting a palette.',
    contoh(root) { $('#in', root).value = '#5eead4'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><input type="color" id="pick" value="#5eead4" style="width:52px;height:44px;border:1px solid var(--line);border-radius:9px;background:none;cursor:pointer"><input class="f" id="in" value="#5eead4" style="max-width:240px" placeholder="#5eead4 / rgb(94,234,212)"></div><div id="out" style="margin-top:12px"></div><div id="sw" style="height:70px;border-radius:12px;border:1px solid var(--line);margin-top:12px"></div>`; function parse(str) { str = str.trim(); let m = str.match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i); if (m) { let h = m[1]; if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; } m = str.match(/rgba?\(([^)]+)\)/i); if (m) { const p = m[1].split(',').map(x => parseFloat(x)); return [p[0], p[1], p[2]]; } return null; } const toHex = ([r, g, b]) => '#' + [r, g, b].map(x => Math.round(x).toString(16).padStart(2, '0')).join(''); const toHsl = ([r, g, b]) => { r /= 255; g /= 255; b /= 255; const mx = Math.max(r, g, b), mn = Math.min(r, g, b); let h = 0, s = 0, l = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; s = l > .5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6; } return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`; }; const run = (src) => { const rgb = parse(src); const out = $('#out', root); if (!rgb || rgb.some(isNaN)) return setErr(out, 'Invalid color'); const hexv = toHex(rgb); $('#sw', root).style.background = hexv; $('#pick', root).value = hexv; out.innerHTML = [['HEX', hexv], ['RGB', `rgb(${rgb.map(Math.round).join(', ')})`], ['HSL', toHsl(rgb)]].map(([k, v]) => `<div class="kv"><span class="k">${k}</span><span class="v" style="cursor:pointer" data-c="${esc(v)}">${esc(v)} ⧉</span></div>`).join(''); out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c))); }; $('#in', root).addEventListener('input', e => run(e.target.value)); $('#pick', root).addEventListener('input', e => { $('#in', root).value = e.target.value; run(e.target.value); }); run('#5eead4'); } },

  { id: 'unit', grp: 'Converters', e: '📐', name: 'Unit Converter', desc: 'Convert length, mass, temperature, & data sizes.',
    tujuan: '<b>What it\'s for:</b> convert common units — length, mass/weight, temperature, and data size — quickly &amp; accurately (official conversion factors). <b>When:</b> converting km↔mi, kg↔lb, °C↔°F, or MB↔GB.',
    contoh(root) { $('#val', root).value = '100'; fire($('#val', root)); },
    body(root) {
      const CATS = {
        'Length': { u: { 'Millimeter (mm)': .001, 'Centimeter (cm)': .01, 'Meter (m)': 1, 'Kilometer (km)': 1000, 'Inch (in)': .0254, 'Foot (ft)': .3048, 'Yard (yd)': .9144, 'Mile': 1609.344 } },
        'Mass': { u: { 'Milligram (mg)': .001, 'Gram (g)': 1, 'Kilogram (kg)': 1000, 'Tonne': 1e6, 'Ounce (oz)': 28.349523125, 'Pound (lb)': 453.59237 } },
        'Temperature': { temp: true, u: { 'Celsius (°C)': 'C', 'Fahrenheit (°F)': 'F', 'Kelvin (K)': 'K' } },
        'Data': { u: { 'Bit': .125, 'Byte (B)': 1, 'Kilobyte (KB)': 1024, 'Megabyte (MB)': 1048576, 'Gigabyte (GB)': 1073741824, 'Terabyte (TB)': 1099511627776 } }
      };
      root.innerHTML = `<div class="row"><div style="flex:1;min-width:160px"><label class="lbl">Category</label><select class="f" id="cat"></select></div></div>
        <div class="cardrow"><div><label class="lbl">From</label><input class="f" id="val" placeholder="100"><select class="f" id="from" style="margin-top:8px"></select></div>
        <div><label class="lbl">To</label><div class="out" id="res" style="min-height:auto;cursor:pointer" title="click to copy">—</div><select class="f" id="to" style="margin-top:8px"></select></div></div>`;
      const catSel = $('#cat', root), fromSel = $('#from', root), toSel = $('#to', root), val = $('#val', root), res = $('#res', root);
      catSel.innerHTML = Object.keys(CATS).map(c => `<option>${c}</option>`).join('');
      const toC = { C: v => v, F: v => (v - 32) * 5 / 9, K: v => v - 273.15 }, fromC = { C: v => v, F: v => v * 9 / 5 + 32, K: v => v + 273.15 };
      const fill = () => { const keys = Object.keys(CATS[catSel.value].u); fromSel.innerHTML = keys.map(k => `<option>${k}</option>`).join(''); toSel.innerHTML = keys.map(k => `<option>${k}</option>`).join(''); fromSel.selectedIndex = 0; toSel.selectedIndex = Math.min(1, keys.length - 1); };
      const run = () => { const c = CATS[catSel.value], v = parseFloat(val.value); if (val.value.trim() === '' || isNaN(v)) { res.textContent = '—'; return; } let o; if (c.temp) { o = fromC[c.u[toSel.value]](toC[c.u[fromSel.value]](v)); } else { o = v * c.u[fromSel.value] / c.u[toSel.value]; } const r = (o !== 0 && (Math.abs(o) >= 1e15 || Math.abs(o) < 1e-6)) ? o.toExponential(6) : String(+o.toFixed(6)); res.textContent = r; };
      catSel.addEventListener('change', () => { fill(); run(); });[fromSel, toSel, val].forEach(x => x.addEventListener('input', run));
      res.addEventListener('click', () => { if (res.textContent && res.textContent !== '—') copy(res.textContent); });
      fill(); run();
    } },

  { id: 'contrast', grp: 'Converters', e: '🌗', name: 'Color Contrast (WCAG)', desc: 'Compute the contrast ratio of two colors & AA/AAA pass status.',
    tujuan: '<b>What it\'s for:</b> make sure text &amp; background colors have enough <b>contrast</b> to read comfortably — per the <b>WCAG</b> accessibility standard. Shows the ratio (e.g. 4.5:1) &amp; pass/fail for AA & AAA. <b>When:</b> designing a UI/web page that\'s friendly to all users.',
    contoh(root) { $('#fg', root).value = '#0b1120'; $('#bg', root).value = '#5eead4'; fire($('#fg', root)); },
    body(root) {
      root.innerHTML = `<div class="cardrow"><div><label class="lbl">Text color</label><div class="row"><input type="color" id="fgp" value="#111111" class="cpick"><input class="f" id="fg" value="#111111"></div></div>
        <div><label class="lbl">Background color</label><div class="row"><input type="color" id="bgp" value="#ffffff" class="cpick"><input class="f" id="bg" value="#ffffff"></div></div></div>
        <div id="cprev" class="contrast-prev"><b>Sample text</b> — Aa Bb Cc 0123456789</div>
        <div id="out" style="margin-top:12px"></div>`;
      const parse = s => { s = s.trim(); let m = s.match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i); if (m) { let h = m[1]; if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; } m = s.match(/rgba?\(([^)]+)\)/i); if (m) { const p = m[1].split(',').map(parseFloat); return [p[0], p[1], p[2]]; } return null; };
      const lin = c => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
      const lum = ([r, g, b]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
      const run = () => { const fg = parse($('#fg', root).value), bg = parse($('#bg', root).value), out = $('#out', root); if (!fg || !bg || fg.some(isNaN) || bg.some(isNaN)) return setErr(out, 'Invalid color (use #hex or rgb())'); const L1 = lum(fg), L2 = lum(bg); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05); const r = ratio.toFixed(2); const prev = $('#cprev', root); prev.style.color = `rgb(${fg.join(',')})`; prev.style.background = `rgb(${bg.join(',')})`; const b = ok => ok ? '<span class="pill ok">Pass ✓</span>' : '<span class="pill err">Fail ✕</span>'; out.innerHTML = `<div class="kv"><span class="k">Contrast ratio</span><span class="v"><b>${r} : 1</b></span></div><div class="kv"><span class="k">AA · normal text (≥ 4.5)</span><span class="v">${b(ratio >= 4.5)}</span></div><div class="kv"><span class="k">AA · large text (≥ 3)</span><span class="v">${b(ratio >= 3)}</span></div><div class="kv"><span class="k">AAA · normal text (≥ 7)</span><span class="v">${b(ratio >= 7)}</span></div><div class="kv"><span class="k">AAA · large text (≥ 4.5)</span><span class="v">${b(ratio >= 4.5)}</span></div>`; };
      $('#fgp', root).addEventListener('input', e => { $('#fg', root).value = e.target.value; run(); });
      $('#bgp', root).addEventListener('input', e => { $('#bg', root).value = e.target.value; run(); });
      $('#fg', root).addEventListener('input', e => { const v = e.target.value.trim(); if (/^#[0-9a-f]{6}$/i.test(v)) $('#fgp', root).value = v; run(); });
      $('#bg', root).addEventListener('input', e => { const v = e.target.value.trim(); if (/^#[0-9a-f]{6}$/i.test(v)) $('#bgp', root).value = v; run(); });
      run();
    } },

  // ================= PHASE 2: NEW TOOLS =================
// ============================================================================
// Phase 2 — 15 new client-side tools. To be spliced into the TOOLS array in
// app.js (before the closing `];`). Uses existing helpers: $, el, esc, setOut,
// setErr, withCopy, copy, fire, enc, b64, b64url, unb64, hex, crypto, withProc.
// Groups use the post-translation English names: Security, Encode / Decode,
// Format & Data, Generator, Converters.
// ============================================================================

  // ---------- SECURITY (new) ----------
  { id: 'secrets', grp: 'Security', e: '🕵️', name: 'Secret Scanner', desc: 'Detect leaked API keys, tokens & private keys in text or .env.',
    tujuan: '<b>What it\'s for:</b> scans pasted code, logs, or <span class="mono">.env</span> files for hardcoded secrets — AWS keys, GitHub/Slack/Stripe tokens, Google API keys, private keys, JWTs, and password assignments. <b>When:</b> before committing or sharing a file, to catch credentials you forgot to remove. Everything runs in your browser — nothing is uploaded.',
    contoh(root) { const demo = ['DB_PASSWORD=hunter2', 'AWS_ACCESS_KEY_ID=AKIA' + 'IOSFODNN7EXAMPLE', 'GITHUB_TOKEN=ghp' + '_1234567890abcdefghijklmnopqrstuvwx12', 'stripe=sk' + '_live_51H8xQ2eZvKYlo2Cabcdefghijklmnop'].join('\n'); $('#in', root).value = demo; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Paste code, logs, or a .env file</label><textarea id="in" style="min-height:170px" placeholder="paste here…"></textarea><div id="stat" style="margin-top:12px"></div><div id="out" style="margin-top:8px"></div>`;
      const RULES = [
        [/AKIA[0-9A-Z]{16}/g, 'AWS Access Key ID'],
        [/(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+]{40})/gi, 'AWS Secret Access Key'],
        [/gh[pousr]_[A-Za-z0-9]{36}/g, 'GitHub Token'],
        [/github_pat_[A-Za-z0-9_]{82}/g, 'GitHub Fine-grained PAT'],
        [/xox[baprs]-[A-Za-z0-9-]{10,}/g, 'Slack Token'],
        [/AIza[0-9A-Za-z\-_]{35}/g, 'Google API Key'],
        [/sk_live_[0-9a-zA-Z]{24,}/g, 'Stripe Secret Key'],
        [/(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}/g, 'Stripe Key'],
        [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'JWT'],
        [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, 'Private Key block'],
        [/(?:api[_-]?key|secret|token|passwd|password|pwd)\s*[:=]\s*["']?([^\s"'#]{6,})/gi, 'Generic secret assignment'],
        [/postgres(?:ql)?:\/\/[^\s:@]+:[^\s@]+@/gi, 'Database URL with password'],
      ];
      const mask = s => s.length <= 8 ? s[0] + '•••' : s.slice(0, 4) + '•'.repeat(Math.min(12, s.length - 8)) + s.slice(-4);
      const run = () => {
        const v = $('#in', root).value, out = $('#out', root), stat = $('#stat', root);
        if (!v.trim()) { stat.innerHTML = ''; out.innerHTML = ''; return; }
        const lines = v.split('\n'); const hits = [];
        for (const [re, label] of RULES) { let m; re.lastIndex = 0; while ((m = re.exec(v)) !== null) { const full = m[0]; const before = v.slice(0, m.index); const line = before.split('\n').length; hits.push({ label, match: full, line }); if (!re.global) break; if (m.index === re.lastIndex) re.lastIndex++; } }
        // de-dup identical (label+match)
        const seen = new Set(), uniq = hits.filter(h => { const k = h.label + '|' + h.match; if (seen.has(k)) return false; seen.add(k); return true; });
        if (!uniq.length) { stat.innerHTML = '<span class="pill ok">✓ No obvious secrets found</span>'; out.innerHTML = '<div class="note">Heuristic scan only — a clean result is not a guarantee. Review sensitive files manually too.</div>'; return; }
        stat.innerHTML = `<span class="pill err">⚠ ${uniq.length} potential secret${uniq.length > 1 ? 's' : ''} found</span>`;
        out.innerHTML = uniq.map(h => `<div class="kv"><span class="k">${esc(h.label)} · line ${h.line}</span><span class="v mono">${esc(mask(h.match))}</span></div>`).join('') + '<div class="note">Rotate anything real that is exposed, and remove it from source & git history.</div>';
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'headers', grp: 'Security', e: '🧱', name: 'Security Headers Analyzer', desc: 'Grade HTTP response headers for CSP, HSTS, X-Frame & more.',
    tujuan: '<b>What it\'s for:</b> paste a site\'s HTTP <b>response headers</b> and get a graded report on the key security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy). <b>When:</b> hardening a web app or auditing one. Tip: copy headers from your browser\'s DevTools → Network → Headers.',
    contoh(root) { $('#in', root).value = 'HTTP/2 200\ncontent-type: text/html; charset=utf-8\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\nx-content-type-options: nosniff\nx-frame-options: DENY'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Paste HTTP response headers</label><textarea id="in" style="min-height:150px" placeholder="strict-transport-security: max-age=...&#10;content-security-policy: default-src 'self'"></textarea><div id="grade" style="margin-top:14px"></div><div id="out" style="margin-top:6px"></div>`;
      const CHECKS = [
        { key: 'strict-transport-security', name: 'Strict-Transport-Security (HSTS)', w: 20, ok: v => /max-age=\d{5,}/.test(v), tip: 'Add e.g. max-age=63072000; includeSubDomains; preload.' },
        { key: 'content-security-policy', name: 'Content-Security-Policy (CSP)', w: 25, ok: v => v.length > 0 && !/unsafe-inline.*unsafe-eval/.test(v), warn: v => /unsafe-inline|unsafe-eval/.test(v), tip: 'Define a policy; avoid unsafe-inline / unsafe-eval where possible.' },
        { key: 'x-content-type-options', name: 'X-Content-Type-Options', w: 15, ok: v => /nosniff/i.test(v), tip: 'Set to "nosniff".' },
        { key: 'x-frame-options', name: 'X-Frame-Options', w: 15, ok: v => /deny|sameorigin/i.test(v), tip: 'Set to DENY or SAMEORIGIN (or use CSP frame-ancestors).' },
        { key: 'referrer-policy', name: 'Referrer-Policy', w: 15, ok: v => v.length > 0, tip: 'Set e.g. strict-origin-when-cross-origin.' },
        { key: 'permissions-policy', name: 'Permissions-Policy', w: 10, ok: v => v.length > 0, tip: 'Restrict powerful features (camera, geolocation, etc).' },
      ];
      const run = () => {
        const v = $('#in', root).value, out = $('#out', root), gEl = $('#grade', root);
        if (!v.trim()) { gEl.innerHTML = ''; out.innerHTML = ''; return; }
        const map = {}; v.split('\n').forEach(l => { const i = l.indexOf(':'); if (i > 0) { const k = l.slice(0, i).trim().toLowerCase(); if (k && !/^http\//i.test(l)) map[k] = l.slice(i + 1).trim(); } });
        let score = 0, total = 0; const rows = [];
        for (const c of CHECKS) { total += c.w; const val = map[c.key]; let state, note; if (val == null) { state = 'err'; note = 'Missing — ' + c.tip; } else if (c.warn && c.warn(val)) { state = 'warn'; score += c.w * 0.5; note = 'Present but weak — ' + c.tip; } else if (c.ok(val)) { state = 'ok'; score += c.w; note = 'OK'; } else { state = 'warn'; score += c.w * 0.4; note = c.tip; } rows.push({ c, state, note }); }
        const pct = Math.round(score / total * 100);
        const grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 60 ? 'C' : pct >= 40 ? 'D' : 'F';
        const gcls = pct >= 75 ? 'ok' : pct >= 40 ? 'warn' : 'err';
        gEl.innerHTML = `<div class="row" style="align-items:center;gap:14px"><span class="pill ${gcls}" style="font-size:16px;padding:6px 16px">Grade ${grade}</span><b class="mono">${pct}/100</b></div><div class="progress" style="margin-top:4px"><i style="width:${pct}%"></i></div>`;
        out.innerHTML = rows.map(r => `<div class="kv"><span class="k">${r.state === 'ok' ? '✓' : r.state === 'warn' ? '!' : '✕'} ${esc(r.c.name)}</span><span class="v"><span class="pill ${r.state}">${r.state === 'ok' ? 'OK' : r.state === 'warn' ? 'Weak' : 'Missing'}</span></span></div>${r.state !== 'ok' ? `<div class="note" style="margin:2px 0 8px">${esc(r.note)}</div>` : ''}`).join('');
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'cvss', grp: 'Security', e: '📊', name: 'CVSS 3.1 Calculator', desc: 'Compute a CVSS v3.1 base score, severity & vector.',
    tujuan: '<b>What it\'s for:</b> turn the CVSS v3.1 base metrics into a <b>base score</b> (0–10), a severity rating, and the canonical vector string. <b>When:</b> triaging or reporting a vulnerability. Uses the official CVSS v3.1 formula.',
    body(root) {
      const M = {
        AV: { label: 'Attack Vector', opts: [['N', 'Network', 0.85], ['A', 'Adjacent', 0.62], ['L', 'Local', 0.55], ['P', 'Physical', 0.2]] },
        AC: { label: 'Attack Complexity', opts: [['L', 'Low', 0.77], ['H', 'High', 0.44]] },
        PR: { label: 'Privileges Required', opts: [['N', 'None', 0], ['L', 'Low', 0], ['H', 'High', 0]] },
        UI: { label: 'User Interaction', opts: [['N', 'None', 0.85], ['R', 'Required', 0.62]] },
        S: { label: 'Scope', opts: [['U', 'Unchanged', 0], ['C', 'Changed', 0]] },
        C: { label: 'Confidentiality', opts: [['H', 'High', 0.56], ['L', 'Low', 0.22], ['N', 'None', 0]] },
        I: { label: 'Integrity', opts: [['H', 'High', 0.56], ['L', 'Low', 0.22], ['N', 'None', 0]] },
        A: { label: 'Availability', opts: [['H', 'High', 0.56], ['L', 'Low', 0.22], ['N', 'None', 0]] },
      };
      const order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
      root.innerHTML = `<div class="cardrow">${order.map(k => `<div><label class="lbl">${M[k].label} (${k})</label><select class="f" id="m_${k}">${M[k].opts.map((o, i) => `<option value="${o[0]}"${i === 0 ? ' selected' : ''}>${o[1]} (${o[0]})</option>`).join('')}</select></div>`).join('')}</div><div id="out" style="margin-top:16px"></div>`;
      const roundup = x => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
      const run = () => {
        const sel = {}; order.forEach(k => sel[k] = $('#m_' + k, root).value);
        const scopeChanged = sel.S === 'C';
        const prVal = { N: 0.85, L: scopeChanged ? 0.68 : 0.62, H: scopeChanged ? 0.5 : 0.27 }[sel.PR];
        const g = (k, code) => M[k].opts.find(o => o[0] === code)[2];
        const iscBase = 1 - (1 - g('C', sel.C)) * (1 - g('I', sel.I)) * (1 - g('A', sel.A));
        const impact = scopeChanged ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15) : 6.42 * iscBase;
        const expl = 8.22 * g('AV', sel.AV) * g('AC', sel.AC) * prVal * g('UI', sel.UI);
        let score = impact <= 0 ? 0 : roundup(Math.min((scopeChanged ? 1.08 : 1) * (impact + expl), 10));
        const sev = score === 0 ? ['None', 'info'] : score < 4 ? ['Low', 'ok'] : score < 7 ? ['Medium', 'warn'] : score < 9 ? ['High', 'err'] : ['Critical', 'err'];
        const vector = 'CVSS:3.1/' + order.map(k => k + ':' + sel[k]).join('/');
        $('#out', root).innerHTML = `<div class="row" style="align-items:center;gap:14px"><span class="pill ${sev[1]}" style="font-size:18px;padding:7px 18px">${score.toFixed(1)}</span><b>${sev[0]}</b></div><label class="lbl" style="margin-top:12px">Vector string</label><div class="out">${esc(vector)}<button class="copy" data-c="${esc(vector)}">Copy</button></div>`;
        $('#out', root).querySelector('[data-c]').addEventListener('click', e => copy(e.target.dataset.c));
      };
      root.querySelectorAll('select').forEach(s => s.addEventListener('change', run)); run();
    } },

  { id: 'token', grp: 'Security', e: '🎰', name: 'Random Token Generator', desc: 'Generate cryptographically-random tokens (hex/base64/url).',
    tujuan: '<b>What it\'s for:</b> generate high-entropy random tokens using the browser\'s cryptographic RNG — for API keys, session IDs, CSRF tokens, or nonces. <b>When:</b> you need a secure random string. Never produced with Math.random.',
    body(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Bytes</label><input class="f" id="n" type="number" value="32" min="4" max="256" style="width:100px"><label class="lbl" style="margin:0">Format</label><select class="f" id="fmt" style="width:160px"><option value="hex">Hex</option><option value="b64">Base64</option><option value="b64url">Base64 URL-safe</option><option value="alnum">Alphanumeric</option></select><label class="lbl" style="margin:0">Count</label><input class="f" id="c" type="number" value="1" min="1" max="100" style="width:90px"><button class="btn acc" id="gen" type="button">Generate</button></div><div class="out empty big" id="out" style="margin-top:12px">—</div><div class="note" id="meta"></div>`;
      const alnum = bytes => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; return [...bytes].map(b => A[b % 62]).join(''); };
      const run = () => {
        const n = Math.max(4, Math.min(256, +$('#n', root).value || 32)), fmt = $('#fmt', root).value, c = Math.max(1, Math.min(100, +$('#c', root).value || 1));
        const lines = []; for (let i = 0; i < c; i++) { const u = crypto.getRandomValues(new Uint8Array(n)); lines.push(fmt === 'hex' ? hex(u) : fmt === 'b64' ? b64(u) : fmt === 'b64url' ? b64url(u) : alnum(u)); }
        setOut($('#out', root), lines.join('\n')); $('#meta', root).innerHTML = `Entropy ≈ <b>${n * 8} bit</b> per token · cryptographically secure`;
      };
      root.querySelectorAll('input,select').forEach(x => x.addEventListener('input', run)); $('#gen', root).addEventListener('click', run); run();
    } },

  // ---------- GENERATOR (new) ----------
  { id: 'ulid', grp: 'Generator', e: '🪪', name: 'ULID Generator', desc: 'Generate sortable, timestamp-based unique IDs (ULID).',
    tujuan: '<b>What it\'s for:</b> ULIDs are 26-character, URL-safe IDs that sort lexicographically by creation time — a friendlier alternative to UUID v4 for database keys. <b>When:</b> you want unique IDs that are also time-ordered.',
    body(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Count</label><input class="f" id="n" type="number" value="5" min="1" max="500" style="width:100px"><button class="btn acc" id="gen" type="button">Generate</button></div><div class="out empty" id="out" style="margin-top:12px">—</div><div class="note">Format: 48-bit timestamp (10 chars) + 80-bit randomness (16 chars), Crockford Base32.</div>`;
      const ENC = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
      const encTime = (now, len) => { let s = ''; for (let i = len - 1; i >= 0; i--) { const mod = now % 32; s = ENC[mod] + s; now = (now - mod) / 32; } return s; };
      const encRand = len => { const u = crypto.getRandomValues(new Uint8Array(len)); return [...u].map(b => ENC[b % 32]).join(''); };
      const ulid = () => encTime(Date.now(), 10) + encRand(16);
      const run = () => { const n = Math.max(1, Math.min(500, +$('#n', root).value || 1)); setOut($('#out', root), Array.from({ length: n }, ulid).join('\n')); };
      $('#gen', root).addEventListener('click', run); run();
    } },

  { id: 'mock', grp: 'Generator', e: '🧪', name: 'Mock Data Generator', desc: 'Generate fake rows (name, email, etc.) as JSON or CSV.',
    tujuan: '<b>What it\'s for:</b> quickly generate realistic-looking sample data for testing, seeding a database, or filling a UI. Pick the fields and row count, export as JSON or CSV. <b>When:</b> prototyping without real data. Generated locally.',
    body(root) {
      const FIELDS = ['id', 'uuid', 'name', 'email', 'username', 'city', 'country', 'phone', 'company', 'job', 'int', 'price', 'bool', 'date', 'ip'];
      root.innerHTML = `<label class="lbl">Fields</label><div class="row" id="flds">${FIELDS.map((f, i) => `<label class="chk"><input type="checkbox" value="${f}" ${['name', 'email', 'city', 'int'].includes(f) ? 'checked' : ''}> ${f}</label>`).join('')}</div>
        <div class="row" style="margin-top:8px"><label class="lbl" style="margin:0">Rows</label><input class="f" id="n" type="number" value="10" min="1" max="1000" style="width:100px"><div class="seg" id="out_m"><button data-m="json" class="on">JSON</button><button data-m="csv">CSV</button></div><button class="btn acc" id="gen" type="button">Generate</button><button class="btn sm" id="dl" type="button">⭳ Download</button></div>
        <div class="out empty" id="out" style="margin-top:12px">—</div>`;
      const FIRST = ['Nadia', 'Andi', 'Budi', 'Maya', 'Riko', 'Sari', 'Dewi', 'Aldo', 'Lina', 'Tomi', 'Olivia', 'Liam', 'Emma', 'Noah', 'Ava', 'Yuki', 'Hana', 'Diego', 'Sofia', 'Omar'];
      const LAST = ['Pratama', 'Santoso', 'Wijaya', 'Putri', 'Hidayat', 'Smith', 'Johnson', 'Garcia', 'Kim', 'Tanaka', 'Rossi', 'Dubois', 'Novak', 'Haddad'];
      const CITY = ['Jakarta', 'Pontianak', 'Bandung', 'Tokyo', 'Berlin', 'Austin', 'Lisbon', 'Nairobi', 'Toronto', 'Seoul', 'Oslo', 'Cairo'];
      const COUNTRY = ['Indonesia', 'Japan', 'Germany', 'USA', 'Portugal', 'Kenya', 'Canada', 'South Korea', 'Norway', 'Egypt'];
      const COMPANY = ['Luxavero', 'Acme Corp', 'Globex', 'Initech', 'Umbrella', 'Hooli', 'Stark Industries', 'Wayne Enterprises'];
      const JOB = ['Engineer', 'Designer', 'Analyst', 'Manager', 'Architect', 'Consultant', 'Developer', 'Researcher'];
      const ri = n => Math.floor(Math.random() * n), pick = a => a[ri(a.length)];
      const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = ri(16), v = c === 'x' ? r : (r & 0x3 | 0x8); return v.toString(16); }));
      const genVal = (f, i) => { const fn = pick(FIRST), ln = pick(LAST); switch (f) { case 'id': return i + 1; case 'uuid': return uuid(); case 'name': return fn + ' ' + ln; case 'email': return (fn + '.' + ln).toLowerCase() + '@' + pick(['mail.com', 'example.com', 'inbox.io', 'test.dev']); case 'username': return (fn + ln[0]).toLowerCase() + ri(1000); case 'city': return pick(CITY); case 'country': return pick(COUNTRY); case 'phone': return '+' + (10 + ri(80)) + ' ' + (100 + ri(900)) + '-' + (1000 + ri(9000)); case 'company': return pick(COMPANY); case 'job': return pick(JOB); case 'int': return ri(1000); case 'price': return (ri(100000) / 100).toFixed(2); case 'bool': return Math.random() < 0.5; case 'date': return new Date(Date.now() - ri(3e10)).toISOString().slice(0, 10); case 'ip': return [ri(256), ri(256), ri(256), ri(256)].join('.'); default: return ''; } };
      let mode = 'json', lastText = '', lastExt = 'json';
      const build = () => {
        const flds = [...root.querySelectorAll('#flds input:checked')].map(c => c.value); if (!flds.length) { setErr($('#out', root), 'Pick at least one field'); return; }
        const n = Math.max(1, Math.min(1000, +$('#n', root).value || 10));
        const rows = Array.from({ length: n }, (_, i) => { const o = {}; flds.forEach(f => o[f] = genVal(f, i)); return o; });
        if (mode === 'json') { lastText = JSON.stringify(rows, null, 2); lastExt = 'json'; }
        else { const esc2 = v => { let s = typeof v === 'object' ? JSON.stringify(v) : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }; lastText = [flds.join(','), ...rows.map(r => flds.map(f => esc2(r[f])).join(','))].join('\r\n'); lastExt = 'csv'; }
        setOut($('#out', root), lastText);
      };
      $('#out_m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#out_m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); build(); });
      $('#gen', root).addEventListener('click', build);
      $('#dl', root).addEventListener('click', () => { if (!lastText) return; const blob = new Blob([lastExt === 'csv' ? '\ufeff' + lastText : lastText], { type: lastExt === 'csv' ? 'text/csv' : 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'mock-data.' + lastExt; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); });
      build();
    } },

  // ---------- ENCODE / DECODE (new) ----------
  { id: 'hex', grp: 'Encode / Decode', e: '🔣', name: 'Hex ↔ Text', desc: 'Convert text to hexadecimal and back (UTF-8).',
    tujuan: '<b>What it\'s for:</b> convert text to its hexadecimal byte representation and back — useful for debugging encodings, binary protocols, or byte-level data. <b>When:</b> inspecting raw bytes of a string.',
    contoh(root) { $('#in', root).value = 'DevSec 🔐'; fire($('#in', root)); },
    body(root) {
      let mode = 'encode';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Text → Hex</button><button data-m="decode">Hex → Text</button></div><label class="chk"><input type="checkbox" id="sp" checked> Space-separated</label></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { if (!v) { setOut(out, ''); return; } if (mode === 'encode') { const h = [...enc.encode(v)].map(b => b.toString(16).padStart(2, '0')); setOut(out, $('#sp', root).checked ? h.join(' ') : h.join('')); } else { const clean = v.replace(/0x/gi, '').replace(/[\s,]+/g, ''); if (!/^[0-9a-f]*$/i.test(clean) || clean.length % 2) throw 0; const bytes = new Uint8Array(clean.match(/../g).map(x => parseInt(x, 16))); setOut(out, new TextDecoder().decode(bytes)); } } catch (e) { setErr(out, 'Invalid hex input'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#sp', root).addEventListener('change', run); $('#in', root).addEventListener('input', run);
    } },

  { id: 'base32', grp: 'Encode / Decode', e: '🔠', name: 'Base32', desc: 'Encode & decode Base32 (RFC 4648).',
    tujuan: '<b>What it\'s for:</b> Base32 encodes binary data using only A–Z and 2–7 — case-insensitive and safe for systems that mangle case or special characters (e.g. TOTP secrets, DNS). <b>When:</b> working with OTP seeds or case-insensitive tokens.',
    contoh(root) { $('#in', root).value = 'DevSec Toolbox'; fire($('#in', root)); },
    body(root) {
      let mode = 'encode'; const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const b32enc = bytes => { let bits = 0, val = 0, out = ''; for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += A[(val << (5 - bits)) & 31]; while (out.length % 8) out += '='; return out; };
      const b32dec = str => { str = str.replace(/=+$/, '').toUpperCase().replace(/\s/g, ''); let bits = 0, val = 0; const out = []; for (const ch of str) { const idx = A.indexOf(ch); if (idx < 0) throw 0; val = (val << 5) | idx; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); };
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { if (!v) { setOut(out, ''); return; } setOut(out, mode === 'encode' ? b32enc(enc.encode(v)) : new TextDecoder().decode(b32dec(v))); } catch (e) { setErr(out, 'Invalid Base32 input'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'base58', grp: 'Encode / Decode', e: '🅱️', name: 'Base58', desc: 'Encode & decode Base58 (Bitcoin alphabet).',
    tujuan: '<b>What it\'s for:</b> Base58 drops easily-confused characters (0, O, I, l) and all punctuation — used by Bitcoin addresses, IPFS, and short IDs. <b>When:</b> producing human-friendly identifiers. Runs in your browser.',
    contoh(root) { $('#in', root).value = 'Hello DevSec'; fire($('#in', root)); },
    body(root) {
      let mode = 'encode'; const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const enc58 = bytes => { let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++; const digits = [0]; for (let i = zeros; i < bytes.length; i++) { let carry = bytes[i]; for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; } while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; } } let s = '1'.repeat(zeros); for (let i = digits.length - 1; i >= 0; i--) s += A[digits[i]]; return s; };
      const dec58 = str => { str = str.trim(); let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++; const bytes = [0]; for (let i = zeros; i < str.length; i++) { const val = A.indexOf(str[i]); if (val < 0) throw 0; let carry = val; for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 255; carry >>= 8; } while (carry) { bytes.push(carry & 255); carry >>= 8; } } const out = new Uint8Array(zeros + bytes.length); for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i]; return out; };
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { if (!v) { setOut(out, ''); return; } setOut(out, mode === 'encode' ? enc58(enc.encode(v)) : new TextDecoder().decode(dec58(v))); } catch (e) { setErr(out, 'Invalid Base58 input'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'unicode', grp: 'Encode / Decode', e: '🔤', name: 'Unicode Escape', desc: 'Escape text to \\uXXXX and back, with code points.',
    tujuan: '<b>What it\'s for:</b> convert text to <span class="mono">\\uXXXX</span> escape sequences (and back), and inspect each character\'s Unicode code point. <b>When:</b> embedding non-ASCII safely in source code or debugging encoding issues.',
    contoh(root) { $('#in', root).value = 'Hello 🌍 café'; fire($('#in', root)); },
    body(root) {
      let mode = 'escape';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="escape" class="on">Text → \\u</button><button data-m="unescape">\\u → Text</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const escU = s => { let out = ''; for (const ch of s) { const cp = ch.codePointAt(0); if (cp > 0xffff) { const h = cp - 0x10000; out += '\\u' + (0xd800 + (h >> 10)).toString(16).padStart(4, '0') + '\\u' + (0xdc00 + (h & 0x3ff)).toString(16).padStart(4, '0'); } else if (cp < 0x20 || cp > 0x7e) out += '\\u' + cp.toString(16).padStart(4, '0'); else out += ch; } return out; };
      const unescU = s => s.replace(/\\u\{([0-9a-f]+)\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      const run = () => { const v = $('#in', root).value, out = $('#out', root); if (!v) { setOut(out, ''); return; } setOut(out, mode === 'escape' ? escU(v) : unescU(v)); };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#in', root).addEventListener('input', run);
    } },

  // ---------- FORMAT & DATA (new) ----------
  { id: 'xml', grp: 'Format & Data', e: '🗂️', name: 'XML Formatter', desc: 'Pretty-print, minify & validate XML.',
    tujuan: '<b>What it\'s for:</b> reformat messy XML into a readable, indented structure, minify it, and catch well-formedness errors. <b>When:</b> reading an API response, config, or SOAP payload.',
    contoh(root) { $('#in', root).value = '<note><to>Nadia</to><from>DevSec</from><body>Hello <b>world</b></body></note>'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="row"><button class="btn acc sm" id="fmt" type="button">Beautify</button><button class="btn sm" id="min" type="button">Minify</button><span id="stat"></span></div><label class="lbl">XML</label><textarea id="in" style="min-height:160px"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const check = v => { const doc = new DOMParser().parseFromString(v, 'application/xml'); const err = doc.querySelector('parsererror'); return err ? err.textContent.replace(/\s+/g, ' ').trim() : null; };
      const pretty = xml => { let formatted = '', indent = 0; const PAD = '  '; xml = xml.replace(/>\s*</g, '><').replace(/</g, '\n<').trim(); xml.split('\n').forEach(node => { if (!node.trim()) return; if (/^<\/\w/.test(node)) indent = Math.max(0, indent - 1); formatted += PAD.repeat(indent) + node.trim() + '\n'; if (/^<\w[^>]*[^\/]>$/.test(node) && !/^<\w[^>]*>.*<\/\w/.test(node) && !/^<(\?|!)/.test(node)) indent++; }); return formatted.trim(); };
      const show = minify => { const v = $('#in', root).value.trim(), out = $('#out', root), stat = $('#stat', root); if (!v) { setOut(out, ''); stat.innerHTML = ''; return; } const err = check(v); if (err) { stat.innerHTML = '<span class="pill err">Invalid</span>'; return setErr(out, err); } stat.innerHTML = '<span class="pill ok">Well-formed</span>'; setOut(out, minify ? v.replace(/>\s+</g, '><').trim() : pretty(v)); };
      $('#fmt', root).addEventListener('click', () => show(false)); $('#min', root).addEventListener('click', () => show(true));
      $('#in', root).addEventListener('input', () => show(false));
    } },

  { id: 'jsonxml', grp: 'Format & Data', e: '🧬', name: 'JSON → XML', desc: 'Convert a JSON object into XML.',
    tujuan: '<b>What it\'s for:</b> turn JSON into equivalent XML — objects become nested elements, arrays repeat an <span class="mono">&lt;item&gt;</span> element. <b>When:</b> integrating with an XML/SOAP system from JSON data.',
    contoh(root) { $('#in', root).value = '{"user":{"name":"Nadia","roles":["admin","editor"],"active":true}}'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JSON</label><textarea id="in" style="min-height:150px" placeholder='{"a":1}'></textarea><label class="lbl" style="margin-top:12px">XML</label><div class="out empty" id="out">—</div>`;
      const escX = s => String(s).replace(/[<>&'"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));
      const tagName = k => /^[A-Za-z_][\w.-]*$/.test(k) ? k : 'item';
      const toXml = (v, key, ind) => { const pad = '  '.repeat(ind); if (Array.isArray(v)) return v.map(it => toXml(it, key, ind)).join('\n'); if (v !== null && typeof v === 'object') { const inner = Object.keys(v).map(k => toXml(v[k], k, ind + 1)).join('\n'); return `${pad}<${tagName(key)}>\n${inner}\n${pad}</${tagName(key)}>`; } return `${pad}<${tagName(key)}>${escX(v == null ? '' : v)}</${tagName(key)}>`; };
      const run = () => { const raw = $('#in', root).value.trim(), out = $('#out', root); if (!raw) { setOut(out, ''); return; } let data; try { data = JSON.parse(raw); } catch (e) { return setErr(out, 'Invalid JSON: ' + e.message); } const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + toXml(data, 'root', 0); setOut(out, xml); };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'xor', grp: 'Encode / Decode', e: '🔀', name: 'XOR Cipher', desc: 'XOR data with a key, or brute-force single-byte XOR (CTF).',
    tujuan: '<b>What it\'s for:</b> XOR a message against a repeating key, or brute-force all 256 single-byte keys to crack a classic XOR cipher — a staple of CTF crypto. <b>When:</b> a decoded blob turns into unreadable bytes. Everything runs in your browser.',
    contoh(root) { $('#in', root).value = '242e2325391072161d762c261d1a72101d362a711d212e7631317321313f'; $('#m button[data-m="brute"]', root).click(); },
    body(root) {
      let mode = 'key', inFmt = 'hex';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="key" class="on">XOR (key)</button><button data-m="brute">Brute 1-byte</button></div><label class="lbl" style="margin:0">Input format</label><select class="f" id="fmt" style="width:120px"><option value="hex">Hex</option><option value="text">Text</option><option value="b64">Base64</option></select></div><label class="lbl" style="margin-top:12px">Input</label><textarea id="in" placeholder="paste ciphertext…"></textarea><div class="row" id="keyrow" style="margin-top:12px"><label class="lbl" style="margin:0">Key</label><input class="f" id="key" style="max-width:240px" placeholder="key"><select class="f" id="kfmt" style="width:120px"><option value="text">Text key</option><option value="hex">Hex key</option></select></div><div class="row" id="brow" style="margin-top:12px;display:none"><label class="lbl" style="margin:0">Only show results containing</label><input class="f" id="needle" style="max-width:200px" value="flag"></div><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const toBytes = (v, fmt) => { v = v.trim(); if (fmt === 'hex') { const c = v.replace(/0x/gi, '').replace(/[\s,]+/g, ''); if (!/^[0-9a-f]*$/i.test(c) || c.length % 2) throw 0; return new Uint8Array(c.match(/../g).map(x => parseInt(x, 16))); } if (fmt === 'b64') { const bin = atob(v.replace(/\s/g, '')); return Uint8Array.from(bin, ch => ch.charCodeAt(0)); } return enc.encode(v); };
      const xorB = (d, k) => { const o = new Uint8Array(d.length); for (let i = 0; i < d.length; i++) o[i] = d[i] ^ k[i % k.length]; return o; };
      const printable = u8 => u8.length > 0 && [...u8].every(b => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13);
      const asText = u8 => new TextDecoder('utf-8', { fatal: false }).decode(u8);
      const run = () => {
        const out = $('#out', root), v = $('#in', root).value;
        if (!v.trim()) { setOut(out, ''); return; }
        let data; try { data = toBytes(v, inFmt); } catch (e) { setErr(out, 'Invalid ' + inFmt + ' input'); return; }
        if (mode === 'key') {
          const kv = $('#key', root).value, kfmt = $('#kfmt', root).value;
          if (!kv) { setOut(out, ''); return; }
          let key; try { key = kfmt === 'hex' ? toBytes(kv, 'hex') : enc.encode(kv); } catch (e) { setErr(out, 'Invalid hex key'); return; }
          if (!key.length) { setErr(out, 'Empty key'); return; }
          const res = xorB(data, key), txt = asText(res);
          out.classList.remove('empty');
          out.innerHTML = `<div class="kv"><span class="k">Text</span><span class="v" data-c="${esc(txt)}" style="cursor:pointer;word-break:break-all">${esc(txt)} ⧉</span></div><div class="kv"><span class="k">Hex</span><span class="v" data-c="${hex(res)}" style="cursor:pointer;word-break:break-all">${hex(res)} ⧉</span></div>`;
          out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c)));
        } else {
          const needle = $('#needle', root).value.toLowerCase(), rows = [];
          for (let k = 0; k < 256; k++) { const res = xorB(data, new Uint8Array([k])), txt = asText(res); const ok = needle ? txt.toLowerCase().includes(needle) : printable(res); if (ok) rows.push(`<div class="kv"><span class="k">0x${k.toString(16).padStart(2, '0')}</span><span class="v" data-c="${esc(txt)}" style="cursor:pointer;word-break:break-all">${esc(txt)} ⧉</span></div>`); }
          out.classList.remove('empty');
          out.innerHTML = rows.length ? rows.join('') : '<span class="pill err">No matching key — clear the filter to see printable results</span>';
          out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c)));
        }
      };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); $('#keyrow', root).style.display = mode === 'key' ? '' : 'none'; $('#brow', root).style.display = mode === 'brute' ? '' : 'none'; run(); });
      $('#fmt', root).addEventListener('change', e => { inFmt = e.target.value; run(); });
      $('#kfmt', root).addEventListener('change', run);
      ['#in', '#key', '#needle'].forEach(s => $(s, root).addEventListener('input', run));
    } },

  { id: 'sql', grp: 'Format & Data', e: '🗄️', name: 'SQL Formatter', desc: 'Format & indent SQL queries for readability.',
    tujuan: '<b>What it\'s for:</b> reformat a one-line or messy SQL query into a readable, indented layout with keywords on their own lines. <b>When:</b> reviewing a query from a log or ORM. Best-effort formatter for common SQL.',
    contoh(root) { $('#in', root).value = 'select id, name, email from users u join orders o on o.user_id=u.id where u.active=1 and o.total>100 order by o.total desc limit 10'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="row"><button class="btn acc sm" id="fmt" type="button">Format</button><label class="chk"><input type="checkbox" id="uc" checked> Uppercase keywords</label></div><label class="lbl">SQL</label><textarea id="in" style="min-height:120px"></textarea><label class="lbl" style="margin-top:12px">Result</label><div class="out empty" id="out">—</div>`;
      const NL = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE FROM', 'INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL JOIN', 'JOIN', 'ON', 'UNION', 'UNION ALL'];
      const KW = [...NL, 'AS', 'IN', 'IS', 'NULL', 'NOT', 'LIKE', 'BETWEEN', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'ASC', 'DESC', 'INT', 'VARCHAR'];
      const run = () => {
        let v = $('#in', root).value.trim(); const out = $('#out', root); if (!v) { setOut(out, ''); return; }
        const upper = $('#uc', root).checked;
        v = v.replace(/\s+/g, ' ');
        if (upper) for (const k of KW.sort((a, b) => b.length - a.length)) v = v.replace(new RegExp('\\b' + k.replace(/ /g, '\\s+') + '\\b', 'gi'), k);
        for (const k of NL.sort((a, b) => b.length - a.length)) v = v.replace(new RegExp('\\s+(' + k.replace(/ /g, '\\s+') + ')\\b', 'gi'), (m, g) => '\n' + (upper ? k : g));
        const lines = v.split('\n').map(l => { const t = l.trim(); return /^(AND|OR|ON)\b/i.test(t) ? '  ' + t : t; });
        setOut(out, lines.join('\n').replace(/,\s*/g, ',\n  ').replace(/^\s*\n/gm, '').trim());
      };
      $('#fmt', root).addEventListener('click', run); $('#in', root).addEventListener('input', run); $('#uc', root).addEventListener('change', run);
    } },

  { id: 'markdown', grp: 'Format & Data', e: '📘', name: 'Markdown Preview', desc: 'Render Markdown to a live HTML preview & copy the HTML.',
    tujuan: '<b>What it\'s for:</b> write or paste Markdown and see it rendered instantly, then copy the generated HTML. Supports headings, bold/italic, code, links, lists, blockquotes, and rules. <b>When:</b> drafting a README or checking formatting. Rendered safely in your browser.',
    contoh(root) { $('#in', root).value = '# DevSec Toolbox\n\n**Fast**, private, *free* dev tools.\n\n- Runs in your browser\n- No data leaves your device\n\n> Privacy by design.\n\n`inline code` and a [link](https://devsec.ksatriabintangsamudra.com).'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="cardrow"><div><label class="lbl">Markdown</label><textarea id="in" style="min-height:260px"></textarea></div><div><label class="lbl">Preview</label><div class="out" id="prev" style="min-height:260px"></div></div></div><div class="row" style="margin-top:12px"><button class="btn sm" id="cp" type="button">Copy HTML</button></div>`;
      const esc2 = s => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
      const inline = s => esc2(s)
        .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>')
        .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
      const render = md => {
        const lines = md.replace(/\r\n?/g, '\n').split('\n'); let html = '', i = 0;
        while (i < lines.length) {
          const l = lines[i];
          if (/^```/.test(l)) { let code = ''; i++; while (i < lines.length && !/^```/.test(lines[i])) code += lines[i++] + '\n'; i++; html += `<pre><code>${esc2(code.replace(/\n$/, ''))}</code></pre>`; continue; }
          let m;
          if (m = l.match(/^(#{1,6})\s+(.*)/)) { html += `<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`; i++; continue; }
          if (/^\s*([-*_])\1{1,}\s*$/.test(l) || /^(---|\*\*\*|___)$/.test(l.trim())) { html += '<hr>'; i++; continue; }
          if (/^>\s?/.test(l)) { let q = ''; while (i < lines.length && /^>\s?/.test(lines[i])) q += lines[i++].replace(/^>\s?/, '') + ' '; html += `<blockquote>${inline(q.trim())}</blockquote>`; continue; }
          if (/^\s*[-*+]\s+/.test(l)) { html += '<ul>'; while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) html += `<li>${inline(lines[i++].replace(/^\s*[-*+]\s+/, ''))}</li>`; html += '</ul>'; continue; }
          if (/^\s*\d+\.\s+/.test(l)) { html += '<ol>'; while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) html += `<li>${inline(lines[i++].replace(/^\s*\d+\.\s+/, ''))}</li>`; html += '</ol>'; continue; }
          if (l.trim() === '') { i++; continue; }
          let para = ''; while (i < lines.length && lines[i].trim() !== '' && !/^(#{1,6}\s|>|\s*[-*+]\s|\s*\d+\.\s|```)/.test(lines[i])) para += lines[i++] + ' '; html += `<p>${inline(para.trim())}</p>`;
        }
        return html;
      };
      let lastHtml = '';
      const run = () => { lastHtml = render($('#in', root).value); $('#prev', root).innerHTML = lastHtml || '<span style="color:var(--tx3)">Preview…</span>'; };
      $('#in', root).addEventListener('input', run); $('#cp', root).addEventListener('click', () => copy(lastHtml));
      run();
    } },

  // ---------- CONVERTERS (new) ----------
  { id: 'shades', grp: 'Converters', e: '🌈', name: 'Color Shades', desc: 'Generate a tint & shade palette from one base color.',
    tujuan: '<b>What it\'s for:</b> from one base color, generate a full palette of lighter tints and darker shades (like a design-system color scale). <b>When:</b> building a UI theme and need consistent steps. Click any swatch to copy its hex.',
    contoh(root) { $('#in', root).value = '#02aab0'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="row"><input type="color" id="pick" value="#02aab0" class="cpick"><input class="f" id="in" value="#02aab0" style="max-width:220px" placeholder="#02aab0"></div><div id="out" style="margin-top:14px"></div>`;
      const toRgb = h => { h = h.replace('#', ''); if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; };
      const toHex = ([r, g, b]) => '#' + [r, g, b].map(x => Math.max(0, Math.min(255, Math.round(x))).toString(16).padStart(2, '0')).join('');
      const mix = (c, t, amt) => c.map((v, i) => v + (t[i] - v) * amt);
      const run = (src) => { const out = $('#out', root); let hex6 = src.trim(); if (!/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.test(hex6)) return setErr(out, 'Enter a valid hex color'); const rgb = toRgb(hex6); const base = toHex(rgb); $('#pick', root).value = base; const steps = [['50', mix(rgb, [255, 255, 255], 0.9)], ['100', mix(rgb, [255, 255, 255], 0.78)], ['200', mix(rgb, [255, 255, 255], 0.6)], ['300', mix(rgb, [255, 255, 255], 0.42)], ['400', mix(rgb, [255, 255, 255], 0.22)], ['500', rgb], ['600', mix(rgb, [0, 0, 0], 0.18)], ['700', mix(rgb, [0, 0, 0], 0.34)], ['800', mix(rgb, [0, 0, 0], 0.5)], ['900', mix(rgb, [0, 0, 0], 0.66)]]; out.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px">${steps.map(([lbl, c]) => { const hx = toHex(c); const light = (c[0] * 299 + c[1] * 587 + c[2] * 114) / 1000 > 140; return `<button type="button" data-c="${hx}" style="border:1px solid var(--line2);border-radius:10px;padding:14px 10px;background:${hx};color:${light ? '#111' : '#fff'};cursor:pointer;font-family:var(--mono);font-size:12px;text-align:left"><b>${lbl}</b><br>${hx}</button>`; }).join('')}</div><div class="note">Click a swatch to copy its hex.</div>`; out.querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c))); };
      $('#in', root).addEventListener('input', e => run(e.target.value)); $('#pick', root).addEventListener('input', e => { $('#in', root).value = e.target.value; run(e.target.value); }); run('#02aab0');
    } },


  // ================= PHASE 3: LIVE SCANNERS (Cloudflare Worker-powered) =================
  { id: 'scadep', grp: 'Scanners', e: '🔍', live: true, name: 'Dependency Vuln Scanner', desc: 'Scan a lockfile for known CVEs via the OSV.dev database.',
    tujuan: '<b>What it\'s for:</b> paste a dependency manifest (package-lock.json, package.json, requirements.txt, go.mod, Gemfile.lock, or composer.json) and find <b>known vulnerabilities</b> in your dependencies, with severity and the version that fixes them. Like the core of Trivy / OSV-Scanner. <b>When:</b> auditing a project before shipping. <b>Live:</b> the parsed package list is sent to this site\'s Cloudflare edge, which queries the public OSV.dev database (your code never leaves the browser — only package names + versions).',
    contoh(root) { $('#in', root).value = '{\n  "dependencies": {\n    "lodash": "4.17.4",\n    "express": "4.17.1",\n    "axios": "0.21.0",\n    "minimist": "1.2.0"\n  }\n}'; },
    body(root) {
      root.innerHTML = `<label class="lbl">Dependency manifest</label><textarea id="in" style="min-height:170px" placeholder="paste package-lock.json / package.json / requirements.txt / go.mod / Gemfile.lock / composer.json"></textarea>
        <div class="row" style="margin-top:10px"><button class="btn acc" id="scan" type="button">Scan dependencies</button><span id="stat"></span></div>
        <div id="out" style="margin-top:12px"></div>`;
      const clean = r => (String(r).match(/\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?/) || [])[0];
      const parseManifest = text => {
        text = text.trim(); const q = [];
        const add = (n, v, eco) => { if (n && v) q.push({ package: { name: n.trim(), ecosystem: eco }, version: String(v).replace(/^v/, '').trim() }); };
        if (text[0] === '{') {
          let j; try { j = JSON.parse(text); } catch { j = null; }
          if (j) {
            if (j.packages && typeof j.packages === 'object') for (const [k, v] of Object.entries(j.packages)) { const nm = k.split('node_modules/').pop(); if (nm && v && v.version) add(nm, v.version, 'npm'); }
            if (!q.length && j.dependencies && Object.values(j.dependencies)[0] && Object.values(j.dependencies)[0].version) { const walk = d => { for (const [nm, v] of Object.entries(d)) { if (v && v.version) add(nm, v.version, 'npm'); if (v && v.dependencies) walk(v.dependencies); } }; walk(j.dependencies); }
            if (!q.length && (j.dependencies || j.devDependencies)) for (const g of ['dependencies', 'devDependencies']) if (j[g]) for (const [nm, r] of Object.entries(j[g])) { const vv = clean(r); if (vv) add(nm, vv, 'npm'); }
            if (!q.length && (j.require || j['require-dev'])) for (const g of ['require', 'require-dev']) if (j[g]) for (const [nm, r] of Object.entries(j[g])) { if (nm === 'php' || nm.startsWith('ext-')) continue; const vv = clean(r); if (vv) add(nm, vv, 'Packagist'); }
            return q;
          }
        }
        const lines = text.split('\n');
        lines.forEach(l => { const m = l.match(/^\s*([a-zA-Z0-9._-]+)\s*==\s*([\w.]+)/); if (m) add(m[1], m[2], 'PyPI'); });
        if (q.length) return q;
        if (/^\s*(module|require|go)\s/m.test(text)) { lines.forEach(l => { const m = l.match(/^\s*(?:require\s+)?([\w.-]+(?:\/[\w.-]+)+)\s+v(\d+\.\d+\.\d+(?:[-+][\w.]+)?)/); if (m) add(m[1], m[2], 'Go'); }); if (q.length) return q; }
        lines.forEach(l => { const m = l.match(/^\s{4}([\w-]+) \(([\d.]+)\)/); if (m) add(m[1], m[2], 'RubyGems'); });
        return q;
      };
      const sevPill = v => { const s = v.severity || (v.score ? (v.score >= 9 ? 'Critical' : v.score >= 7 ? 'High' : v.score >= 4 ? 'Medium' : 'Low') : ''); const cls = /crit|high/i.test(s) ? 'err' : /med/i.test(s) ? 'warn' : s ? 'info' : ''; return s ? `<span class="pill ${cls}">${esc(s)}${v.score ? ' ' + v.score : ''}</span>` : '<span class="pill info">Unknown</span>'; };
      const scan = async () => {
        const out = $('#out', root), stat = $('#stat', root), btn = $('#scan', root);
        const queries = parseManifest($('#in', root).value);
        if (!queries.length) { stat.innerHTML = ''; return setErr(out, 'Could not detect any dependencies. Supported: package-lock.json, package.json, requirements.txt, go.mod, Gemfile.lock, composer.json.'); }
        stat.innerHTML = `<span class="pill info">${queries.length} packages</span>`;
        btn.classList.add('loading'); prog.start(true);
        out.innerHTML = `<div class="proc"><span class="spinner"></span>Querying OSV.dev for ${queries.length} packages…</div>`;
        try {
          const res = await fetch('/api/sca', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries }) });
          const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Scan failed');
          if (!d.results.length) { out.innerHTML = `<div class="row"><span class="pill ok">✓ No known vulnerabilities</span><span class="pill info">${d.scanned} packages scanned</span></div><div class="note">Clean against the OSV.dev database right now. Keep dependencies updated.</div>`; return; }
          let html = `<div class="row"><span class="pill info">${d.scanned} scanned</span><span class="pill err">${d.vulnerable} vulnerable</span><span class="pill warn">${d.vulns} vulnerabilities</span></div>`;
          html += d.results.map(r => `<div class="scapkg"><b>${esc(r.name)}</b> <span class="mono" style="color:var(--tx3)">${esc(r.version)}</span> <span class="ars-tag">${esc(r.ecosystem)}</span></div>` +
            r.vulns.map(v => { const url = v.cve && /^CVE-/.test(v.cve) ? 'https://osv.dev/vulnerability/' + v.id : 'https://osv.dev/vulnerability/' + v.id; return `<div class="scavuln"><div class="row" style="margin:0;gap:8px;align-items:center">${sevPill(v)}<a href="${url}" target="_blank" rel="noopener" class="mono" style="color:var(--acc);text-decoration:none">${esc(v.cve || v.id)}</a>${v.fixed ? `<span class="pill ok">fix: ${esc(v.fixed)}</span>` : ''}</div>${v.summary ? `<div class="note" style="margin-top:5px">${esc(v.summary)}</div>` : ''}</div>`; }).join('')).join('');
          out.innerHTML = html;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', scan);
    } },

  { id: 'webscan', grp: 'Scanners', e: '🛡️', live: true, name: 'Website Security Scanner', desc: 'Grade a live site\'s security headers, HTTPS & cookies.',
    tujuan: '<b>What it\'s for:</b> enter a URL and get a graded report of a <b>live website\'s</b> security headers (HSTS, CSP, X-Frame-Options…), HTTPS, redirects, and cookie flags. Like securityheaders.com / Mozilla Observatory. <b>When:</b> hardening or auditing a site. <b>Live:</b> the request is made from this site\'s Cloudflare edge (internal/private addresses are blocked).',
    contoh(root) { $('#in', root).value = 'https://github.com'; },
    body(root) {
      root.innerHTML = `<label class="lbl">Website URL</label><div class="row"><input class="f" id="in" placeholder="https://example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Scan</button></div><div id="out" style="margin-top:14px"></div>`;
      const scan = async () => {
        const out = $('#out', root), btn = $('#scan', root); let u = $('#in', root).value.trim(); if (!u) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Fetching ${esc(u)}…</div>`;
        try {
          const res = await fetch('/api/headers?url=' + encodeURIComponent(u)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Scan failed');
          const gcls = d.score >= 75 ? 'ok' : d.score >= 40 ? 'warn' : 'err';
          const ic = s => s === 'pass' ? '✓' : s === 'warn' ? '!' : '✕';
          let html = `<div class="row" style="align-items:center;gap:14px"><span class="pill ${gcls}" style="font-size:17px;padding:6px 16px">Grade ${d.grade}</span><b class="mono">${d.score}/100</b><span class="pill ${d.https ? 'ok' : 'err'}">${d.https ? 'HTTPS' : 'HTTP only'}</span>${d.redirected ? '<span class="pill info">redirected</span>' : ''}</div><div class="progress" style="margin:10px 0 14px"><i style="width:${d.score}%"></i></div>`;
          html += `<div class="kv"><span class="k">Final URL</span><span class="v">${esc(d.url)}</span></div><div class="kv"><span class="k">Status</span><span class="v">${d.status}</span></div>${d.server ? `<div class="kv"><span class="k">Server</span><span class="v">${esc(d.server)}</span></div>` : ''}${d.poweredBy ? `<div class="kv"><span class="k">X-Powered-By</span><span class="v">${esc(d.poweredBy)}</span></div>` : ''}`;
          html += '<label class="lbl" style="margin-top:14px">Security headers</label>' + d.checks.map(c => `<div class="kv"><span class="k">${ic(c.state)} ${esc(c.name)}</span><span class="v"><span class="pill ${c.state === 'pass' ? 'ok' : c.state === 'warn' ? 'warn' : 'err'}">${c.state === 'pass' ? 'OK' : c.state === 'warn' ? 'Weak' : 'Missing'}</span></span></div>${c.state !== 'pass' ? `<div class="note" style="margin:1px 0 7px">${esc(c.tip)}</div>` : ''}`).join('');
          if (d.cookies && d.cookies.length) html += '<label class="lbl" style="margin-top:14px">Cookies</label>' + d.cookies.map(c => `<div class="kv"><span class="k">${esc(c.name)}</span><span class="v">${c.secure ? '<span class="pill ok">Secure</span> ' : '<span class="pill err">no Secure</span> '}${c.httpOnly ? '<span class="pill ok">HttpOnly</span> ' : '<span class="pill warn">no HttpOnly</span> '}<span class="pill info">SameSite: ${esc(c.sameSite)}</span></span></div>`).join('');
          out.innerHTML = html;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', scan); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') scan(); });
    } },

  { id: 'dnsscan', grp: 'Scanners', e: '🌐', live: true, name: 'DNS & Email Security', desc: 'Look up DNS records + check SPF, DMARC, DNSSEC & CAA.',
    tujuan: '<b>What it\'s for:</b> look up a domain\'s DNS records (A, AAAA, MX, NS, CAA, TXT) and check its <b>email security</b> posture — SPF, DMARC (and policy), DNSSEC, and CAA. <b>When:</b> auditing a domain or debugging email deliverability. <b>Live:</b> resolved via DNS-over-HTTPS from this site\'s Cloudflare edge.',
    contoh(root) { $('#in', root).value = 'github.com'; },
    body(root) {
      root.innerHTML = `<div class="row"><div style="flex:1;min-width:200px"><label class="lbl">Domain</label><input class="f" id="in" placeholder="example.com"></div><div><label class="lbl">DKIM selector (optional)</label><input class="f" id="sel" placeholder="e.g. google, default" style="width:170px"></div></div><div class="row" style="margin-top:10px"><button class="btn acc" id="scan" type="button">Lookup</button></div><div id="out" style="margin-top:14px"></div>`;
      const yn = (ok, good, bad) => `<span class="pill ${ok ? 'ok' : 'err'}">${ok ? '✓ ' + good : '✕ ' + (bad || good)}</span>`;
      const scan = async () => {
        const out = $('#out', root), btn = $('#scan', root); const dom = $('#in', root).value.trim(); if (!dom) return;
        const sel = $('#sel', root).value.trim();
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Resolving ${esc(dom)}…</div>`;
        try {
          const res = await fetch('/api/dns?domain=' + encodeURIComponent(dom) + (sel ? '&selector=' + encodeURIComponent(sel) : '')); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Lookup failed');
          const s = d.summary;
          let html = `<label class="lbl">Email &amp; DNS security</label><div class="row" style="gap:8px">${yn(s.spf, 'SPF', 'no SPF')}${yn(s.dmarc, 'DMARC' + (d.email.dmarcPolicy ? ' (' + d.email.dmarcPolicy + ')' : ''), 'no DMARC')}${d.email.dmarc ? (s.dmarcStrong ? '<span class="pill ok">strong policy</span>' : '<span class="pill warn">weak policy (p=none)</span>') : ''}${yn(s.dnssec, 'DNSSEC', 'no DNSSEC')}${yn(s.caa, 'CAA', 'no CAA')}</div>`;
          const rec = (label, arr) => arr && arr.length ? `<label class="lbl" style="margin-top:14px">${label} <span class="hg-cnt">${arr.length}</span></label>` + arr.map(x => `<div class="out" style="min-height:0;padding:9px 12px;margin-bottom:6px">${esc(x)}</div>`).join('') : '';
          html += rec('A', d.records.A) + rec('AAAA', d.records.AAAA) + rec('MX', d.records.MX) + rec('NS', d.records.NS) + rec('CAA', d.records.CAA) + rec('TXT', d.records.TXT);
          if (sel) html += rec('DKIM (' + esc(sel) + ')', d.email.dkim ? [d.email.dkim] : []);
          out.innerHTML = html;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', scan); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') scan(); });
    } },

  { id: 'dockerlint', grp: 'Scanners', e: '🐳', name: 'Dockerfile Linter', desc: 'Lint a Dockerfile for security & best-practice issues.',
    tujuan: '<b>What it\'s for:</b> check a Dockerfile against common security and best-practice rules (root user, unpinned base image, curl|bash, hardcoded secrets, apt cache, and more). Like a lightweight hadolint. <b>When:</b> before building or shipping an image. Runs 100% on-device.',
    contoh(root) { $('#in', root).value = 'FROM node:latest\nADD https://example.com/app.tar.gz /app\nRUN apt-get update && apt-get install curl\nENV API_KEY=supersecret123\nRUN curl https://get.example.com | bash\nCMD ["node","server.js"]'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Dockerfile</label><textarea id="in" style="min-height:170px" placeholder="FROM ..."></textarea><div id="stat" style="margin-top:12px"></div><div id="out" style="margin-top:6px"></div>`;
      const LINE = [
        { re: /^\s*FROM\s+\S+:latest(\s|$)/i, sev: 'warn', msg: 'Base image uses the `latest` tag — pin a specific version for reproducible builds. (DL3007)' },
        { re: /^\s*FROM\s+[^\s:@]+\s*$/i, sev: 'warn', msg: 'Base image has no tag — pin an explicit version. (DL3006)' },
        { re: /apt-get\s+install(?![^\n]*--no-install-recommends)/i, sev: 'info', msg: 'Add `--no-install-recommends` to apt-get install to keep the image small. (DL3015)' },
        { re: /(^|\s)(ADD)\s+(?!--)(?!https?:)[^\s]+/i, sev: 'info', msg: 'Prefer COPY over ADD unless you need URL download or tar extraction. (DL3020)' },
        { re: /curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh/i, sev: 'high', msg: 'Piping curl into a shell executes unverified remote code. Download, verify, then run. (security)' },
        { re: /wget\s+[^|]*\|\s*(ba)?sh/i, sev: 'high', msg: 'Piping wget into a shell executes unverified remote code. (security)' },
        { re: /(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY)\w*\s*[= ]/i, sev: 'high', msg: 'Possible hardcoded secret in ENV/ARG — use build secrets or runtime env, never bake secrets into layers. (security)' },
        { re: /^\s*RUN\s+sudo\s/i, sev: 'warn', msg: 'Avoid `sudo` inside RUN — it can behave unexpectedly in containers. (DL3004)' },
        { re: /pip\s+install(?![^\n]*--no-cache-dir)/i, sev: 'info', msg: 'Use `pip install --no-cache-dir` to reduce image size. (DL3042)' },
        { re: /^\s*WORKDIR\s+(?!\/|\$)/i, sev: 'info', msg: 'Use an absolute path for WORKDIR. (DL3000)' },
      ];
      const DOC = [
        { test: t => /^\s*(FROM|RUN|CMD|ENTRYPOINT)/im.test(t) && !/^\s*USER\s+/im.test(t), sev: 'high', msg: 'No USER instruction — the container runs as root. Create and switch to a non-root user. (DL3002)' },
        { test: t => /^\s*(FROM)/im.test(t) && !/HEALTHCHECK/i.test(t), sev: 'info', msg: 'No HEALTHCHECK instruction — consider adding one so orchestrators know the container is healthy. (DL3057)' },
        { test: t => /apt-get\s+install/i.test(t) && !/rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(t), sev: 'info', msg: 'After apt-get install, clean the cache (`rm -rf /var/lib/apt/lists/*`) in the same RUN to shrink the image. (DL3009)' },
      ];
      const run = () => {
        const text = $('#in', root).value, out = $('#out', root), stat = $('#stat', root);
        if (!text.trim()) { stat.innerHTML = ''; out.innerHTML = ''; return; }
        const lines = text.split('\n'); const finds = [];
        lines.forEach((l, i) => LINE.forEach(r => { if (r.re.test(l)) finds.push({ sev: r.sev, line: i + 1, msg: r.msg }); }));
        DOC.forEach(r => { if (r.test(text)) finds.push({ sev: r.sev, line: '—', msg: r.msg }); });
        const order = { high: 0, warn: 1, info: 2 }; finds.sort((a, b) => order[a.sev] - order[b.sev] || (a.line === '—' ? 999 : a.line) - (b.line === '—' ? 999 : b.line));
        if (!finds.length) { stat.innerHTML = '<span class="pill ok">✓ No issues found</span>'; out.innerHTML = '<div class="note">Looks clean against the built-in rules. Still review for your own context.</div>'; return; }
        const nH = finds.filter(f => f.sev === 'high').length, nW = finds.filter(f => f.sev === 'warn').length, nI = finds.filter(f => f.sev === 'info').length;
        stat.innerHTML = `${nH ? `<span class="pill err">${nH} high</span> ` : ''}${nW ? `<span class="pill warn">${nW} warning</span> ` : ''}${nI ? `<span class="pill info">${nI} info</span>` : ''}`;
        const pc = s => s === 'high' ? 'err' : s === 'warn' ? 'warn' : 'info';
        out.innerHTML = finds.map(f => `<div class="kv"><span class="k"><span class="pill ${pc(f.sev)}">${f.sev}</span> ${f.line !== '—' ? 'line ' + f.line : 'file'}</span><span class="v" style="text-align:left;max-width:78%">${esc(f.msg)}</span></div>`).join('');
      };
      $('#in', root).addEventListener('input', run);
    } },


  // ================= PHASE 4: MORE SCANNERS (edge) + on-device security =================
  { id: 'tls', grp: 'Scanners', e: '🔏', live: true, name: 'TLS / SSL Certificate', desc: 'Inspect a domain\'s certificates & expiry from CT logs.',
    tujuan: '<b>What it\'s for:</b> inspect a domain\'s TLS/SSL certificates from public Certificate Transparency logs — issuer, validity dates, days until expiry, and the names (SANs) each cert covers. <b>When:</b> checking a cert is valid, not expiring soon, or spotting unexpected certs issued for your domain. <b>Live:</b> queried from this site\'s Cloudflare edge (CertSpotter / crt.sh).',
    contoh(root) { $('#in', root).value = 'github.com'; },
    body(root) {
      root.innerHTML = `<div class="row"><input class="f" id="in" placeholder="example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Inspect</button></div><div id="out" style="margin-top:14px"></div>`;
      const fd = x => { try { return new Date(x).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return x; } };
      const run = async () => {
        const out = $('#out', root), btn = $('#scan', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Querying CT logs…</div>`;
        try { const res = await fetch('/api/tls?domain=' + encodeURIComponent(v)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Lookup failed');
          const days = d.daysLeft, dc = days == null ? 'info' : days < 0 ? 'err' : days < 15 ? 'err' : days < 30 ? 'warn' : 'ok';
          const c0 = d.certs[0] || {};
          let html = `<div class="row"><span class="pill ${dc}">${days == null ? '—' : days < 0 ? 'EXPIRED' : days + ' days left'}</span><span class="pill info">${d.total} certs in CT logs</span></div>`;
          html += `<label class="lbl" style="margin-top:12px">Latest certificate</label><div class="kv"><span class="k">Issuer</span><span class="v">${esc(c0.issuer || '—')}</span></div><div class="kv"><span class="k">Valid from</span><span class="v">${esc(fd(c0.notBefore))}</span></div><div class="kv"><span class="k">Expires</span><span class="v">${esc(fd(c0.notAfter))}</span></div><div class="kv"><span class="k">Covers (SAN)</span><span class="v">${esc((c0.names || []).slice(0, 10).join(', '))}</span></div>`;
          if (d.certs.length > 1) html += `<label class="lbl" style="margin-top:14px">Recent certificates <span class="hg-cnt">${d.certs.length}</span></label>` + d.certs.map(c => `<div class="kv"><span class="k">${esc(c.issuer || '—')}</span><span class="v">exp ${esc(fd(c.notAfter))}</span></div>`).join('');
          out.innerHTML = html;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', run); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    } },

  { id: 'ipinfo', grp: 'Scanners', e: '📍', live: true, name: 'IP Lookup', desc: 'Geolocate an IP/domain + ASN, org & reverse DNS.',
    tujuan: '<b>What it\'s for:</b> look up an IP address (or a domain) — country, city, the owning organization &amp; ASN, and reverse DNS (PTR). <b>When:</b> investigating a suspicious IP from your logs, or checking where a host is. <b>Live:</b> resolved from this site\'s Cloudflare edge.',
    contoh(root) { $('#in', root).value = '8.8.8.8'; },
    body(root) {
      root.innerHTML = `<div class="row"><input class="f" id="in" placeholder="8.8.8.8 or example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Lookup</button></div><div id="out" style="margin-top:14px"></div>`;
      const run = async () => {
        const out = $('#out', root), btn = $('#scan', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Looking up…</div>`;
        try { const res = await fetch('/api/ip?q=' + encodeURIComponent(v)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Lookup failed');
          const row = (k, val) => val ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(val)}</span></div>` : '';
          out.innerHTML = row('IP', d.ip) + row('Resolved from', d.resolvedFrom) + row('Reverse DNS', d.reverseDns) + row('Country', [d.city, d.region, d.country].filter(Boolean).join(', ')) + row('Organization', d.org) + row('ISP', d.isp && d.isp !== d.org ? d.isp : '') + row('ASN', d.asn ? d.asn + (d.asName ? ' · ' + d.asName : '') : '') + row('Coordinates', d.lat != null && d.lon != null ? d.lat + ', ' + d.lon : '') + (!d.country && !d.org ? '<div class="note">Geolocation unavailable for this address; reverse DNS shown above.</div>' : '');
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', run); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    } },

  { id: 'whois', grp: 'Scanners', e: '📇', live: true, name: 'Domain WHOIS', desc: 'Registrar, dates, status & nameservers (via RDAP).',
    tujuan: '<b>What it\'s for:</b> look up a domain\'s registration — registrar, creation / last-updated / expiry dates (with days left), EPP status codes, and nameservers. Uses modern <b>RDAP</b> (WHOIS over HTTPS). <b>When:</b> checking who owns a domain or when it expires. <b>Live:</b> resolved from this site\'s Cloudflare edge.',
    contoh(root) { $('#in', root).value = 'github.com'; },
    body(root) {
      root.innerHTML = `<div class="row"><input class="f" id="in" placeholder="example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Lookup</button></div><div id="out" style="margin-top:14px"></div>`;
      const fd = x => { if (!x) return null; try { return new Date(x).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return x; } };
      const run = async () => {
        const out = $('#out', root), btn = $('#scan', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Querying RDAP…</div>`;
        try { const res = await fetch('/api/whois?domain=' + encodeURIComponent(v)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Lookup failed');
          let days = null; if (d.expires) days = Math.round((new Date(d.expires) - Date.now()) / 86400000);
          const row = (k, val) => val ? `<div class="kv"><span class="k">${k}</span><span class="v">${esc(val)}</span></div>` : '';
          let html = row('Domain', d.domain) + row('Registrar', d.registrar) + row('Registered', fd(d.created)) + row('Updated', fd(d.updated)) + row('Expires', d.expires ? fd(d.expires) + (days != null ? ' (' + days + ' days)' : '') : '');
          if (d.status && d.status.length) html += `<label class="lbl" style="margin-top:12px">Status</label><div class="row">${d.status.map(s => `<span class="ars-tag">${esc(s)}</span>`).join('')}</div>`;
          if (d.nameservers && d.nameservers.length) html += `<label class="lbl" style="margin-top:12px">Nameservers</label>` + d.nameservers.map(n => `<div class="out" style="min-height:0;padding:9px 12px;margin-bottom:6px">${esc(n)}</div>`).join('');
          out.innerHTML = html;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', run); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    } },

  { id: 'cors', grp: 'Scanners', e: '🔀', live: true, name: 'CORS Checker', desc: 'Test a site\'s CORS policy for misconfigurations.',
    tujuan: '<b>What it\'s for:</b> check a URL\'s <b>CORS</b> policy by sending a cross-origin request and inspecting the response — it flags dangerous setups like reflecting any Origin together with credentials. <b>When:</b> auditing an API\'s cross-origin exposure. <b>Live:</b> a single request from this site\'s Cloudflare edge (internal addresses blocked). Passive — no exploitation.',
    contoh(root) { $('#in', root).value = 'https://api.github.com'; },
    body(root) {
      root.innerHTML = `<div class="row"><input class="f" id="in" placeholder="https://api.example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Check</button></div><div id="out" style="margin-top:14px"></div>`;
      const run = async () => {
        const out = $('#out', root), btn = $('#scan', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Testing CORS…</div>`;
        try { const res = await fetch('/api/cors?url=' + encodeURIComponent(v)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Check failed');
          const row = (k, val) => `<div class="kv"><span class="k">${k}</span><span class="v mono">${esc(val || '(not set)')}</span></div>`;
          out.innerHTML = `<div class="row"><span class="pill ${d.state}">${d.state === 'ok' ? 'OK' : d.state === 'warn' ? 'Review' : 'Risk'}</span></div><div class="note" style="margin:8px 0 12px">${esc(d.verdict)}</div><label class="lbl">Response</label>${row('Access-Control-Allow-Origin', d.acao)}${row('Access-Control-Allow-Credentials', d.acac)}${row('Access-Control-Allow-Methods', d.acam)}<div class="note">Test Origin sent: <span class="mono">${esc(d.testOrigin)}</span></div>`;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', run); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    } },

  { id: 'headersview', grp: 'Scanners', e: '📋', live: true, name: 'HTTP Header Viewer', desc: 'Fetch a URL and view all raw response headers.',
    tujuan: '<b>What it\'s for:</b> fetch a URL and see <b>every</b> HTTP response header the server returns (status, server, cache, security, redirects…). <b>When:</b> debugging caching, CDN, redirects, or any header. <b>Live:</b> a single request from this site\'s Cloudflare edge (internal addresses blocked).',
    contoh(root) { $('#in', root).value = 'https://example.com'; },
    body(root) {
      root.innerHTML = `<div class="row"><input class="f" id="in" placeholder="https://example.com" style="flex:1;min-width:220px"><button class="btn acc" id="scan" type="button">Fetch</button></div><div id="out" style="margin-top:14px"></div>`;
      const run = async () => {
        const out = $('#out', root), btn = $('#scan', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Fetching…</div>`;
        try { const res = await fetch('/api/rawheaders?url=' + encodeURIComponent(v)); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'Fetch failed');
          const keys = Object.keys(d.headers).sort();
          out.innerHTML = `<div class="row"><span class="pill ${d.status < 400 ? 'ok' : 'warn'}">HTTP ${d.status}</span><span class="pill info">${keys.length} headers</span></div><label class="lbl" style="margin-top:10px">Response headers</label>` + keys.map(k => `<div class="kv"><span class="k">${esc(k)}</span><span class="v mono">${esc(d.headers[k])}</span></div>`).join('');
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      $('#scan', root).addEventListener('click', run); $('#in', root).addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
    } },

  { id: 'aiexplain', grp: 'Scanners', e: '🤖', live: true, name: 'AI Security Explainer', desc: 'Explain a CVE, header, or finding in plain English (AI).',
    tujuan: '<b>What it\'s for:</b> paste a CVE ID, a security header, an error, or a scan finding and get a plain-English explanation — what it is, the risk, and how to fix it. Powered by <b>Cloudflare Workers AI</b> (Llama). <b>When:</b> you hit a finding you don\'t fully understand. <b>Live:</b> your prompt is sent to this site\'s Cloudflare edge to run the model. Defensive only — it won\'t write exploits.',
    body(root) {
      root.innerHTML = `<label class="lbl">Ask about a CVE, header, or security concept</label><textarea id="in" style="min-height:90px" placeholder="e.g. Explain CVE-2021-44228 (Log4Shell)"></textarea>
        <div class="row" style="margin-top:8px">${['Explain CVE-2021-44228 (Log4Shell)', 'What is a Content-Security-Policy?', 'Why is SameSite cookie important?'].map(q => `<button class="btn sm" data-q="${esc(q)}" type="button">${esc(q.length > 34 ? q.slice(0, 32) + '…' : q)}</button>`).join('')}</div>
        <div class="row" style="margin-top:8px"><button class="btn acc" id="ask" type="button">Explain</button></div><div id="out" style="margin-top:12px"></div>`;
      const fmt = s => esc(s).replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
      const run = async () => {
        const out = $('#out', root), btn = $('#ask', root), v = $('#in', root).value.trim(); if (!v) return;
        btn.classList.add('loading'); prog.start(true); out.innerHTML = `<div class="proc"><span class="spinner"></span>Thinking…</div>`;
        try { const res = await fetch('/api/ai', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ prompt: v }) }); const d = await res.json(); prog.done(); btn.classList.remove('loading');
          if (!res.ok) return setErr(out, d.error || 'AI failed');
          out.innerHTML = `<div class="out" style="white-space:pre-wrap;line-height:1.7">${fmt(d.text || '(no response)')}</div><div class="note">AI-generated · verify important details. Powered by Cloudflare Workers AI.</div>`;
        } catch (e) { prog.done(); btn.classList.remove('loading'); setErr(out, 'Network error — ' + e.message); }
      };
      root.querySelectorAll('[data-q]').forEach(b => b.addEventListener('click', () => { $('#in', root).value = b.dataset.q; run(); }));
      $('#ask', root).addEventListener('click', run);
    } },

  { id: 'envcheck', grp: 'Security', e: '🗝️', name: '.env Auditor', desc: 'Audit a .env file for secrets, weak values & mistakes.',
    tujuan: '<b>What it\'s for:</b> paste a <span class="mono">.env</span> file to catch secrets that should not be committed, weak or placeholder values, duplicate keys, and quoting mistakes. <b>When:</b> before committing config or sharing a project. Runs 100% on-device.',
    contoh(root) { $('#in', root).value = 'NODE_ENV=production\nDB_PASSWORD=123456\nAPI_KEY=sk_live_' + 'abcdef1234567890abcdef\nDEBUG=true\nSECRET=\nDB_PASSWORD=admin\nJWT_SECRET=changeme'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">.env contents</label><textarea id="in" style="min-height:160px" placeholder="KEY=value"></textarea><div id="stat" style="margin-top:12px"></div><div id="out" style="margin-top:6px"></div>`;
      const WEAK = ['123456', 'password', 'admin', 'changeme', 'secret', 'root', 'test', '12345678', 'qwerty', 'example', 'your_', 'xxx', 'todo'];
      const SECRETISH = /(pass|pwd|secret|token|api[_-]?key|apikey|private|credential|access[_-]?key)/i;
      const run = () => {
        const text = $('#in', root).value, out = $('#out', root), stat = $('#stat', root);
        if (!text.trim()) { stat.innerHTML = ''; out.innerHTML = ''; return; }
        const finds = []; const seen = {};
        text.split('\n').forEach((l, i) => {
          const line = l.trim(); if (!line || line.startsWith('#')) return;
          const m = line.match(/^([A-Za-z0-9_.]+)\s*=\s*(.*)$/); if (!m) { finds.push({ sev: 'warn', line: i + 1, msg: 'Line is not a valid KEY=value pair.' }); return; }
          const k = m[1], val = m[2].replace(/^["']|["']$/g, '').trim();
          if (seen[k]) finds.push({ sev: 'warn', line: i + 1, msg: `Duplicate key "${k}" (also on line ${seen[k]}).` }); else seen[k] = i + 1;
          if (SECRETISH.test(k) && val) finds.push({ sev: 'high', line: i + 1, msg: `"${k}" holds a secret — never commit this to git (use a secret manager / .gitignore).` });
          if (SECRETISH.test(k) && !val) finds.push({ sev: 'info', line: i + 1, msg: `"${k}" is empty — a placeholder to fill at deploy time.` });
          if (val && WEAK.some(w => val.toLowerCase().includes(w))) finds.push({ sev: 'high', line: i + 1, msg: `"${k}" looks like a weak/placeholder value ("${val.slice(0, 20)}") — replace before production.` });
          if (/\s/.test(m[2].trim()) && !/^["']/.test(m[2].trim())) finds.push({ sev: 'info', line: i + 1, msg: `"${k}" value contains spaces but is not quoted — may be truncated.` });
        });
        const order = { high: 0, warn: 1, info: 2 }; finds.sort((a, b) => order[a.sev] - order[b.sev] || a.line - b.line);
        if (!finds.length) { stat.innerHTML = '<span class="pill ok">✓ No issues found</span>'; out.innerHTML = '<div class="note">Clean against the built-in checks. Ensure .env is in .gitignore.</div>'; return; }
        const nH = finds.filter(f => f.sev === 'high').length, nW = finds.filter(f => f.sev === 'warn').length, nI = finds.filter(f => f.sev === 'info').length;
        stat.innerHTML = `${nH ? `<span class="pill err">${nH} high</span> ` : ''}${nW ? `<span class="pill warn">${nW} warning</span> ` : ''}${nI ? `<span class="pill info">${nI} info</span>` : ''}`;
        const pc = s => s === 'high' ? 'err' : s === 'warn' ? 'warn' : 'info';
        out.innerHTML = finds.map(f => `<div class="kv"><span class="k"><span class="pill ${pc(f.sev)}">${f.sev}</span> line ${f.line}</span><span class="v" style="text-align:left;max-width:78%">${esc(f.msg)}</span></div>`).join('');
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'sqlcheck', grp: 'Security', e: '🛢️', name: 'SQL Safety Linter', desc: 'Flag SQL-injection-prone patterns in your own queries.',
    tujuan: '<b>What it\'s for:</b> review <b>your own</b> SQL / query-building code for patterns that lead to SQL injection — string concatenation of user input, missing parameterization, dangerous functions, and risky clauses. <b>When:</b> code review before shipping. Educational &amp; defensive; runs 100% on-device. (This does not attack anything.)',
    contoh(root) { $('#in', root).value = `query = "SELECT * FROM users WHERE name = '" + userName + "' AND pass = '" + pass + "'";\ndb.exec("DELETE FROM logs");\nEXEC('xp_cmdshell');`; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">SQL or query-building code</label><textarea id="in" style="min-height:150px" placeholder="paste SQL or code that builds SQL"></textarea><div id="stat" style="margin-top:12px"></div><div id="out" style="margin-top:6px"></div>`;
      const RULES = [
        { re: /["'`]\s*\+\s*\w|\w\s*\+\s*["'`]/, sev: 'high', msg: 'String concatenation to build SQL with a variable — the classic SQL-injection vector. Use parameterized queries / prepared statements.' },
        { re: /\$\{[^}]+\}|%s|%d|\bf["']/i, sev: 'high', msg: 'Interpolating a variable directly into a query string. Bind parameters instead of formatting.' },
        { re: /\bxp_cmdshell\b/i, sev: 'high', msg: 'xp_cmdshell runs OS commands from SQL — a major RCE risk. Disable it.' },
        { re: /\bEXEC(UTE)?\s*\(/i, sev: 'warn', msg: 'Dynamic EXEC() of a string — if it includes user input, it is injectable. Prefer parameterized calls.' },
        { re: /\bOR\s+1\s*=\s*1\b/i, sev: 'warn', msg: 'Tautology "OR 1=1" present — a common injection payload / logic bug.' },
        { re: /\b(UPDATE|DELETE)\b(?![^;]*\bWHERE\b)/i, sev: 'warn', msg: 'UPDATE/DELETE without a WHERE clause affects every row.' },
        { re: /--|\/\*/, sev: 'info', msg: 'SQL comment present — make sure it is not from concatenated user input (comment-based injection).' },
        { re: /SELECT\s+\*/i, sev: 'info', msg: 'SELECT * — prefer explicit columns (avoids leaking columns & is faster).' },
      ];
      const run = () => {
        const text = $('#in', root).value, out = $('#out', root), stat = $('#stat', root);
        if (!text.trim()) { stat.innerHTML = ''; out.innerHTML = ''; return; }
        const finds = [];
        text.split('\n').forEach((l, i) => RULES.forEach(r => { if (r.re.test(l)) finds.push({ sev: r.sev, line: i + 1, msg: r.msg }); }));
        const order = { high: 0, warn: 1, info: 2 }; finds.sort((a, b) => order[a.sev] - order[b.sev] || a.line - b.line);
        if (!finds.length) { stat.innerHTML = '<span class="pill ok">✓ No risky patterns found</span>'; out.innerHTML = '<div class="note">Nothing matched the built-in rules. Still prefer parameterized queries everywhere.</div>'; return; }
        const nH = finds.filter(f => f.sev === 'high').length, nW = finds.filter(f => f.sev === 'warn').length, nI = finds.filter(f => f.sev === 'info').length;
        stat.innerHTML = `${nH ? `<span class="pill err">${nH} high</span> ` : ''}${nW ? `<span class="pill warn">${nW} warning</span> ` : ''}${nI ? `<span class="pill info">${nI} info</span>` : ''}`;
        const pc = s => s === 'high' ? 'err' : s === 'warn' ? 'warn' : 'info';
        out.innerHTML = finds.map(f => `<div class="kv"><span class="k"><span class="pill ${pc(f.sev)}">${f.sev}</span> line ${f.line}</span><span class="v" style="text-align:left;max-width:78%">${esc(f.msg)}</span></div>`).join('');
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'htmlcheck', grp: 'Security', e: '📑', name: 'HTML Security Checker', desc: 'Scan HTML for XSS-prone & accessibility issues.',
    tujuan: '<b>What it\'s for:</b> scan an HTML snippet for security and quality issues — inline event handlers &amp; <span class="mono">javascript:</span> URLs (XSS), <span class="mono">target="_blank"</span> without <span class="mono">rel="noopener"</span> (tabnabbing), missing alt/lang, and inline eval. <b>When:</b> reviewing templates or user-generated HTML. Runs 100% on-device.',
    contoh(root) { $('#in', root).value = '<a href="javascript:alert(1)" target="_blank">click</a>\n<img src="x.png">\n<button onclick="run()">go</button>\n<script>eval(data)</scr' + 'ipt>'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">HTML</label><textarea id="in" style="min-height:150px" placeholder="<html>…"></textarea><div id="stat" style="margin-top:12px"></div><div id="out" style="margin-top:6px"></div>`;
      const LINE = [
        { re: /\son\w+\s*=/i, sev: 'high', msg: 'Inline event handler (onclick/onerror/…) — an XSS sink. Move to addEventListener and sanitize data.' },
        { re: /(href|src)\s*=\s*["']?\s*javascript:/i, sev: 'high', msg: 'javascript: URL — executes script, a classic XSS vector. Remove it.' },
        { re: /\beval\s*\(|new\s+Function\s*\(|document\.write\s*\(|\.innerHTML\s*=/i, sev: 'warn', msg: 'Dynamic code / HTML injection sink (eval / Function / document.write / innerHTML). Validate & escape input.' },
        { re: /target\s*=\s*["']_blank["'](?![^>]*rel\s*=\s*["'][^"']*noopener)/i, sev: 'warn', msg: 'target="_blank" without rel="noopener" — enables reverse-tabnabbing. Add rel="noopener noreferrer".' },
        { re: /<img\b(?![^>]*\balt\s*=)/i, sev: 'info', msg: '<img> without alt — accessibility issue (and can hide injected content).' },
      ];
      const DOC = [
        { test: t => /<html\b(?![^>]*\blang\s*=)/i.test(t), sev: 'info', msg: '<html> without a lang attribute — set it (e.g. lang="en").' },
        { test: t => /<head\b/i.test(t) && !/name\s*=\s*["']viewport["']/i.test(t), sev: 'info', msg: 'No viewport meta — add it for responsive/mobile rendering.' },
      ];
      const run = () => {
        const text = $('#in', root).value, out = $('#out', root), stat = $('#stat', root);
        if (!text.trim()) { stat.innerHTML = ''; out.innerHTML = ''; return; }
        const finds = [];
        text.split('\n').forEach((l, i) => LINE.forEach(r => { if (r.re.test(l)) finds.push({ sev: r.sev, line: i + 1, msg: r.msg }); }));
        DOC.forEach(r => { if (r.test(text)) finds.push({ sev: r.sev, line: '—', msg: r.msg }); });
        const order = { high: 0, warn: 1, info: 2 }; finds.sort((a, b) => order[a.sev] - order[b.sev] || (a.line === '—' ? 999 : a.line) - (b.line === '—' ? 999 : b.line));
        if (!finds.length) { stat.innerHTML = '<span class="pill ok">✓ No issues found</span>'; out.innerHTML = '<div class="note">Nothing matched the built-in rules.</div>'; return; }
        const nH = finds.filter(f => f.sev === 'high').length, nW = finds.filter(f => f.sev === 'warn').length, nI = finds.filter(f => f.sev === 'info').length;
        stat.innerHTML = `${nH ? `<span class="pill err">${nH} high</span> ` : ''}${nW ? `<span class="pill warn">${nW} warning</span> ` : ''}${nI ? `<span class="pill info">${nI} info</span>` : ''}`;
        const pc = s => s === 'high' ? 'err' : s === 'warn' ? 'warn' : 'info';
        out.innerHTML = finds.map(f => `<div class="kv"><span class="k"><span class="pill ${pc(f.sev)}">${f.sev}</span> ${f.line !== '—' ? 'line ' + f.line : 'doc'}</span><span class="v" style="text-align:left;max-width:78%">${esc(f.msg)}</span></div>`).join('');
      };
      $('#in', root).addEventListener('input', run);
    } },

];

const GROUPS = ['Scanners', 'Security', 'Encode / Decode', 'Format & Data', 'Generator', 'Converters'];
const HOME_TITLE = 'DevSec Toolbox — Developer & Security Tools Online (100% in the Browser)';
const HOME_DESC = 'A collection of free developer & security tools that run 100% in the browser: JWT decoder, AES encryption, SHA & MD5 hashing, HMAC, JSON, regex, QR, unit conversion, and more. No server, no data sent anywhere.';

// ================= ROUTES (path-based, SEO-friendly) =================
// Each tool has its own URL: <BASE><id>/ (e.g. /devsec/jwt/). Clicking the menu = in-page
// navigation via the History API (fast, no reload); direct/crawler access = a real static page.
const nav = $('#nav');
const urlFor = id => id === 'home' ? BASE : BASE + id + '/';
function tid(t) { return `<a class="nlink" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span> ${t.name}</a>`; }
let navFilter = '';
const openGroups = new Set();
function navClick(e) { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return; e.preventDefault(); go(e.currentTarget.dataset.id, true); document.body.classList.remove('nav-open'); }
// Collapsible category sidebar: compact on the home page (all collapsed), open on a tool page / while searching.
function buildNav(filter = '') {
  navFilter = filter;
  const f = filter.toLowerCase().trim();
  const activeGroup = (TOOLS.find(t => t.id === current()) || {}).grp;
  let html = `<a class="nlink navhome" data-id="home" href="${BASE}"><span class="e">🏠</span> Home</a>`;
  for (const g of GROUPS) {
    const arr = TOOLS.filter(t => t.grp === g && (!f || (t.name + ' ' + t.id + ' ' + t.desc).toLowerCase().includes(f)));
    if (!arr.length) continue;
    const isOpen = f ? true : (g === activeGroup || openGroups.has(SLUG[g]));
    html += `<button type="button" class="grp${isOpen ? ' open' : ''}" data-g="${SLUG[g]}" aria-expanded="${isOpen}"><span class="gdot" data-grp="${SLUG[g]}"></span><span class="grp-name">${g}</span><span class="grp-cnt">${arr.length}</span><svg class="grp-chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></button><div class="grp-items${isOpen ? ' open' : ''}" data-g="${SLUG[g]}">${arr.map(tid).join('')}</div>`;
  }
  if (!f || 'devsecops arsenal directory catalogue'.includes(f)) html += `<a class="nlink navhome" data-id="arsenal" href="${urlFor('arsenal')}" style="margin-top:8px"><span class="e">📚</span> DevSecOps Arsenal</a>`;
  nav.innerHTML = html;
  nav.querySelectorAll('a.nlink').forEach(a => a.addEventListener('click', navClick));
  nav.querySelectorAll('button.grp').forEach(b => b.addEventListener('click', () => { const items = nav.querySelector(`.grp-items[data-g="${b.dataset.g}"]`); const nowOpen = b.classList.toggle('open'); b.setAttribute('aria-expanded', String(nowOpen)); if (items) items.classList.toggle('open', nowOpen); nowOpen ? openGroups.add(b.dataset.g) : openGroups.delete(b.dataset.g); }));
  markActive();
}
function markActive() {
  const id = current();
  nav.querySelectorAll('.nlink').forEach(a => a.classList.toggle('on', a.dataset.id === id));
  const ag = (TOOLS.find(t => t.id === id) || {}).grp;
  if (ag && !navFilter) { const slug = SLUG[ag], b = nav.querySelector(`button.grp[data-g="${slug}"]`), items = nav.querySelector(`.grp-items[data-g="${slug}"]`); if (b && items && !b.classList.contains('open')) { b.classList.add('open'); b.setAttribute('aria-expanded', 'true'); items.classList.add('open'); openGroups.add(slug); } }
}
function current() {
  let p = decodeURIComponent(location.pathname);
  if (p.startsWith(BASE)) p = p.slice(BASE.length);
  p = p.replace(/index\.html?$/i, '').replace(/^\/+|\/+$/g, '');
  const id = p.split('/')[0];
  if (!id) return 'home';
  if (id === 'arsenal') return 'arsenal';
  if (TOOLS.some(t => t.id === id)) return id;
  const dt = document.body.dataset.tool;
  if (dt === 'arsenal') return 'arsenal';
  return dt && TOOLS.some(t => t.id === dt) ? dt : 'home';
}
function setMeta(title, desc) { document.title = title; const md = document.querySelector('meta[name="description"]'); if (md && desc) md.setAttribute('content', desc); }
function setPriv(live) {
  const p = document.querySelector('.topbar .priv');
  if (p) { p.classList.toggle('live', !!live); p.innerHTML = live ? '<svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 10-12h-7z"/></svg> Live · edge' : '<svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg> on-device'; }
  const sf = document.querySelector('.side-foot');
  if (sf) sf.innerHTML = live ? "⚡ <b>Live scanner.</b> Your query is sent to this site's Cloudflare edge to run (never stored)." : "🔒 <b>100% in your browser.</b> No data is sent to any server.";
}

const SLUG = { 'Scanners': 'scanners', 'Security': 'keamanan', 'Encode / Decode': 'encode', 'Format & Data': 'format', 'Generator': 'generator', 'Converters': 'konversi' };
const card = t => `<a class="hcard" data-grp="${SLUG[t.grp]}" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span><span class="hc-t"><b>${esc(t.name)}${t.live ? '<span class="hc-live">Live</span>' : ''}</b><span class="hc-d">${esc(t.desc)}</span></span><span class="hc-go">→</span></a>`;
function renderHome() {
  runCleanup();
  const root = $('#tool');
  $('#ttl').textContent = 'Home'; $('#desc').textContent = ''; setPriv(false);
  const counts = Object.fromEntries(GROUPS.map(g => [g, TOOLS.filter(t => t.grp === g).length]));
  const gdot = g => `<span class="gdot" data-grp="${SLUG[g]}"></span>`;
  root.innerHTML = `<div class="home-hero">
      <div class="home-eyebrow">🧰 ${TOOLS.length} tools · 100% in-browser · free</div>
      <h2>Developer &amp; security tools <span class="g">that just work</span> — right in your browser.</h2>
      <p>From decoding JWTs, AES encryption, hashing &amp; HMAC, to QR, regex, conversion &amp; SEO — everything runs <b>inside your browser</b>, with no server &amp; no data sent. Free, for everyone.</p>
      <div class="home-search"><svg class="hs-ic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.2-4.2"/></svg><input id="hsearch" type="text" placeholder="Search tools… e.g. jwt, hash, qr, color, csv"><kbd>/</kbd></div>
      <div class="home-badges"><span class="hb">🔒 <b>On-device</b></span><span class="hb">⚡ <b>Instant</b></span><span class="hb">✅ <b>Tested</b></span><span class="hb">🆓 <b>No ads</b></span></div>
      <div class="home-stats" id="hstats"></div>
    </div>
    <div class="home-filter" id="hfilter"><button class="chip on" data-g="all" type="button">All <span class="cnt">${TOOLS.length}</span></button>${GROUPS.map(g => `<button class="chip" data-g="${esc(g)}" type="button">${esc(g)} <span class="cnt">${counts[g]}</span></button>`).join('')}</div>
    <div id="hgrid"></div>
    <div class="home-foot">Built by <a href="https://ksatriabintangsamudra.my.id">Ksatria Bintang Samudra</a> · <a href="https://github.com/Kstriabintang/devsec" rel="noopener">source code</a> · every tool runs locally in your browser.</div>`;
  let group = 'all', query = '';
  const grid = $('#hgrid', root);
  const wire = () => grid.querySelectorAll('.hcard').forEach(a => a.addEventListener('click', e => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return; e.preventDefault(); go(a.dataset.id, true); }));
  const render = () => {
    const q = query.toLowerCase().trim();
    if (group === 'all' && !q) {
      grid.innerHTML = GROUPS.map(g => `<div class="home-grp">${gdot(g)}${esc(g)} <span class="hg-cnt">${counts[g]}</span></div><div class="home-grid">${TOOLS.filter(t => t.grp === g).map(card).join('')}</div>`).join('');
    } else {
      const arr = TOOLS.filter(t => (group === 'all' || t.grp === group) && (!q || (t.name + ' ' + t.id + ' ' + t.desc + ' ' + t.grp).toLowerCase().includes(q)));
      grid.innerHTML = `<div class="home-grp">${arr.length} tools${q ? ` for “${esc(query.trim())}”` : ''}</div>` + (arr.length ? `<div class="home-grid">${arr.map(card).join('')}</div>` : `<div class="empty-note">😕 No tools matched. Try a different keyword.</div>`);
    }
    wire();
  };
  $('#hfilter', root).addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; group = b.dataset.g; [...$('#hfilter', root).children].forEach(c => c.classList.toggle('on', c === b)); render(); });
  $('#hsearch', root).addEventListener('input', e => { query = e.target.value; render(); });
  render();
  fetch('/api/stats').then(r => r.json()).then(d => { const s = (d && d.stats) || {}; const he = $('#hstats'); const n = x => (x || 0).toLocaleString('en-US'); if (he && (s.packages_scanned || s.sites_scanned)) he.innerHTML = `<span class="hs-dot"></span>Live edge totals · <b>${n(s.packages_scanned)}</b> dependencies scanned · <b>${n(s.vulns_found)}</b> vulnerabilities found · <b>${n(s.sites_scanned)}</b> sites checked`; }).catch(() => {});
  setMeta(HOME_TITLE, HOME_DESC);
  markActive(); const m = $('.main'); if (m) m.scrollTop = 0;
}

// ---------- DevSecOps Arsenal (curated directory, lazy-loaded) ----------
let _arsenal;
function loadArsenal() { return _arsenal || (_arsenal = import(new URL('arsenal.js?v11', import.meta.url).href)); }
async function renderArsenal() {
  runCleanup();
  $('#ttl').textContent = 'DevSecOps Arsenal'; $('#desc').textContent = ''; setPriv(false);
  const root = $('#tool');
  root.innerHTML = `<div class="home-hero" style="padding-bottom:4px">
      <div class="home-eyebrow">📚 Curated · open-source · from awesome-devsecops</div>
      <h2>The DevSecOps <span class="g">Arsenal</span>.</h2>
      <p class="arsenal-intro">A comprehensive directory of <b id="acount">270+</b> open-source DevSecOps tools, curated from the community <span class="mono">awesome-devsecops</span> lists. These are external tools — the badge on each card shows <b>how it runs</b>, so it is honest about what runs on your machine vs in the browser. Only <span class="ars-run" data-r="Browser">Browser</span>-tagged tools run in the browser like the DevSec Toolbox itself.</p>
      <div class="ars-legend"><span class="ars-run" data-r="CLI">CLI</span> command line · <span class="ars-run" data-r="Server">Server</span> self-hosted · <span class="ars-run" data-r="SaaS">SaaS</span> hosted product · <span class="ars-run" data-r="GUI">GUI</span> desktop app · <span class="ars-run" data-r="Practice">Practice</span> labs · <span class="ars-run" data-r="Browser">Browser</span> in-browser</div>
      <div class="home-search"><svg class="hs-ic" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.2-4.2"/></svg><input id="asearch" type="text" placeholder="Search the arsenal… e.g. terraform, sbom, kubernetes"></div>
    </div>
    <div class="home-filter" id="afilter"></div>
    <div id="agrid"><div class="proc"><span class="spinner"></span>Loading the curated catalogue…</div></div>
    <div class="home-foot">Curated from <a href="https://github.com/devsecops/awesome-devsecops" rel="noopener">awesome-devsecops</a> &amp; related lists · star counts are approximate · these tools link out to their own repos.</div>`;
  setMeta('DevSecOps Arsenal — Curated DevSecOps Tools | DevSec Toolbox', 'A curated directory of the best open-source DevSecOps tools: SAST, DAST, SCA, secrets, containers, IaC, cloud & supply chain.');
  markActive(); const mm = $('.main'); if (mm) mm.scrollTop = 0;
  let mod; try { mod = await loadArsenal(); } catch (e) { const g = $('#agrid'); if (g) g.innerHTML = '<div class="empty-note">Failed to load the catalogue.</div>'; return; }
  if (current() !== 'arsenal') return; // user navigated away while loading
  const { ARSENAL, ARSENAL_CATS } = mod;
  const ac = $('#acount'); if (ac) ac.textContent = ARSENAL.length;
  const fmtStars = n => !n ? '' : n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1).replace(/\.0$/, '') + 'k' : String(n);
  let cat = 'all', q = '';
  const fil = $('#afilter'), grid = $('#agrid');
  fil.innerHTML = `<button class="chip on" data-c="all" type="button">All <span class="cnt">${ARSENAL.length}</span></button>` + ARSENAL_CATS.map(c => `<button class="chip" data-c="${esc(c)}" type="button">${esc(c)} <span class="cnt">${ARSENAL.filter(a => a.cat === c).length}</span></button>`).join('');
  const acard = a => `<a class="ars-card" href="${esc(a.url)}" target="_blank" rel="noopener"><div class="ars-top"><b>${esc(a.name)}</b><span class="ars-run" data-r="${esc(a.run)}">${esc(a.run)}</span>${a.stars ? `<span class="ars-star">★ ${fmtStars(a.stars)}</span>` : ''}</div>${a.desc ? `<div class="ars-d">${esc(a.desc)}</div>` : ''}<div class="ars-tags"><span class="ars-tag">${esc(a.cat)}</span></div></a>`;
  const render = () => {
    const ql = q.toLowerCase().trim();
    const arr = ARSENAL.filter(a => (cat === 'all' || a.cat === cat) && (!ql || (a.name + ' ' + a.desc + ' ' + a.cat + ' ' + (a.tags || []).join(' ')).toLowerCase().includes(ql)));
    grid.innerHTML = arr.length ? `<div class="home-grid">${arr.map(acard).join('')}</div>` : `<div class="empty-note">😕 No tools matched. Try another keyword.</div>`;
  };
  fil.addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; cat = b.dataset.c; [...fil.children].forEach(c => c.classList.toggle('on', c === b)); render(); });
  $('#asearch').addEventListener('input', e => { q = e.target.value; render(); });
  render();
}

function open(id) {
  runCleanup();
  if (id === 'home') return renderHome();
  if (id === 'arsenal') return renderArsenal();
  const t = TOOLS.find(x => x.id === id) || TOOLS[0];
  $('#ttl').textContent = t.name; $('#desc').textContent = t.desc; setPriv(t.live);
  const root = $('#tool'); root.innerHTML = '';
  const pb = el('div', 'purpose'); pb.innerHTML = `<span class="pi">${t.e}</span><div class="pt">${t.tujuan || esc(t.desc)}${t.contoh ? '<div class="ex"><button type="button" id="_ex">▶ Try example</button></div>' : ''}</div>`;
  root.appendChild(pb);
  const bodyWrap = el('div'); root.appendChild(bodyWrap); t.body(bodyWrap);
  if (t.contoh) $('#_ex', pb).addEventListener('click', () => t.contoh(bodyWrap));
  setMeta(t.name + ' — DevSec Toolbox', t.desc);
  markActive(); const m = $('.main'); if (m) m.scrollTop = 0;
}

function go(id, push) { if (push) { const u = urlFor(id); if (location.pathname !== u) { history.pushState({ id }, '', u); prog.pulse(); } } open(id); }
addEventListener('popstate', () => open(current()));
$('#search').addEventListener('input', e => buildNav(e.target.value));
$('#menutgl').addEventListener('click', () => document.body.classList.toggle('nav-open'));
// press "/" to focus search (focus the home search if present, otherwise the sidebar)
addEventListener('keydown', e => { if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '')) { e.preventDefault(); (document.getElementById('hsearch') || $('#search')).focus(); } });
buildNav(); open(current());

window.__DS = { tools: TOOLS.map(t => t.id), groups: GROUPS, get active() { return current(); }, open(id) { go(id, true); } };
