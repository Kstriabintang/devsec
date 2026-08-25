// DevSec Toolbox — alat developer & keamanan, 100% di browser (tanpa jaringan).
const $ = (s, r = document) => r.querySelector(s);
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = new TextEncoder();

function toast(msg = 'Tersalin ✓') { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('on'), 1400); }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast()).catch(() => toast('Gagal menyalin')); }
// tombol salin pada elemen .out
function withCopy(outEl, getText) {
  const b = el('button', 'copy', 'Salin'); b.type = 'button';
  b.addEventListener('click', () => copy(typeof getText === 'function' ? getText() : outEl.innerText));
  outEl.appendChild(b); return outEl;
}

// ---------- util kripto ----------
async function sha(algo, str) {
  const buf = await crypto.subtle.digest(algo, enc.encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hmacSha256(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
// MD5 ringkas (SubtleCrypto tak menyediakan MD5)
function md5(str) {
  function rl(n, s) { return (n << s) | (n >>> (32 - s)); }
  function au(x, y) { const l = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xFFFF); }
  function cmn(q, a, b, x, s, t) { return au(rl(au(au(a, q), au(x, t)), s), b); }
  const FF = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t);
  const GG = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t);
  const HH = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t);
  const II = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t);
  function tb(s) { const b = unescape(encodeURIComponent(s)); const n = []; for (let i = 0; i < b.length * 8; i += 8) n[i >> 5] |= (b.charCodeAt(i / 8) & 0xFF) << (i % 32); return n; }
  function bh(n) { let s = ''; for (let i = 0; i < n.length * 4; i++) s += ((n[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF).toString(16) + ((n[i >> 2] >> ((i % 4) * 8)) & 0xF).toString(16); return s; }
  const x = tb(str), len = unescape(encodeURIComponent(str)).length * 8;
  x[len >> 5] |= 0x80 << (len % 32); x[(((len + 64) >>> 9) << 4) + 14] = len;
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < x.length; i += 16) {
    const oa = a, ob = b, oc = c, od = d;
    a = FF(a, b, c, d, x[i], 7, -680876936); d = FF(d, a, b, c, x[i + 1], 12, -389564586); c = FF(c, d, a, b, x[i + 2], 17, 606105819); b = FF(b, c, d, a, x[i + 3], 22, -1044525330);
    a = FF(a, b, c, d, x[i + 4], 7, -176418897); d = FF(d, a, b, c, x[i + 5], 12, 1200080426); c = FF(c, d, a, b, x[i + 6], 17, -1473231341); b = FF(b, c, d, a, x[i + 7], 22, -45705983);
    a = FF(a, b, c, d, x[i + 8], 7, 1770035416); d = FF(d, a, b, c, x[i + 9], 12, -1958414417); c = FF(c, d, a, b, x[i + 10], 17, -42063); b = FF(b, c, d, a, x[i + 11], 22, -1990404162);
    a = FF(a, b, c, d, x[i + 12], 7, 1804603682); d = FF(d, a, b, c, x[i + 13], 12, -40341101); c = FF(c, d, a, b, x[i + 14], 17, -1502002290); b = FF(b, c, d, a, x[i + 15], 22, 1236535329);
    a = GG(a, b, c, d, x[i + 1], 5, -165796510); d = GG(d, a, b, c, x[i + 6], 9, -1069501632); c = GG(c, d, a, b, x[i + 11], 14, 643717713); b = GG(b, c, d, a, x[i], 20, -373897302);
    a = GG(a, b, c, d, x[i + 5], 5, -701558691); d = GG(d, a, b, c, x[i + 10], 9, 38016083); c = GG(c, d, a, b, x[i + 15], 14, -660478335); b = GG(b, c, d, a, x[i + 4], 20, -405537848);
    a = GG(a, b, c, d, x[i + 9], 5, 568446438); d = GG(d, a, b, c, x[i + 14], 9, -1019803690); c = GG(c, d, a, b, x[i + 3], 14, -187363961); b = GG(b, c, d, a, x[i + 8], 20, 1163531501);
    a = GG(a, b, c, d, x[i + 13], 5, -1444681467); d = GG(d, a, b, c, x[i + 2], 9, -51403784); c = GG(c, d, a, b, x[i + 7], 14, 1735328473); b = GG(b, c, d, a, x[i + 12], 20, -1926607734);
    a = HH(a, b, c, d, x[i + 5], 4, -378558); d = HH(d, a, b, c, x[i + 8], 11, -2022574463); c = HH(c, d, a, b, x[i + 11], 16, 1839030562); b = HH(b, c, d, a, x[i + 14], 23, -35309556);
    a = HH(a, b, c, d, x[i + 1], 4, -1530992060); d = HH(d, a, b, c, x[i + 4], 11, 1272893353); c = HH(c, d, a, b, x[i + 7], 16, -155497632); b = HH(b, c, d, a, x[i + 10], 23, -1094730640);
    a = HH(a, b, c, d, x[i + 13], 4, 681279174); d = HH(d, a, b, c, x[i], 11, -358537222); c = HH(c, d, a, b, x[i + 3], 16, -722521979); b = HH(b, c, d, a, x[i + 6], 23, 76029189);
    a = HH(a, b, c, d, x[i + 9], 4, -640364487); d = HH(d, a, b, c, x[i + 12], 11, -421815835); c = HH(c, d, a, b, x[i + 15], 16, 530742520); b = HH(b, c, d, a, x[i + 2], 23, -995338651);
    a = II(a, b, c, d, x[i], 6, -198630844); d = II(d, a, b, c, x[i + 7], 10, 1126891415); c = II(c, d, a, b, x[i + 14], 15, -1416354905); b = II(b, c, d, a, x[i + 5], 21, -57434055);
    a = II(a, b, c, d, x[i + 12], 6, 1700485571); d = II(d, a, b, c, x[i + 3], 10, -1894986606); c = II(c, d, a, b, x[i + 10], 15, -1051523); b = II(b, c, d, a, x[i + 1], 21, -2054922799);
    a = II(a, b, c, d, x[i + 8], 6, 1873313359); d = II(d, a, b, c, x[i + 15], 10, -30611744); c = II(c, d, a, b, x[i + 6], 15, -1560198380); b = II(b, c, d, a, x[i + 13], 21, 1309151649);
    a = II(a, b, c, d, x[i + 4], 6, -145523070); d = II(d, a, b, c, x[i + 11], 10, -1120210379); c = II(c, d, a, b, x[i + 2], 15, 718787259); b = II(b, c, d, a, x[i + 9], 21, -343485551);
    a = au(a, oa); b = au(b, ob); c = au(c, oc); d = au(d, od);
  }
  return bh([a, b, c, d]);
}
const b64urlToStr = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; try { return decodeURIComponent(escape(atob(s))); } catch (e) { return atob(s); } };

// ================= REGISTRY ALAT =================
const TOOLS = [
  // ---------- Encode / Decode ----------
  { id: 'base64', grp: 'Encode / Decode', e: '🔡', name: 'Base64', desc: 'Encode & decode teks Base64 (mendukung UTF-8 & URL-safe).',
    render(root) {
      let mode = 'encode', urlsafe = false;
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div>
        <label class="chk"><input type="checkbox" id="us"> URL-safe</label></div>
        <label class="lbl">Input</label><textarea id="in" placeholder="Ketik teks…"></textarea>
        <label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`;
      const run = () => {
        const v = $('#in', root).value, out = $('#out', root);
        try {
          let r;
          if (mode === 'encode') { r = btoa(unescape(encodeURIComponent(v))); if (urlsafe) r = r.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
          else { let s = v.trim(); if (urlsafe || /[-_]/.test(s)) s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; r = decodeURIComponent(escape(atob(s))); }
          out.textContent = r || '—'; out.classList.toggle('empty', !r); withCopy(out, () => r);
        } catch (e) { out.innerHTML = '<span class="pill err">Input tidak valid</span>'; out.classList.remove('empty'); }
      };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#us', root).addEventListener('change', e => { urlsafe = e.target.checked; run(); });
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'url', grp: 'Encode / Decode', e: '🔗', name: 'URL Encode', desc: 'Encode & decode komponen URL (encodeURIComponent).',
    render(root) {
      let mode = 'encode';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div>
        <label class="lbl">Input</label><textarea id="in" placeholder="teks atau URL…"></textarea>
        <label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`;
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { const r = mode === 'encode' ? encodeURIComponent(v) : decodeURIComponent(v); out.textContent = r || '—'; out.classList.toggle('empty', !r); withCopy(out, () => r); } catch (e) { out.innerHTML = '<span class="pill err">Input tidak valid</span>'; out.classList.remove('empty'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'jwt', grp: 'Encode / Decode', e: '🎫', name: 'JWT Decoder', desc: 'Bongkar token JWT: header, payload, dan klaim (exp/iat) — tanpa mengirim token ke mana pun.',
    render(root) {
      root.innerHTML = `<label class="lbl">Token JWT</label><textarea id="in" placeholder="eyJhbGciOi..."></textarea>
        <div class="cardrow" style="margin-top:14px"><div><label class="lbl">Header</label><div class="out empty" id="h">—</div></div>
        <div><label class="lbl">Payload</label><div class="out empty" id="p">—</div></div></div>
        <div id="claims"></div>
        <div class="note">Decoder ini <b>tidak memverifikasi tanda tangan</b> (butuh secret/kunci publik). Gunakan untuk membaca isi token saja.</div>`;
      const run = () => {
        const t = $('#in', root).value.trim(), H = $('#h', root), P = $('#p', root), C = $('#claims', root);
        C.innerHTML = ''; if (!t) { H.textContent = P.textContent = '—'; H.classList.add('empty'); P.classList.add('empty'); return; }
        const parts = t.split('.');
        if (parts.length < 2) { H.innerHTML = '<span class="pill err">Bukan JWT valid</span>'; H.classList.remove('empty'); P.textContent = '—'; return; }
        try {
          const hd = JSON.parse(b64urlToStr(parts[0])), pl = JSON.parse(b64urlToStr(parts[1]));
          H.textContent = JSON.stringify(hd, null, 2); H.classList.remove('empty'); withCopy(H, () => JSON.stringify(hd, null, 2));
          P.textContent = JSON.stringify(pl, null, 2); P.classList.remove('empty'); withCopy(P, () => JSON.stringify(pl, null, 2));
          const rows = [];
          const now = Math.floor(Date.now() / 1000);
          const fmt = s => new Date(s * 1000).toLocaleString();
          if (pl.alg || hd.alg) rows.push(['Algoritma', hd.alg || pl.alg]);
          if (pl.iat) rows.push(['Diterbitkan (iat)', fmt(pl.iat)]);
          if (pl.nbf) rows.push(['Berlaku sejak (nbf)', fmt(pl.nbf)]);
          if (pl.exp) { const ok = pl.exp > now; rows.push(['Kedaluwarsa (exp)', fmt(pl.exp) + (ok ? '  ✓ masih berlaku' : '  ✕ SUDAH kedaluwarsa')]); }
          if (pl.sub) rows.push(['Subject (sub)', pl.sub]);
          if (pl.iss) rows.push(['Issuer (iss)', pl.iss]);
          if (rows.length) C.innerHTML = '<label class="lbl" style="margin-top:14px">Klaim</label>' + rows.map(r => `<div class="kv"><span class="k">${esc(r[0])}</span><span class="v">${esc(r[1])}</span></div>`).join('');
        } catch (e) { H.innerHTML = '<span class="pill err">Gagal decode: ' + esc(e.message) + '</span>'; H.classList.remove('empty'); }
      };
      $('#in', root).addEventListener('input', run);
    } },

  // ---------- Hash & ID ----------
  { id: 'hash', grp: 'Hash & ID', e: '#️⃣', name: 'Hash Teks', desc: 'Hitung MD5, SHA-1, SHA-256, dan SHA-512 dari teks sekaligus.',
    render(root) {
      root.innerHTML = `<label class="lbl">Teks</label><textarea id="in" placeholder="Ketik teks…"></textarea><div id="out" style="margin-top:14px"></div>`;
      const run = async () => {
        const v = $('#in', root).value, out = $('#out', root);
        if (!v) { out.innerHTML = '<div class="out empty">—</div>'; return; }
        const [s1, s256, s512] = await Promise.all([sha('SHA-1', v), sha('SHA-256', v), sha('SHA-512', v)]);
        const items = [['MD5', md5(v)], ['SHA-1', s1], ['SHA-256', s256], ['SHA-512', s512]];
        out.innerHTML = items.map(([k, h]) => `<label class="lbl">${k}</label><div class="out" data-h="${esc(h)}">${esc(h)}<button class="copy" data-c="${esc(h)}">Salin</button></div>`).join('');
        out.querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c)));
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'hmac', grp: 'Hash & ID', e: '🔑', name: 'HMAC-SHA256', desc: 'Hitung HMAC-SHA256 dari pesan memakai secret key.',
    render(root) {
      root.innerHTML = `<label class="lbl">Secret key</label><input class="f" id="key" placeholder="kunci rahasia">
        <label class="lbl" style="margin-top:12px">Pesan</label><textarea id="in" placeholder="pesan…"></textarea>
        <label class="lbl" style="margin-top:12px">HMAC-SHA256</label><div class="out empty" id="out">—</div>`;
      const run = async () => { const k = $('#key', root).value, m = $('#in', root).value, out = $('#out', root); if (!k || !m) { out.textContent = '—'; out.classList.add('empty'); return; } const r = await hmacSha256(k, m); out.textContent = r; out.classList.remove('empty'); withCopy(out, () => r); };
      $('#key', root).addEventListener('input', run); $('#in', root).addEventListener('input', run);
    } },

  { id: 'uuid', grp: 'Hash & ID', e: '🆔', name: 'UUID Generator', desc: 'Buat UUID v4 acak (kriptografis) — satu atau sekaligus banyak.',
    render(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Jumlah</label><input class="f" id="n" type="number" value="5" min="1" max="500" style="width:100px">
        <button class="btn acc" id="gen" type="button">Generate</button></div>
        <div class="out empty" id="out" style="margin-top:12px">—</div>`;
      const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16, v = c === 'x' ? r : (r & 0x3 | 0x8); return v.toString(16); }));
      const run = () => { const n = Math.max(1, Math.min(500, +$('#n', root).value || 1)); const list = Array.from({ length: n }, uuid).join('\n'); const out = $('#out', root); out.textContent = list; out.classList.remove('empty'); withCopy(out, () => list); };
      $('#gen', root).addEventListener('click', run); run();
    } },

  { id: 'password', grp: 'Hash & ID', e: '🔐', name: 'Password Generator', desc: 'Buat sandi acak yang kuat (kriptografis) — atur panjang & jenis karakter.',
    render(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Panjang</label><input class="f" id="len" type="number" value="16" min="4" max="128" style="width:100px">
        <label class="chk"><input type="checkbox" id="up" checked> A-Z</label>
        <label class="chk"><input type="checkbox" id="lo" checked> a-z</label>
        <label class="chk"><input type="checkbox" id="nu" checked> 0-9</label>
        <label class="chk"><input type="checkbox" id="sy" checked> simbol</label>
        <button class="btn acc" id="gen" type="button">Generate</button></div>
        <div class="out empty big" id="out" style="margin-top:12px">—</div><div id="meter" class="note"></div>`;
      const run = () => {
        let set = ''; if ($('#up', root).checked) set += 'ABCDEFGHJKLMNPQRSTUVWXYZ'; if ($('#lo', root).checked) set += 'abcdefghijkmnpqrstuvwxyz'; if ($('#nu', root).checked) set += '23456789'; if ($('#sy', root).checked) set += '!@#$%^&*()-_=+[]{};:,.?';
        const out = $('#out', root); if (!set) { out.textContent = 'Pilih minimal satu jenis karakter'; return; }
        const len = Math.max(4, Math.min(128, +$('#len', root).value || 16));
        const rnd = crypto.getRandomValues(new Uint32Array(len));
        let pw = ''; for (let i = 0; i < len; i++) pw += set[rnd[i] % set.length];
        out.textContent = pw; out.classList.remove('empty'); withCopy(out, () => pw);
        const bits = Math.round(len * Math.log2(set.length));
        const lvl = bits < 50 ? ['Lemah', 'err'] : bits < 80 ? ['Cukup', 'warn'] : ['Kuat', 'ok'];
        $('#meter', root).innerHTML = `Entropi ≈ <b>${bits} bit</b> · <span class="pill ${lvl[1]}">${lvl[0]}</span>`;
      };
      root.querySelectorAll('input,#gen').forEach(x => x.addEventListener('input', run));
      $('#gen', root).addEventListener('click', run); run();
    } },

  // ---------- Format ----------
  { id: 'json', grp: 'Format', e: '📦', name: 'JSON Formatter', desc: 'Rapikan, minify, dan validasi JSON dengan penunjuk lokasi error.',
    render(root) {
      root.innerHTML = `<div class="row"><button class="btn acc sm" id="fmt" type="button">Rapikan (2 spasi)</button><button class="btn sm" id="min" type="button">Minify</button><span id="stat"></span></div>
        <label class="lbl">JSON</label><textarea id="in" style="min-height:180px" placeholder='{"hello":"world"}'></textarea>
        <label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`;
      const parse = () => { const v = $('#in', root).value.trim(); const stat = $('#stat', root); if (!v) { stat.innerHTML = ''; return null; } try { const o = JSON.parse(v); stat.innerHTML = '<span class="pill ok">Valid</span>'; return o; } catch (e) { stat.innerHTML = '<span class="pill err">' + esc(e.message) + '</span>'; return undefined; } };
      const show = (o, sp) => { const out = $('#out', root); if (o === undefined) { out.innerHTML = '<span class="pill err">JSON tidak valid</span>'; out.classList.remove('empty'); return; } if (o === null) { out.textContent = '—'; out.classList.add('empty'); return; } const r = JSON.stringify(o, null, sp); out.textContent = r; out.classList.remove('empty'); withCopy(out, () => r); };
      $('#fmt', root).addEventListener('click', () => show(parse(), 2));
      $('#min', root).addEventListener('click', () => show(parse(), 0));
      $('#in', root).addEventListener('input', () => { const o = parse(); if (o && o !== undefined) show(o, 2); });
    } },

  { id: 'regex', grp: 'Format', e: '🔍', name: 'Regex Tester', desc: 'Uji pola regular expression, sorot kecocokan, dan lihat grup tangkapan.',
    render(root) {
      root.innerHTML = `<div class="row"><div style="flex:1;min-width:200px"><label class="lbl">Pola</label><input class="f" id="pat" placeholder="\\b\\w+@\\w+\\.\\w+\\b"></div>
        <div><label class="lbl">Flag</label><input class="f" id="fl" value="g" style="width:90px" placeholder="gim"></div></div>
        <label class="lbl">Teks uji</label><textarea id="in" placeholder="tempel teks…"></textarea>
        <div class="row" style="margin-top:12px"><span id="stat"></span></div>
        <label class="lbl">Sorotan</label><div class="out empty" id="hl">—</div>
        <div id="groups"></div>`;
      const run = () => {
        const pat = $('#pat', root).value, fl = $('#fl', root).value, txt = $('#in', root).value;
        const stat = $('#stat', root), hlEl = $('#hl', root), gEl = $('#groups', root); gEl.innerHTML = '';
        if (!pat) { stat.innerHTML = ''; hlEl.textContent = '—'; hlEl.classList.add('empty'); return; }
        let re; try { re = new RegExp(pat, fl.includes('g') ? fl : fl + 'g'); } catch (e) { stat.innerHTML = '<span class="pill err">' + esc(e.message) + '</span>'; return; }
        let m, count = 0, last = 0, html = '', groups = [];
        try {
          while ((m = re.exec(txt)) !== null) {
            count++; html += esc(txt.slice(last, m.index)) + '<mark>' + esc(m[0] || '') + '</mark>'; last = m.index + (m[0].length || 0);
            if (m.length > 1) groups.push(m.slice(1));
            if (!re.global) break; if (m[0] === '') re.lastIndex++;
            if (count > 5000) break;
          }
        } catch (e) { stat.innerHTML = '<span class="pill err">' + esc(e.message) + '</span>'; return; }
        html += esc(txt.slice(last));
        stat.innerHTML = count ? `<span class="pill ok">${count} kecocokan</span>` : '<span class="pill warn">Tidak ada kecocokan</span>';
        hlEl.innerHTML = html || '—'; hlEl.classList.toggle('empty', !txt);
        if (groups.length) gEl.innerHTML = '<label class="lbl" style="margin-top:14px">Grup tangkapan (kecocokan pertama)</label>' + groups[0].map((g, i) => `<div class="kv"><span class="k">Grup ${i + 1}</span><span class="v">${esc(g == null ? '(kosong)' : g)}</span></div>`).join('');
      };
      root.querySelectorAll('input,textarea').forEach(x => x.addEventListener('input', run));
    } },

  // ---------- Konversi ----------
  { id: 'timestamp', grp: 'Konversi', e: '⏱️', name: 'Timestamp', desc: 'Konversi Unix timestamp ↔ tanggal (lokal & UTC).',
    render(root) {
      root.innerHTML = `<div class="row"><button class="btn acc sm" id="now" type="button">Sekarang</button></div>
        <label class="lbl">Unix timestamp (detik atau milidetik)</label><input class="f" id="ts" placeholder="1735689600">
        <div id="o1" style="margin-top:6px"></div>
        <label class="lbl" style="margin-top:16px">Tanggal (apa saja yang bisa diparse)</label><input class="f" id="dt" placeholder="2026-08-25 14:30 atau 25 Aug 2026">
        <div id="o2" style="margin-top:6px"></div>`;
      const fromTs = () => { const v = $('#ts', root).value.trim(), o = $('#o1', root); if (!v || isNaN(+v)) { o.innerHTML = ''; return; } let n = +v; if (v.length <= 11) n *= 1000; const d = new Date(n); if (isNaN(d)) { o.innerHTML = '<span class="pill err">Tidak valid</span>'; return; } o.innerHTML = `<div class="kv"><span class="k">Lokal</span><span class="v">${esc(d.toLocaleString())}</span></div><div class="kv"><span class="k">UTC</span><span class="v">${esc(d.toUTCString())}</span></div><div class="kv"><span class="k">ISO 8601</span><span class="v">${esc(d.toISOString())}</span></div>`; };
      const fromDt = () => { const v = $('#dt', root).value.trim(), o = $('#o2', root); if (!v) { o.innerHTML = ''; return; } const d = new Date(v); if (isNaN(d)) { o.innerHTML = '<span class="pill err">Tidak bisa diparse</span>'; return; } o.innerHTML = `<div class="kv"><span class="k">Unix (detik)</span><span class="v">${Math.floor(d.getTime() / 1000)}</span></div><div class="kv"><span class="k">Unix (ms)</span><span class="v">${d.getTime()}</span></div>`; };
      $('#ts', root).addEventListener('input', fromTs); $('#dt', root).addEventListener('input', fromDt);
      $('#now', root).addEventListener('click', () => { $('#ts', root).value = Math.floor(Date.now() / 1000); fromTs(); });
    } },

  { id: 'text', grp: 'Konversi', e: '📝', name: 'Teks & Kasus', desc: 'Ubah kapitalisasi, buat slug, hitung kata, urutkan/uniq/balik baris.',
    render(root) {
      root.innerHTML = `<label class="lbl">Teks</label><textarea id="in" placeholder="tempel teks…"></textarea>
        <div class="row" style="margin-top:12px">
          ${['UPPER', 'lower', 'Title Case', 'camelCase', 'snake_case', 'kebab-case', 'slug', 'Balik baris', 'Urutkan A-Z', 'Hapus duplikat'].map(x => `<button class="btn sm" data-op="${x}">${x}</button>`).join('')}
        </div>
        <div id="stat" class="note"></div>
        <label class="lbl" style="margin-top:10px">Hasil</label><div class="out empty" id="out">—</div>`;
      const words = s => (s.trim().match(/\S+/g) || []).length;
      const stat = () => { const v = $('#in', root).value; $('#stat', root).innerHTML = `${v.length} karakter · ${words(v)} kata · ${v ? v.split(/\n/).length : 0} baris`; };
      const ops = {
        'UPPER': s => s.toUpperCase(), 'lower': s => s.toLowerCase(),
        'Title Case': s => s.replace(/\w\S*/g, t => t[0].toUpperCase() + t.slice(1).toLowerCase()),
        'camelCase': s => s.toLowerCase().replace(/[^a-z0-9]+(.)/g, (_, c) => c.toUpperCase()),
        'snake_case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, ''),
        'kebab-case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
        'slug': s => s.trim().toLowerCase().normalize('NFKD').replace(/[^\w\s-]/g, '').replace(/[\s_]+/g, '-').replace(/^-+|-+$/g, ''),
        'Balik baris': s => s.split('\n').reverse().join('\n'),
        'Urutkan A-Z': s => s.split('\n').sort((a, b) => a.localeCompare(b)).join('\n'),
        'Hapus duplikat': s => [...new Set(s.split('\n'))].join('\n'),
      };
      root.querySelectorAll('[data-op]').forEach(b => b.addEventListener('click', () => { const r = ops[b.dataset.op]($('#in', root).value); const out = $('#out', root); out.textContent = r || '—'; out.classList.toggle('empty', !r); withCopy(out, () => r); }));
      $('#in', root).addEventListener('input', stat); stat();
    } },

  { id: 'color', grp: 'Konversi', e: '🎨', name: 'Konversi Warna', desc: 'Ubah warna antara HEX, RGB, dan HSL.',
    render(root) {
      root.innerHTML = `<div class="row"><input type="color" id="pick" value="#5eead4" style="width:52px;height:44px;border:1px solid var(--line);border-radius:9px;background:none;cursor:pointer">
        <input class="f" id="in" value="#5eead4" style="max-width:220px" placeholder="#5eead4 / rgb(94,234,212)"></div>
        <div id="out" style="margin-top:12px"></div><div id="sw" style="height:70px;border-radius:12px;border:1px solid var(--line);margin-top:12px"></div>`;
      function parse(str) {
        str = str.trim();
        let m = str.match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i);
        if (m) { let h = m[1]; if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; }
        m = str.match(/rgba?\(([^)]+)\)/i); if (m) { const p = m[1].split(',').map(x => parseFloat(x)); return [p[0], p[1], p[2]]; }
        return null;
      }
      const toHex = ([r, g, b]) => '#' + [r, g, b].map(x => Math.round(x).toString(16).padStart(2, '0')).join('');
      const toHsl = ([r, g, b]) => { r /= 255; g /= 255; b /= 255; const mx = Math.max(r, g, b), mn = Math.min(r, g, b); let h = 0, s = 0, l = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; s = l > .5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6; } return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`; };
      const run = (src) => { const rgb = parse(src); const out = $('#out', root); if (!rgb || rgb.some(isNaN)) { out.innerHTML = '<span class="pill err">Warna tidak valid</span>'; return; } const hex = toHex(rgb); $('#sw', root).style.background = hex; $('#pick', root).value = hex; const items = [['HEX', hex], ['RGB', `rgb(${rgb.map(Math.round).join(', ')})`], ['HSL', toHsl(rgb)]]; out.innerHTML = items.map(([k, v]) => `<div class="kv"><span class="k">${k}</span><span class="v" style="cursor:pointer" data-c="${esc(v)}">${esc(v)} ⧉</span></div>`).join(''); out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c))); };
      $('#in', root).addEventListener('input', e => run(e.target.value));
      $('#pick', root).addEventListener('input', e => { $('#in', root).value = e.target.value; run(e.target.value); });
      run('#5eead4');
    } },
];

// ================= SHELL =================
const nav = $('#nav');
function buildNav(filter = '') {
  const f = filter.toLowerCase().trim();
  const groups = {};
  TOOLS.filter(t => !f || (t.name + ' ' + t.id + ' ' + t.desc).toLowerCase().includes(f)).forEach(t => (groups[t.grp] = groups[t.grp] || []).push(t));
  nav.innerHTML = Object.entries(groups).map(([g, arr]) =>
    `<div class="grp">${g}</div>` + arr.map(t => `<button class="nlink" data-id="${t.id}"><span class="e">${t.e}</span> ${t.name}</button>`).join('')
  ).join('') || '<div class="grp">Tidak ditemukan</div>';
  nav.querySelectorAll('.nlink').forEach(b => b.addEventListener('click', () => { location.hash = b.dataset.id; document.body.classList.remove('nav-open'); }));
  markActive();
}
function markActive() { const id = current(); nav.querySelectorAll('.nlink').forEach(b => b.classList.toggle('on', b.dataset.id === id)); }
function current() { const id = location.hash.replace('#', ''); return TOOLS.some(t => t.id === id) ? id : TOOLS[0].id; }
function open(id) {
  const t = TOOLS.find(x => x.id === id) || TOOLS[0];
  $('#ttl').textContent = t.name; $('#desc').textContent = t.desc;
  const root = $('#tool'); root.innerHTML = ''; t.render(root); markActive();
  document.title = t.name + ' — DevSec Toolbox';
  $('.main').scrollTop = 0;
}
addEventListener('hashchange', () => open(current()));
$('#search').addEventListener('input', e => buildNav(e.target.value));
$('#menutgl').addEventListener('click', () => document.body.classList.toggle('nav-open'));
buildNav(); open(current());

// status QA
window.__DS = { tools: TOOLS.map(t => t.id), get active() { return current(); }, open(id) { location.hash = id; } };
