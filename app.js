// DevSec Toolbox — alat developer & keamanan, 100% di browser (tanpa jaringan).
// Tiap alat punya "tujuan" (untuk apa & kapan dipakai) + contoh. Semua diverifikasi vs nilai standar.
const $ = (s, r = document) => r.querySelector(s);
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const enc = new TextEncoder();
const fire = inp => inp.dispatchEvent(new Event('input', { bubbles: true }));

// Akar aplikasi (mis. "/devsec/") — dihitung dari lokasi app.js agar rute berbasis path jalan.
const BASE = new URL('.', import.meta.url).pathname;
// jsQR dimuat malas (lazy) — hanya saat alat "Baca QR" dibuka.
let _jsqr;
function loadJsQR() { return _jsqr || (_jsqr = new Promise((res, rej) => { const s = document.createElement('script'); s.src = new URL('vendor/jsqr.min.js', import.meta.url).href; s.onload = () => res(window.jsQR); s.onerror = () => rej(new Error('gagal memuat pemindai')); document.head.appendChild(s); })); }
// Pembersih: alat yang memasang listener global mendaftarkannya agar dilepas saat pindah alat.
let _cleanup = null;
function onCleanup(fn) { _cleanup = fn; }
function runCleanup() { if (_cleanup) { try { _cleanup(); } catch (e) { } _cleanup = null; } }

function toast(msg = 'Tersalin ✓') { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('on'), 1400); }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast()).catch(() => toast('Gagal menyalin')); }
function withCopy(outEl, getText) { const b = el('button', 'copy', 'Salin'); b.type = 'button'; b.addEventListener('click', () => copy(typeof getText === 'function' ? getText() : outEl.innerText)); outEl.appendChild(b); return outEl; }

// ---------- util kripto ----------
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

// ================= REGISTRY ALAT =================
const TOOLS = [
  // ---------- KEAMANAN ----------
  { id: 'jwt', grp: 'Keamanan', e: '🎫', name: 'JWT Decoder & Verify', desc: 'Bongkar token JWT dan (opsional) verifikasi tanda tangan HS256.',
    tujuan: '<b>Untuk apa:</b> JWT dipakai untuk sesi login & otorisasi API. Alat ini membaca isi token (siapa, peran, kapan kedaluwarsa) dan bisa <b>memverifikasi</b> apakah token asli/tidak dipalsukan (HS256) memakai secret-mu. <b>Kapan:</b> saat debugging autentikasi atau memeriksa token yang mencurigakan — semua di browser, token tak pernah dikirim.',
    contoh(root) { $('#in', root).value = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik5hZGlhIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE3NjcyMjU2MDB9.3Toql3l7Wzn3f0dW8kK5m0dW3Zt6xO2xU5aQ2vFqk1o'; $('#sec', root).value = ''; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Token JWT</label><textarea id="in" placeholder="eyJhbGciOi..."></textarea>
        <label class="lbl" style="margin-top:12px">Secret (opsional — untuk verifikasi HS256)</label><input class="f" id="sec" placeholder="secret HMAC">
        <div class="cardrow" style="margin-top:14px"><div><label class="lbl">Header</label><div class="out empty" id="h">—</div></div><div><label class="lbl">Payload</label><div class="out empty" id="p">—</div></div></div>
        <div id="verify" style="margin-top:12px"></div><div id="claims"></div>`;
      const run = async () => {
        const t = $('#in', root).value.trim(), H = $('#h', root), P = $('#p', root), C = $('#claims', root), V = $('#verify', root);
        C.innerHTML = ''; V.innerHTML = '';
        if (!t) { H.textContent = P.textContent = '—'; H.classList.add('empty'); P.classList.add('empty'); return; }
        const parts = t.split('.'); if (parts.length < 2) return setErr(H, 'Bukan JWT valid (butuh header.payload.signature)');
        let hd, pl;
        try { hd = JSON.parse(b64urlToStr(parts[0])); pl = JSON.parse(b64urlToStr(parts[1])); } catch (e) { return setErr(H, 'Gagal decode: ' + e.message); }
        H.textContent = JSON.stringify(hd, null, 2); H.classList.remove('empty'); withCopy(H, () => JSON.stringify(hd, null, 2));
        P.textContent = JSON.stringify(pl, null, 2); P.classList.remove('empty'); withCopy(P, () => JSON.stringify(pl, null, 2));
        const now = Math.floor(Date.now() / 1000), fmt = s => new Date(s * 1000).toLocaleString(), rows = [];
        if (hd.alg) rows.push(['Algoritma', hd.alg]);
        if (pl.iat) rows.push(['Diterbitkan (iat)', fmt(pl.iat)]);
        if (pl.exp) rows.push(['Kedaluwarsa (exp)', fmt(pl.exp) + (pl.exp > now ? '  ✓ masih berlaku' : '  ✕ SUDAH kedaluwarsa')]);
        if (pl.sub) rows.push(['Subject (sub)', pl.sub]); if (pl.iss) rows.push(['Issuer (iss)', pl.iss]);
        if (rows.length) C.innerHTML = '<label class="lbl" style="margin-top:14px">Klaim</label>' + rows.map(r => `<div class="kv"><span class="k">${esc(r[0])}</span><span class="v">${esc(r[1])}</span></div>`).join('');
        const sec = $('#sec', root).value;
        if (sec && parts[2]) {
          if (hd.alg !== 'HS256') { V.innerHTML = '<span class="pill warn">Verifikasi otomatis hanya untuk HS256 (token ini ' + esc(hd.alg || '?') + ')</span>'; return; }
          const sig = await hmacSha256(sec, parts[0] + '.' + parts[1]);
          const ok = b64url(sig) === parts[2];
          V.innerHTML = ok ? '<span class="pill ok">✓ Tanda tangan VALID — token asli</span>' : '<span class="pill err">✕ Tanda tangan TIDAK cocok — token palsu / secret salah</span>';
        }
      };
      $('#in', root).addEventListener('input', run); $('#sec', root).addEventListener('input', run);
    } },

  { id: 'aes', grp: 'Keamanan', e: '🔒', name: 'Enkripsi AES', desc: 'Enkripsi & dekripsi teks dengan AES-256-GCM + kata sandi (PBKDF2).',
    tujuan: '<b>Untuk apa:</b> mengunci teks rahasia (catatan, kunci API, pesan) memakai <b>AES-256-GCM</b> — standar enkripsi kuat. Kunci diturunkan dari kata sandimu via <b>PBKDF2 (150.000 iterasi)</b> + salt acak, jadi hanya yang tahu sandi bisa membuka. <b>Kapan:</b> mengirim teks sensitif lewat kanal tak aman. Semua di browser — teks &amp; sandi tak pernah keluar.',
    contoh(root) { $('#pass', root).value = 'rahasia123'; $('#in', root).value = 'Ini pesan rahasia untuk diuji 🔐'; $('#m button[data-m=enc]', root).click(); $('#go', root).click(); },
    body(root) {
      let mode = 'enc';
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="enc" class="on">Enkripsi</button><button data-m="dec">Dekripsi</button></div></div>
        <label class="lbl">Kata sandi</label><input class="f" id="pass" type="text" placeholder="kata sandi rahasia">
        <label class="lbl" style="margin-top:12px" id="inl">Teks</label><textarea id="in" placeholder="teks…"></textarea>
        <button class="btn acc" id="go" type="button" style="margin-top:12px">Proses</button>
        <label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>
        <div class="note">Format keluaran: Base64 dari <span class="mono">salt(16) + iv(12) + ciphertext</span>. Untuk mendekripsi, tempel kembali seluruh Base64 itu &amp; sandi yang sama.</div>`;
      const setMode = m => { mode = m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b.dataset.m === m)); $('#inl', root).textContent = m === 'enc' ? 'Teks (plaintext)' : 'Base64 terenkripsi'; };
      $('#m', root).addEventListener('click', e => { if (e.target.dataset.m) setMode(e.target.dataset.m); });
      async function deriveKey(pass, salt) { const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']); return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }
      $('#go', root).addEventListener('click', async () => {
        const pass = $('#pass', root).value, v = $('#in', root).value, out = $('#out', root);
        if (!pass) return setErr(out, 'Isi kata sandi dulu'); if (!v) return setErr(out, 'Isi teks dulu');
        try {
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
        } catch (e) { setErr(out, mode === 'dec' ? 'Gagal dekripsi — sandi salah atau data rusak' : e.message); }
      });
    } },

  { id: 'hash', grp: 'Keamanan', e: '#️⃣', name: 'Hash Teks', desc: 'Hitung MD5, SHA-1, SHA-256, SHA-512 dari teks sekaligus.',
    tujuan: '<b>Untuk apa:</b> "sidik jari" digital sebuah teks. Hash yang sama = isi sama; beda sedikit = hash berubah total. <b>Kapan:</b> memeriksa integritas, menyimpan checksum, atau membandingkan data. Catatan: MD5 &amp; SHA-1 sudah <b>tidak aman untuk keamanan</b> (rawan tabrakan) — pakai SHA-256+.',
    contoh(root) { $('#in', root).value = 'abc'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Teks</label><textarea id="in" placeholder="Ketik teks…"></textarea><div id="out" style="margin-top:14px"></div>`;
      const run = async () => { const v = $('#in', root).value, out = $('#out', root); if (!v) { out.innerHTML = '<div class="out empty">—</div>'; return; } const [s1, s256, s512] = await Promise.all([sha('SHA-1', v), sha('SHA-256', v), sha('SHA-512', v)]); const items = [['MD5', md5(v)], ['SHA-1', s1], ['SHA-256', s256], ['SHA-512', s512]]; out.innerHTML = items.map(([k, h]) => `<label class="lbl">${k}</label><div class="out">${esc(h)}<button class="copy" data-c="${esc(h)}">Salin</button></div>`).join(''); out.querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c))); };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'hashfile', grp: 'Keamanan', e: '📂', name: 'Hash File', desc: 'Hitung SHA-256/SHA-1/SHA-512 dari sebuah file (cek integritas).',
    tujuan: '<b>Untuk apa:</b> memastikan file yang kamu unduh <b>utuh &amp; tidak diubah</b> — bandingkan hash-nya dengan yang dipublikasikan pembuat. <b>Kapan:</b> setelah mengunduh installer, ISO, atau rilis software. File diproses lokal, tidak diunggah ke mana pun.',
    body(root) {
      root.innerHTML = `<div class="drop" id="drop"><div class="big">Jatuhkan file di sini</div><div>atau klik untuk memilih · file tidak diunggah</div></div>
        <input type="file" id="file" style="display:none"><div id="meta" class="note"></div><div id="out" style="margin-top:12px"></div>`;
      const drop = $('#drop', root), file = $('#file', root);
      const run = async f => {
        if (!f) return; $('#meta', root).innerHTML = `<b>${esc(f.name)}</b> · ${(f.size / 1024).toFixed(1)} KB`; $('#out', root).innerHTML = '<div class="out empty">menghitung…</div>';
        const buf = await f.arrayBuffer();
        const [s256, s1, s512] = await Promise.all([sha('SHA-256', buf), sha('SHA-1', buf), sha('SHA-512', buf)]);
        const items = [['SHA-256', s256], ['SHA-1', s1], ['SHA-512', s512]];
        $('#out', root).innerHTML = items.map(([k, h]) => `<label class="lbl">${k}</label><div class="out">${esc(h)}<button class="copy" data-c="${esc(h)}">Salin</button></div>`).join('');
        $('#out', root).querySelectorAll('[data-c]').forEach(b => b.addEventListener('click', () => copy(b.dataset.c)));
      };
      drop.addEventListener('click', () => file.click());
      file.addEventListener('change', e => run(e.target.files[0]));
      drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', () => drop.classList.remove('over'));
      drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); run(e.dataTransfer.files[0]); });
    } },

  { id: 'hmac', grp: 'Keamanan', e: '🔑', name: 'HMAC-SHA256', desc: 'Hitung HMAC-SHA256 dari pesan memakai secret key.',
    tujuan: '<b>Untuk apa:</b> membuktikan sebuah pesan benar dari pihak yang tahu secret &amp; tidak diubah (message authentication). <b>Kapan:</b> menandatangani webhook, memverifikasi callback pembayaran, atau tanda tangan API.',
    contoh(root) { $('#key', root).value = 'kunci-rahasia'; $('#in', root).value = 'pesan penting'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Secret key</label><input class="f" id="key" placeholder="kunci rahasia"><label class="lbl" style="margin-top:12px">Pesan</label><textarea id="in" placeholder="pesan…"></textarea><label class="lbl" style="margin-top:12px">HMAC-SHA256 (hex)</label><div class="out empty" id="out">—</div>`;
      const run = async () => { const k = $('#key', root).value, m = $('#in', root).value, out = $('#out', root); if (!k || !m) { setOut(out, ''); return; } setOut(out, hex(await hmacSha256(k, m))); };
      $('#key', root).addEventListener('input', run); $('#in', root).addEventListener('input', run);
    } },

  { id: 'password', grp: 'Keamanan', e: '🎲', name: 'Password Generator', desc: 'Buat sandi acak kuat (kriptografis) + meter entropi.',
    tujuan: '<b>Untuk apa:</b> membuat sandi yang benar-benar acak &amp; sulit ditebak, memakai generator kriptografis (bukan Math.random). <b>Kapan:</b> tiap kali butuh sandi/kunci baru. Makin panjang &amp; beragam, makin tinggi entropinya.',
    body(root) {
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Panjang</label><input class="f" id="len" type="number" value="16" min="4" max="128" style="width:100px">
        <label class="chk"><input type="checkbox" id="up" checked> A-Z</label><label class="chk"><input type="checkbox" id="lo" checked> a-z</label><label class="chk"><input type="checkbox" id="nu" checked> 0-9</label><label class="chk"><input type="checkbox" id="sy" checked> simbol</label>
        <button class="btn acc" id="gen" type="button">Generate</button></div>
        <div class="out empty big" id="out" style="margin-top:12px">—</div><div id="meter" class="note"></div>`;
      const run = () => { let set = ''; if ($('#up', root).checked) set += 'ABCDEFGHJKLMNPQRSTUVWXYZ'; if ($('#lo', root).checked) set += 'abcdefghijkmnpqrstuvwxyz'; if ($('#nu', root).checked) set += '23456789'; if ($('#sy', root).checked) set += '!@#$%^&*()-_=+[]{};:,.?'; const out = $('#out', root); if (!set) { out.textContent = 'Pilih minimal satu jenis karakter'; return; } const len = Math.max(4, Math.min(128, +$('#len', root).value || 16)); const rnd = crypto.getRandomValues(new Uint32Array(len)); let pw = ''; for (let i = 0; i < len; i++) pw += set[rnd[i] % set.length]; setOut(out, pw); const bits = Math.round(len * Math.log2(set.length)); const lvl = bits < 50 ? ['Lemah', 'err'] : bits < 80 ? ['Cukup', 'warn'] : ['Kuat', 'ok']; $('#meter', root).innerHTML = `Entropi ≈ <b>${bits} bit</b> · <span class="pill ${lvl[1]}">${lvl[0]}</span>`; };
      root.querySelectorAll('input').forEach(x => x.addEventListener('input', run)); $('#gen', root).addEventListener('click', run); run();
    } },

  { id: 'pwcheck', grp: 'Keamanan', e: '🛡️', name: 'Cek Kekuatan Sandi', desc: 'Perkirakan kekuatan sandi & waktu untuk membobolnya.',
    tujuan: '<b>Untuk apa:</b> menilai seberapa aman sebuah sandi — memperkirakan entropi &amp; berapa lama untuk ditebak secara brute-force. <b>Kapan:</b> mengecek sandi sebelum memakainya. Sandi tidak dikirim ke mana pun; ini estimasi kasar untuk edukasi, bukan jaminan.',
    contoh(root) { $('#in', root).value = 'P@ssw0rd2024'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Sandi</label><input class="f" id="in" type="text" placeholder="ketik sandi untuk dinilai"><div id="out" style="margin-top:14px"></div>`;
      const COMMON = ['password', 'qwerty', '123456', 'admin', '111111', 'iloveyou', 'welcome', 'letmein', 'monkey', 'dragon', 'abc123', 'p@ssw0rd'];
      const run = () => {
        const v = $('#in', root).value, out = $('#out', root); if (!v) { out.innerHTML = ''; return; }
        let pool = 0; if (/[a-z]/.test(v)) pool += 26; if (/[A-Z]/.test(v)) pool += 26; if (/[0-9]/.test(v)) pool += 10; if (/[^a-zA-Z0-9]/.test(v)) pool += 33;
        let bits = v.length * Math.log2(pool || 1);
        const warns = [];
        if (COMMON.some(c => v.toLowerCase().includes(c))) { bits = Math.min(bits, 14); warns.push('Mengandung kata sandi umum'); }
        if (/^(.)\1+$/.test(v)) { bits = Math.min(bits, 10); warns.push('Karakter berulang'); }
        if (/^(0123456789|abcdefghijklmnopqrstuvwxyz|qwertyuiop)/i.test(v)) { bits = Math.min(bits, 15); warns.push('Pola berurutan'); }
        if (v.length < 8) warns.push('Terlalu pendek (< 8 karakter)');
        const guesses = Math.pow(2, bits) / 2, perSec = 1e10, secs = guesses / perSec;
        const human = s => s < 1 ? 'seketika' : s < 60 ? Math.round(s) + ' detik' : s < 3600 ? Math.round(s / 60) + ' menit' : s < 86400 ? Math.round(s / 3600) + ' jam' : s < 31536000 ? Math.round(s / 86400) + ' hari' : s < 3.15e9 ? Math.round(s / 31536000) + ' tahun' : (s / 31536000).toExponential(1) + ' tahun';
        const lvl = bits < 40 ? ['Sangat Lemah', 'err'] : bits < 60 ? ['Lemah', 'err'] : bits < 80 ? ['Cukup', 'warn'] : bits < 100 ? ['Kuat', 'ok'] : ['Sangat Kuat', 'ok'];
        out.innerHTML = `<div class="kv"><span class="k">Kekuatan</span><span class="v"><span class="pill ${lvl[1]}">${lvl[0]}</span></span></div>
          <div class="kv"><span class="k">Entropi</span><span class="v">${Math.round(bits)} bit</span></div>
          <div class="kv"><span class="k">Panjang</span><span class="v">${v.length} karakter</span></div>
          <div class="kv"><span class="k">Perkiraan waktu bobol</span><span class="v">${human(secs)}</span></div>
          ${warns.length ? '<div class="note" style="margin-top:10px">⚠️ ' + warns.map(esc).join(' · ') + '</div>' : ''}
          <div class="note">Asumsi 10 miliar tebakan/detik (serangan offline). Estimasi edukatif.</div>`;
      };
      $('#in', root).addEventListener('input', run);
    } },

  // ---------- ENCODE / DECODE ----------
  { id: 'base64', grp: 'Encode / Decode', e: '🔡', name: 'Base64', desc: 'Encode & decode teks Base64 (UTF-8 & URL-safe).',
    tujuan: '<b>Untuk apa:</b> mengubah teks/biner menjadi teks aman-transport (hanya A–Z, 0–9, +/). <b>Kapan:</b> menyisipkan data di URL, JSON, JWT, data URI, atau email. Base64 <b>bukan enkripsi</b> — siapa pun bisa men-decode-nya.',
    contoh(root) { $('#in', root).value = 'Halo Dunia 🌍'; fire($('#in', root)); },
    body(root) {
      let mode = 'encode', us = false;
      root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div><label class="chk"><input type="checkbox" id="us"> URL-safe</label></div><label class="lbl">Input</label><textarea id="in" placeholder="Ketik teks…"></textarea><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`;
      const run = () => { const v = $('#in', root).value, out = $('#out', root); try { let r; if (mode === 'encode') { r = btoa(unescape(encodeURIComponent(v))); if (us) r = r.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); } else { let s = v.trim(); if (us || /[-_]/.test(s)) s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; r = decodeURIComponent(escape(atob(s))); } setOut(out, r); } catch (e) { setErr(out, 'Input tidak valid'); } };
      $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#us', root).addEventListener('change', e => { us = e.target.checked; run(); }); $('#in', root).addEventListener('input', run);
    } },

  { id: 'url', grp: 'Encode / Decode', e: '🔗', name: 'URL Encode', desc: 'Encode & decode komponen URL (encodeURIComponent).',
    tujuan: '<b>Untuk apa:</b> mengamankan teks agar valid di dalam URL — spasi, &amp;, ?, / diubah jadi %XX. <b>Kapan:</b> menyusun query string atau parameter tautan secara manual.',
    contoh(root) { $('#in', root).value = 'nama=Andi & kota=Yogyakarta?'; fire($('#in', root)); },
    body(root) { let mode = 'encode'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in" placeholder="teks atau URL…"></textarea><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`; const run = () => { const v = $('#in', root).value, out = $('#out', root); try { setOut(out, mode === 'encode' ? encodeURIComponent(v) : decodeURIComponent(v)); } catch (e) { setErr(out, 'Input tidak valid'); } }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  { id: 'htmlent', grp: 'Encode / Decode', e: '🏷️', name: 'HTML Entities', desc: 'Encode & decode entitas HTML untuk menampilkan < > & di web.',
    tujuan: '<b>Untuk apa:</b> menampilkan karakter khusus (&lt; &gt; &amp; " \') sebagai teks di HTML tanpa dianggap tag — mencegah rusaknya markup &amp; XSS. <b>Kapan:</b> menampilkan kode/teks pengguna di halaman web.',
    contoh(root) { $('#in', root).value = '<a href="x">Tom & Jerry</a>'; fire($('#in', root)); },
    body(root) { let mode = 'encode'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="encode" class="on">Encode</button><button data-m="decode">Decode</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`; const ta = document.createElement('textarea'); const run = () => { const v = $('#in', root).value, out = $('#out', root); let r; if (mode === 'encode') r = v.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); else { ta.innerHTML = v; r = ta.value; } setOut(out, r); }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  { id: 'escape', grp: 'Encode / Decode', e: '⤵️', name: 'Escape String', desc: 'Escape & unescape string gaya JSON/JS (\\n, \\t, \\uXXXX).',
    tujuan: '<b>Untuk apa:</b> mengubah teks berbaris/berkarakter khusus menjadi satu baris aman untuk ditaruh di kode/JSON, dan sebaliknya. <b>Kapan:</b> menempel teks multi-baris ke dalam string kode atau file JSON.',
    contoh(root) { $('#in', root).value = 'Baris 1\nBaris 2\t"kutip"'; fire($('#in', root)); },
    body(root) { let mode = 'escape'; root.innerHTML = `<div class="row"><div class="seg" id="m"><button data-m="escape" class="on">Escape</button><button data-m="unescape">Unescape</button></div></div><label class="lbl">Input</label><textarea id="in"></textarea><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`; const run = () => { const v = $('#in', root).value, out = $('#out', root); try { setOut(out, mode === 'escape' ? JSON.stringify(v).slice(1, -1) : JSON.parse('"' + v.replace(/"/g, '\\"') + '"')); } catch (e) { setErr(out, 'Tidak bisa di-unescape'); } }; $('#m', root).addEventListener('click', e => { if (!e.target.dataset.m) return; mode = e.target.dataset.m; [...$('#m', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); }); $('#in', root).addEventListener('input', run); } },

  // ---------- FORMAT & DATA ----------
  { id: 'json', grp: 'Format & Data', e: '📦', name: 'JSON Formatter', desc: 'Rapikan, minify, & validasi JSON dengan pesan error.',
    tujuan: '<b>Untuk apa:</b> merapikan JSON yang berantakan agar mudah dibaca, memadatkannya untuk produksi, dan mengecek apakah valid. <b>Kapan:</b> membaca respons API atau menyunting file konfigurasi.',
    contoh(root) { $('#in', root).value = '{"nama":"Andi","umur":25,"skill":["JS","Go"],"aktif":true}'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><button class="btn acc sm" id="fmt" type="button">Rapikan</button><button class="btn sm" id="min" type="button">Minify</button><span id="stat"></span></div><label class="lbl">JSON</label><textarea id="in" style="min-height:180px" placeholder='{"hello":"world"}'></textarea><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`; const parse = () => { const v = $('#in', root).value.trim(), stat = $('#stat', root); if (!v) { stat.innerHTML = ''; return null; } try { const o = JSON.parse(v); stat.innerHTML = '<span class="pill ok">Valid</span>'; return o; } catch (e) { stat.innerHTML = '<span class="pill err">' + esc(e.message) + '</span>'; return undefined; } }; const show = (o, sp) => { const out = $('#out', root); if (o === undefined) return setErr(out, 'JSON tidak valid'); if (o === null) { setOut(out, ''); return; } setOut(out, JSON.stringify(o, null, sp)); }; $('#fmt', root).addEventListener('click', () => show(parse(), 2)); $('#min', root).addEventListener('click', () => show(parse(), 0)); $('#in', root).addEventListener('input', () => { const o = parse(); if (o && o !== undefined) show(o, 2); }); } },

  { id: 'regex', grp: 'Format & Data', e: '🔍', name: 'Regex Tester', desc: 'Uji regex, sorot kecocokan, lihat grup tangkapan.',
    tujuan: '<b>Untuk apa:</b> menguji pola pencarian teks (regular expression) secara langsung — melihat apa yang cocok sebelum dipakai di kode. <b>Kapan:</b> membuat validasi (email, telepon), parsing log, atau find-replace.',
    contoh(root) { $('#pat', root).value = '\\b\\w+@\\w+\\.\\w+\\b'; $('#in', root).value = 'kontak: andi@mail.com dan budi@web.id'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><div style="flex:1;min-width:200px"><label class="lbl">Pola</label><input class="f" id="pat" placeholder="\\d+"></div><div><label class="lbl">Flag</label><input class="f" id="fl" value="g" style="width:90px"></div></div><label class="lbl">Teks uji</label><textarea id="in"></textarea><div class="row" style="margin-top:12px"><span id="stat"></span></div><label class="lbl">Sorotan</label><div class="out empty" id="hl">—</div><div id="groups"></div>`; const run = () => { const pat = $('#pat', root).value, fl = $('#fl', root).value, txt = $('#in', root).value, stat = $('#stat', root), hlEl = $('#hl', root), gEl = $('#groups', root); gEl.innerHTML = ''; if (!pat) { stat.innerHTML = ''; hlEl.textContent = '—'; hlEl.classList.add('empty'); return; } let re; try { re = new RegExp(pat, fl.includes('g') ? fl : fl + 'g'); } catch (e) { return setErr(stat, e.message); } let m, count = 0, last = 0, html = '', groups = []; try { while ((m = re.exec(txt)) !== null) { count++; html += esc(txt.slice(last, m.index)) + '<mark>' + esc(m[0] || '') + '</mark>'; last = m.index + (m[0].length || 0); if (m.length > 1) groups.push(m.slice(1)); if (!re.global) break; if (m[0] === '') re.lastIndex++; if (count > 5000) break; } } catch (e) { return setErr(stat, e.message); } html += esc(txt.slice(last)); stat.innerHTML = count ? `<span class="pill ok">${count} kecocokan</span>` : '<span class="pill warn">Tidak ada kecocokan</span>'; hlEl.innerHTML = html || '—'; hlEl.classList.toggle('empty', !txt); if (groups.length) gEl.innerHTML = '<label class="lbl" style="margin-top:14px">Grup (kecocokan pertama)</label>' + groups[0].map((g, i) => `<div class="kv"><span class="k">Grup ${i + 1}</span><span class="v">${esc(g == null ? '(kosong)' : g)}</span></div>`).join(''); }; root.querySelectorAll('input,textarea').forEach(x => x.addEventListener('input', run)); } },

  { id: 'diff', grp: 'Format & Data', e: '↔️', name: 'Diff Teks', desc: 'Bandingkan dua teks baris demi baris (tambah/hapus).',
    tujuan: '<b>Untuk apa:</b> melihat perbedaan antara dua versi teks — baris yang ditambah (hijau) &amp; dihapus (merah). <b>Kapan:</b> membandingkan konfigurasi, revisi dokumen, atau dua respons.',
    contoh(root) { $('#a', root).value = 'baris satu\nbaris dua\nbaris tiga'; $('#b', root).value = 'baris satu\nbaris DUA diubah\nbaris tiga\nbaris empat'; fire($('#a', root)); },
    body(root) {
      root.innerHTML = `<div class="cardrow"><div><label class="lbl">Teks A (lama)</label><textarea id="a"></textarea></div><div><label class="lbl">Teks B (baru)</label><textarea id="b"></textarea></div></div><label class="lbl" style="margin-top:12px">Perbedaan</label><div class="out empty" id="out">—</div>`;
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
        out.innerHTML = rows.map(([t, l]) => `<div class="diffline ${t}">${esc(sign[t] + l)}</div>`).join('') || '<span class="pill ok">Identik</span>';
      };
      $('#a', root).addEventListener('input', run); $('#b', root).addEventListener('input', run);
    } },

  { id: 'numbase', grp: 'Format & Data', e: '🔢', name: 'Konversi Basis Angka', desc: 'Ubah angka antar biner, oktal, desimal, heksadesimal.',
    tujuan: '<b>Untuk apa:</b> mengonversi bilangan antar basis 2/8/10/16 (mendukung angka besar via BigInt). <b>Kapan:</b> bekerja dengan bitmask, warna hex, alamat memori, atau flag.',
    contoh(root) { $('#in', root).value = '255'; $('#from', root).value = '10'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<div class="row"><div style="flex:1"><label class="lbl">Angka</label><input class="f" id="in" placeholder="255"></div><div><label class="lbl">Dari basis</label><select class="f" id="from"><option value="2">Biner (2)</option><option value="8">Oktal (8)</option><option value="10" selected>Desimal (10)</option><option value="16">Heksa (16)</option></select></div></div><div id="out" style="margin-top:14px"></div>`;
      const run = () => { const v = $('#in', root).value.trim().replace(/^0[xob]/i, ''), base = +$('#from', root).value, out = $('#out', root); if (!v) { out.innerHTML = ''; return; } try { let n = 0n; const B = BigInt(base); for (const ch of v.toLowerCase()) { if (ch === '_') continue; const d = parseInt(ch, base); if (isNaN(d) || d >= base) throw new Error('digit "' + ch + '" tidak valid untuk basis ' + base); n = n * B + BigInt(d); } out.innerHTML = [['Biner', n.toString(2)], ['Oktal', n.toString(8)], ['Desimal', n.toString(10)], ['Heksa', n.toString(16).toUpperCase()]].map(([k, val]) => `<div class="kv"><span class="k">${k}</span><span class="v" style="cursor:pointer" data-c="${val}">${esc(val)} ⧉</span></div>`).join(''); out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c))); } catch (e) { setErr(out, e.message); } };
      $('#in', root).addEventListener('input', run); $('#from', root).addEventListener('change', run);
    } },

  { id: 'jsoncsv', grp: 'Format & Data', e: '📊', name: 'JSON → CSV', desc: 'Ubah array JSON objek menjadi tabel CSV (siap Excel).',
    tujuan: '<b>Untuk apa:</b> mengubah data JSON berbentuk array objek menjadi CSV yang bisa dibuka di Excel / Google Sheets. Kolom diambil dari gabungan semua kunci; nilai objek/array ditulis sebagai JSON; koma &amp; kutip di-escape sesuai standar RFC 4180. <b>Kapan:</b> mengekspor respons API atau data ke spreadsheet.',
    contoh(root) { $('#in', root).value = '[{"nama":"Andi","umur":25,"kota":"Yogyakarta"},{"nama":"Budi","umur":30,"kota":"Bandung","hobi":"catur"}]'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">JSON (array objek)</label><textarea id="in" style="min-height:150px" placeholder='[{"a":1,"b":2}]'></textarea>
        <div class="row" style="margin-top:10px"><label class="chk"><input type="checkbox" id="semi"> Pemisah titik-koma (;)</label><button class="btn sm" id="dl" type="button">⭳ Unduh CSV</button><span id="stat"></span></div>
        <label class="lbl" style="margin-top:6px">CSV</label><div class="out empty" id="out">—</div>`;
      let lastCsv = '';
      const cell = (v, sep) => { if (v == null) return ''; let s = typeof v === 'object' ? JSON.stringify(v) : String(v); if (s.includes('"') || s.includes(sep) || s.includes('\n') || s.includes('\r')) s = '"' + s.replace(/"/g, '""') + '"'; return s; };
      const run = () => {
        const raw = $('#in', root).value.trim(), out = $('#out', root), stat = $('#stat', root); lastCsv = '';
        if (!raw) { out.textContent = '—'; out.classList.add('empty'); stat.innerHTML = ''; return; }
        let data; try { data = JSON.parse(raw); } catch (e) { return setErr(out, 'JSON tidak valid: ' + e.message); }
        if (!Array.isArray(data)) data = [data];
        if (!data.length) return setErr(out, 'Array kosong');
        const sep = $('#semi', root).checked ? ';' : ',';
        const keys = []; for (const row of data) { if (row && typeof row === 'object' && !Array.isArray(row)) for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k); }
        if (!keys.length) return setErr(out, 'Butuh array berisi objek {…}');
        const lines = [keys.map(k => cell(k, sep)).join(sep)];
        for (const row of data) lines.push(keys.map(k => cell(row ? row[k] : '', sep)).join(sep));
        lastCsv = lines.join('\r\n'); out.classList.remove('empty'); out.textContent = lastCsv; withCopy(out, () => lastCsv);
        stat.innerHTML = `<span class="pill ok">${data.length} baris · ${keys.length} kolom</span>`;
      };
      $('#dl', root).addEventListener('click', () => { if (!lastCsv) return; const blob = new Blob(['﻿' + lastCsv], { type: 'text/csv;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'data.csv'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); });
      $('#in', root).addEventListener('input', run); $('#semi', root).addEventListener('change', run);
    } },

  // ---------- GENERATOR ----------
  { id: 'uuid', grp: 'Generator', e: '🆔', name: 'UUID Generator', desc: 'Buat UUID v4 acak (kriptografis), satu atau banyak.',
    tujuan: '<b>Untuk apa:</b> membuat pengenal unik (ID) untuk record database, request, atau file tanpa risiko bentrok. <b>Kapan:</b> butuh primary key/ID acak yang praktis unik secara global.',
    body(root) { root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Jumlah</label><input class="f" id="n" type="number" value="5" min="1" max="500" style="width:100px"><button class="btn acc" id="gen" type="button">Generate</button></div><div class="out empty" id="out" style="margin-top:12px">—</div>`; const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16, v = c === 'x' ? r : (r & 0x3 | 0x8); return v.toString(16); })); const run = () => { const n = Math.max(1, Math.min(500, +$('#n', root).value || 1)); setOut($('#out', root), Array.from({ length: n }, uuid).join('\n')); }; $('#gen', root).addEventListener('click', run); run(); } },

  { id: 'qr', grp: 'Generator', e: '📱', name: 'QR Code Generator', desc: 'Buat QR code dari teks/URL & unduh sebagai PNG.',
    tujuan: '<b>Untuk apa:</b> mengubah teks, URL, WiFi, atau kontak menjadi QR yang bisa dipindai kamera HP. <b>Kapan:</b> berbagi tautan di poster/kartu nama, atau menyambungkan perangkat dengan cepat. Dibuat lokal (offline).',
    contoh(root) { $('#in', root).value = 'https://ksatriabintangsamudra.my.id'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Teks / URL</label><textarea id="in" placeholder="https://…"></textarea>
        <div class="row" style="margin-top:10px"><label class="lbl" style="margin:0">Koreksi galat</label><select class="f" id="ec" style="width:150px"><option value="L">L (7%)</option><option value="M" selected>M (15%)</option><option value="Q">Q (25%)</option><option value="H">H (30%)</option></select>
        <button class="btn sm" id="dl" type="button">⭳ Unduh PNG</button></div>
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
        } catch (e) { box.style.display = 'none'; err.innerHTML = '<span class="pill err">Teks terlalu panjang untuk QR</span>'; }
      };
      $('#dl', root).addEventListener('click', () => { if (!lastCanvas) return; const a = document.createElement('a'); a.href = lastCanvas.toDataURL('image/png'); a.download = 'qrcode.png'; a.click(); });
      $('#in', root).addEventListener('input', run); $('#ec', root).addEventListener('change', run);
    } },

  { id: 'qrdecode', grp: 'Generator', e: '📷', name: 'Baca QR (Gambar)', desc: 'Unggah gambar berisi QR code untuk membaca teks/URL-nya.',
    tujuan: '<b>Untuk apa:</b> membaca isi QR code dari sebuah gambar (screenshot / foto) langsung di browser — tanpa kamera &amp; <b>tanpa mengunggah gambar</b> ke server. <b>Kapan:</b> memeriksa tujuan sebuah QR sebelum membukanya, atau mengambil teks dari QR yang tampil di layar.',
    body(root) {
      root.innerHTML = `<div class="drop" id="drop"><div class="big">Jatuhkan gambar QR di sini</div><div>atau klik untuk memilih · tempel (Ctrl/⌘+V) juga bisa · gambar tidak diunggah</div></div>
        <input type="file" id="file" accept="image/*" style="display:none"><div id="out" style="margin-top:12px"></div>`;
      const drop = $('#drop', root), file = $('#file', root), out = $('#out', root);
      async function decode(src) {
        out.innerHTML = '<div class="out empty">memindai…</div>';
        let jsQR; try { jsQR = await loadJsQR(); } catch (e) { return setErr(out, 'Gagal memuat pemindai QR'); }
        const img = new Image();
        img.onload = () => {
          const max = 1200, sc = Math.min(1, max / Math.max(img.width, img.height));
          const w = Math.max(1, Math.round(img.width * sc)), h = Math.max(1, Math.round(img.height * sc));
          const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
          const ctx = cv.getContext('2d'); ctx.drawImage(img, 0, 0, w, h);
          const data = ctx.getImageData(0, 0, w, h);
          const code = jsQR(data.data, w, h);
          if (!code) return setErr(out, 'Tidak ada QR yang terbaca di gambar ini — coba gambar lebih jelas/besar');
          const txt = code.data, isUrl = /^https?:\/\//i.test(txt);
          out.innerHTML = `<label class="lbl">Isi QR</label><div class="out">${esc(txt)}<button class="copy" data-c="${esc(txt)}">Salin</button></div>${isUrl ? `<div class="note">🔗 Ini tautan — periksa dulu sebelum membukanya.</div>` : ''}`;
          out.querySelector('[data-c]').addEventListener('click', () => copy(txt));
        };
        img.onerror = () => setErr(out, 'Gagal memuat gambar'); img.src = src;
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

  { id: 'lorem', grp: 'Generator', e: '📄', name: 'Lorem Ipsum', desc: 'Buat teks placeholder (kata/kalimat/paragraf).',
    tujuan: '<b>Untuk apa:</b> mengisi desain/mockup dengan teks contoh agar tata letak terlihat nyata sebelum konten asli ada. <b>Kapan:</b> membuat prototipe UI atau template.',
    body(root) {
      const W = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum'.split(' ');
      root.innerHTML = `<div class="row"><label class="lbl" style="margin:0">Jumlah</label><input class="f" id="n" type="number" value="3" min="1" max="50" style="width:90px"><div class="seg" id="u"><button data-u="para" class="on">Paragraf</button><button data-u="kal">Kalimat</button><button data-u="kata">Kata</button></div><button class="btn acc" id="gen" type="button">Buat</button></div><label class="lbl" style="margin-top:12px">Hasil</label><div class="out empty" id="out">—</div>`;
      let unit = 'para'; const rnd = n => W[Math.floor(Math.random() * W.length)];
      const sentence = () => { const len = 8 + Math.floor(Math.random() * 8); let s = Array.from({ length: len }, rnd).join(' '); return s[0].toUpperCase() + s.slice(1) + '.'; };
      const para = () => Array.from({ length: 4 + Math.floor(Math.random() * 3) }, sentence).join(' ');
      const run = () => { const n = Math.max(1, Math.min(50, +$('#n', root).value || 1)); let r; if (unit === 'kata') r = Array.from({ length: n }, rnd).join(' '); else if (unit === 'kal') r = Array.from({ length: n }, sentence).join(' '); else r = Array.from({ length: n }, para).join('\n\n'); setOut($('#out', root), r); };
      $('#u', root).addEventListener('click', e => { if (!e.target.dataset.u) return; unit = e.target.dataset.u; [...$('#u', root).children].forEach(b => b.classList.toggle('on', b === e.target)); run(); });
      $('#gen', root).addEventListener('click', run); run();
    } },

  // ---------- KONVERSI ----------
  { id: 'timestamp', grp: 'Konversi', e: '⏱️', name: 'Timestamp', desc: 'Konversi Unix timestamp ↔ tanggal (lokal & UTC).',
    tujuan: '<b>Untuk apa:</b> menerjemahkan angka waktu Unix (detik sejak 1970) menjadi tanggal yang terbaca, dan sebaliknya. <b>Kapan:</b> membaca timestamp dari database, log, atau token (iat/exp).',
    contoh(root) { $('#now', root).click(); },
    body(root) { root.innerHTML = `<div class="row"><button class="btn acc sm" id="now" type="button">Sekarang</button></div><label class="lbl">Unix timestamp (detik/milidetik)</label><input class="f" id="ts" placeholder="1735689600"><div id="o1" style="margin-top:6px"></div><label class="lbl" style="margin-top:16px">Tanggal (bebas format)</label><input class="f" id="dt" placeholder="2026-08-25 14:30"><div id="o2" style="margin-top:6px"></div>`; const fromTs = () => { const v = $('#ts', root).value.trim(), o = $('#o1', root); if (!v || isNaN(+v)) { o.innerHTML = ''; return; } let n = +v; if (v.length <= 11) n *= 1000; const d = new Date(n); if (isNaN(d)) return setErr(o, 'Tidak valid'); o.innerHTML = `<div class="kv"><span class="k">Lokal</span><span class="v">${esc(d.toLocaleString())}</span></div><div class="kv"><span class="k">UTC</span><span class="v">${esc(d.toUTCString())}</span></div><div class="kv"><span class="k">ISO 8601</span><span class="v">${esc(d.toISOString())}</span></div>`; }; const fromDt = () => { const v = $('#dt', root).value.trim(), o = $('#o2', root); if (!v) { o.innerHTML = ''; return; } const d = new Date(v); if (isNaN(d)) return setErr(o, 'Tidak bisa diparse'); o.innerHTML = `<div class="kv"><span class="k">Unix (detik)</span><span class="v">${Math.floor(d.getTime() / 1000)}</span></div><div class="kv"><span class="k">Unix (ms)</span><span class="v">${d.getTime()}</span></div>`; }; $('#ts', root).addEventListener('input', fromTs); $('#dt', root).addEventListener('input', fromDt); $('#now', root).addEventListener('click', () => { $('#ts', root).value = Math.floor(Date.now() / 1000); fromTs(); }); } },

  { id: 'cron', grp: 'Konversi', e: '📅', name: 'Cron Parser', desc: 'Jelaskan ekspresi cron & tampilkan 5 jadwal berikutnya.',
    tujuan: '<b>Untuk apa:</b> memahami arti ekspresi cron (mis. <span class="mono">0 9 * * 1</span>) dan kapan ia benar-benar akan berjalan. <b>Kapan:</b> menyetel cron job/scheduled task agar tidak salah jadwal.',
    contoh(root) { $('#in', root).value = '0 9 * * 1-5'; fire($('#in', root)); },
    body(root) {
      root.innerHTML = `<label class="lbl">Ekspresi cron (menit jam tgl bln hari)</label><input class="f" id="in" placeholder="0 9 * * 1-5"><div id="desc2" style="margin-top:10px"></div><label class="lbl" style="margin-top:14px">5 jadwal berikutnya</label><div class="out empty" id="out">—</div>`;
      const NM = ['menit (0-59)', 'jam (0-23)', 'tanggal (1-31)', 'bulan (1-12)', 'hari (0-6, Min=0)'];
      const parseField = (f, min, max) => { const set = new Set(); for (const part of f.split(',')) { let step = 1, range = part; const sl = part.split('/'); if (sl.length === 2) { range = sl[0]; step = +sl[1]; } let lo, hi; if (range === '*') { lo = min; hi = max; } else if (range.includes('-')) { const [a, b] = range.split('-'); lo = +a; hi = +b; } else { lo = hi = +range; } if (isNaN(lo) || isNaN(hi) || isNaN(step) || step < 1) throw new Error('bagian tidak valid: "' + part + '"'); for (let v = lo; v <= hi; v += step) if (v >= min && v <= max) set.add(v); } return set; };
      const run = () => {
        const v = $('#in', root).value.trim(), out = $('#out', root), d2 = $('#desc2', root); d2.innerHTML = '';
        if (!v) { out.textContent = '—'; out.classList.add('empty'); return; }
        const f = v.split(/\s+/); if (f.length !== 5) return setErr(out, 'Harus 5 bagian dipisah spasi (menit jam tgl bln hari)');
        let sets; try { sets = [parseField(f[0], 0, 59), parseField(f[1], 0, 23), parseField(f[2], 1, 31), parseField(f[3], 1, 12), parseField(f[4], 0, 6)]; } catch (e) { return setErr(out, e.message); }
        d2.innerHTML = f.map((x, i) => `<div class="kv"><span class="k">${NM[i]}</span><span class="v">${esc(x)}</span></div>`).join('');
        const runs = []; const dt = new Date(); dt.setSeconds(0, 0); dt.setMinutes(dt.getMinutes() + 1);
        for (let guard = 0; guard < 366 * 24 * 60 && runs.length < 5; guard++) { const dow = dt.getDay(); if (sets[0].has(dt.getMinutes()) && sets[1].has(dt.getHours()) && sets[2].has(dt.getDate()) && sets[3].has(dt.getMonth() + 1) && sets[4].has(dow)) runs.push(new Date(dt).toLocaleString()); dt.setMinutes(dt.getMinutes() + 1); }
        out.classList.remove('empty'); out.textContent = runs.length ? runs.join('\n') : 'Tidak ada jadwal dalam 1 tahun ke depan'; if (runs.length) withCopy(out, () => runs.join('\n'));
      };
      $('#in', root).addEventListener('input', run);
    } },

  { id: 'urlparse', grp: 'Konversi', e: '🧭', name: 'URL Parser', desc: 'Uraikan URL menjadi bagian-bagiannya + tabel query.',
    tujuan: '<b>Untuk apa:</b> membedah URL menjadi protokol, host, port, path, parameter query, dan fragment. <b>Kapan:</b> debugging tautan, memeriksa parameter tracking, atau menganalisis URL mencurigakan.',
    contoh(root) { $('#in', root).value = 'https://user@shop.example.com:8443/produk/42?ref=promo&utm_source=ig#ulasan'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<label class="lbl">URL</label><input class="f" id="in" placeholder="https://…"><div id="out" style="margin-top:14px"></div>`; const run = () => { const v = $('#in', root).value.trim(), out = $('#out', root); if (!v) { out.innerHTML = ''; return; } let u; try { u = new URL(v); } catch (e) { return setErr(out, 'URL tidak valid'); } const rows = [['Protokol', u.protocol.replace(':', '')], ['Host', u.hostname], ['Port', u.port || '(default)'], ['Path', u.pathname], ['Fragment', u.hash.replace('#', '') || '(kosong)'], ['Origin', u.origin]]; let html = rows.map(r => `<div class="kv"><span class="k">${r[0]}</span><span class="v">${esc(r[1])}</span></div>`).join(''); const params = [...u.searchParams.entries()]; if (params.length) html += '<label class="lbl" style="margin-top:14px">Query parameter</label>' + params.map(([k, val]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join(''); out.innerHTML = html; }; $('#in', root).addEventListener('input', run); } },

  { id: 'text', grp: 'Konversi', e: '📝', name: 'Teks & Kasus', desc: 'Ubah kapitalisasi, slug, hitung kata, urut/uniq/balik.',
    tujuan: '<b>Untuk apa:</b> transformasi teks cepat — ubah huruf besar/kecil, buat slug URL, hitung kata, urutkan atau hapus baris duplikat. <b>Kapan:</b> merapikan daftar, membuat slug, atau menyiapkan data.',
    contoh(root) { $('#in', root).value = 'Halo Dunia Yang Indah'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<label class="lbl">Teks</label><textarea id="in"></textarea><div class="row" style="margin-top:12px">${['UPPER', 'lower', 'Title Case', 'camelCase', 'snake_case', 'kebab-case', 'slug', 'Balik baris', 'Urutkan A-Z', 'Hapus duplikat'].map(x => `<button class="btn sm" data-op="${x}">${x}</button>`).join('')}</div><div id="stat" class="note"></div><label class="lbl" style="margin-top:10px">Hasil</label><div class="out empty" id="out">—</div>`; const words = s => (s.trim().match(/\S+/g) || []).length; const stat = () => { const v = $('#in', root).value; $('#stat', root).innerHTML = `${v.length} karakter · ${words(v)} kata · ${v ? v.split(/\n/).length : 0} baris`; }; const ops = { 'UPPER': s => s.toUpperCase(), 'lower': s => s.toLowerCase(), 'Title Case': s => s.replace(/\w\S*/g, t => t[0].toUpperCase() + t.slice(1).toLowerCase()), 'camelCase': s => s.toLowerCase().replace(/[^a-z0-9]+(.)/g, (_, c) => c.toUpperCase()), 'snake_case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, ''), 'kebab-case': s => s.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''), 'slug': s => s.trim().toLowerCase().normalize('NFKD').replace(/[^\w\s-]/g, '').replace(/[\s_]+/g, '-').replace(/^-+|-+$/g, ''), 'Balik baris': s => s.split('\n').reverse().join('\n'), 'Urutkan A-Z': s => s.split('\n').sort((a, b) => a.localeCompare(b)).join('\n'), 'Hapus duplikat': s => [...new Set(s.split('\n'))].join('\n') }; root.querySelectorAll('[data-op]').forEach(b => b.addEventListener('click', () => setOut($('#out', root), ops[b.dataset.op]($('#in', root).value)))); $('#in', root).addEventListener('input', stat); stat(); } },

  { id: 'color', grp: 'Konversi', e: '🎨', name: 'Konversi Warna', desc: 'Ubah warna antara HEX, RGB, dan HSL.',
    tujuan: '<b>Untuk apa:</b> mengonversi kode warna antar format yang dipakai CSS/desain. <b>Kapan:</b> menyamakan warna dari Figma ke CSS, atau menyesuaikan palet.',
    contoh(root) { $('#in', root).value = '#5eead4'; fire($('#in', root)); },
    body(root) { root.innerHTML = `<div class="row"><input type="color" id="pick" value="#5eead4" style="width:52px;height:44px;border:1px solid var(--line);border-radius:9px;background:none;cursor:pointer"><input class="f" id="in" value="#5eead4" style="max-width:240px" placeholder="#5eead4 / rgb(94,234,212)"></div><div id="out" style="margin-top:12px"></div><div id="sw" style="height:70px;border-radius:12px;border:1px solid var(--line);margin-top:12px"></div>`; function parse(str) { str = str.trim(); let m = str.match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i); if (m) { let h = m[1]; if (h.length === 3) h = h.split('').map(c => c + c).join(''); return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]; } m = str.match(/rgba?\(([^)]+)\)/i); if (m) { const p = m[1].split(',').map(x => parseFloat(x)); return [p[0], p[1], p[2]]; } return null; } const toHex = ([r, g, b]) => '#' + [r, g, b].map(x => Math.round(x).toString(16).padStart(2, '0')).join(''); const toHsl = ([r, g, b]) => { r /= 255; g /= 255; b /= 255; const mx = Math.max(r, g, b), mn = Math.min(r, g, b); let h = 0, s = 0, l = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; s = l > .5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6; } return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`; }; const run = (src) => { const rgb = parse(src); const out = $('#out', root); if (!rgb || rgb.some(isNaN)) return setErr(out, 'Warna tidak valid'); const hexv = toHex(rgb); $('#sw', root).style.background = hexv; $('#pick', root).value = hexv; out.innerHTML = [['HEX', hexv], ['RGB', `rgb(${rgb.map(Math.round).join(', ')})`], ['HSL', toHsl(rgb)]].map(([k, v]) => `<div class="kv"><span class="k">${k}</span><span class="v" style="cursor:pointer" data-c="${esc(v)}">${esc(v)} ⧉</span></div>`).join(''); out.querySelectorAll('[data-c]').forEach(x => x.addEventListener('click', () => copy(x.dataset.c))); }; $('#in', root).addEventListener('input', e => run(e.target.value)); $('#pick', root).addEventListener('input', e => { $('#in', root).value = e.target.value; run(e.target.value); }); run('#5eead4'); } },

  { id: 'unit', grp: 'Konversi', e: '📐', name: 'Konversi Unit', desc: 'Konversi panjang, massa, suhu, & ukuran data.',
    tujuan: '<b>Untuk apa:</b> mengonversi satuan yang sering dipakai — panjang, massa/berat, suhu, dan ukuran data — dengan cepat &amp; akurat (faktor konversi resmi). <b>Kapan:</b> mengubah km↔mil, kg↔pon, °C↔°F, atau MB↔GB.',
    contoh(root) { $('#val', root).value = '100'; fire($('#val', root)); },
    body(root) {
      const CATS = {
        'Panjang': { u: { 'Milimeter (mm)': .001, 'Sentimeter (cm)': .01, 'Meter (m)': 1, 'Kilometer (km)': 1000, 'Inci (in)': .0254, 'Kaki (ft)': .3048, 'Yard (yd)': .9144, 'Mil': 1609.344 } },
        'Massa': { u: { 'Miligram (mg)': .001, 'Gram (g)': 1, 'Kilogram (kg)': 1000, 'Ton': 1e6, 'Ons (oz)': 28.349523125, 'Pon (lb)': 453.59237 } },
        'Suhu': { temp: true, u: { 'Celsius (°C)': 'C', 'Fahrenheit (°F)': 'F', 'Kelvin (K)': 'K' } },
        'Data': { u: { 'Bit': .125, 'Byte (B)': 1, 'Kilobyte (KB)': 1024, 'Megabyte (MB)': 1048576, 'Gigabyte (GB)': 1073741824, 'Terabyte (TB)': 1099511627776 } }
      };
      root.innerHTML = `<div class="row"><div style="flex:1;min-width:160px"><label class="lbl">Kategori</label><select class="f" id="cat"></select></div></div>
        <div class="cardrow"><div><label class="lbl">Dari</label><input class="f" id="val" placeholder="100"><select class="f" id="from" style="margin-top:8px"></select></div>
        <div><label class="lbl">Ke</label><div class="out" id="res" style="min-height:auto;cursor:pointer" title="klik untuk menyalin">—</div><select class="f" id="to" style="margin-top:8px"></select></div></div>`;
      const catSel = $('#cat', root), fromSel = $('#from', root), toSel = $('#to', root), val = $('#val', root), res = $('#res', root);
      catSel.innerHTML = Object.keys(CATS).map(c => `<option>${c}</option>`).join('');
      const toC = { C: v => v, F: v => (v - 32) * 5 / 9, K: v => v - 273.15 }, fromC = { C: v => v, F: v => v * 9 / 5 + 32, K: v => v + 273.15 };
      const fill = () => { const keys = Object.keys(CATS[catSel.value].u); fromSel.innerHTML = keys.map(k => `<option>${k}</option>`).join(''); toSel.innerHTML = keys.map(k => `<option>${k}</option>`).join(''); fromSel.selectedIndex = 0; toSel.selectedIndex = Math.min(1, keys.length - 1); };
      const run = () => { const c = CATS[catSel.value], v = parseFloat(val.value); if (val.value.trim() === '' || isNaN(v)) { res.textContent = '—'; return; } let o; if (c.temp) { o = fromC[c.u[toSel.value]](toC[c.u[fromSel.value]](v)); } else { o = v * c.u[fromSel.value] / c.u[toSel.value]; } const r = (o !== 0 && (Math.abs(o) >= 1e15 || Math.abs(o) < 1e-6)) ? o.toExponential(6) : String(+o.toFixed(6)); res.textContent = r; };
      catSel.addEventListener('change', () => { fill(); run(); });[fromSel, toSel, val].forEach(x => x.addEventListener('input', run));
      res.addEventListener('click', () => { if (res.textContent && res.textContent !== '—') copy(res.textContent); });
      fill(); run();
    } },
];

const GROUPS = ['Keamanan', 'Encode / Decode', 'Format & Data', 'Generator', 'Konversi'];
const HOME_TITLE = 'DevSec Toolbox — Alat Developer & Keamanan Online (100% di Browser)';
const HOME_DESC = 'Kumpulan alat developer & keamanan gratis yang berjalan 100% di browser: JWT decoder, enkripsi AES, hash SHA & MD5, HMAC, JSON, regex, QR, konversi unit, dan lainnya. Tanpa server, data tidak dikirim ke mana pun.';

// ================= RUTE (berbasis path, ramah SEO) =================
// Tiap alat punya URL sendiri: <BASE><id>/ (mis. /devsec/jwt/). Klik menu = navigasi
// dalam-halaman via History API (cepat, tanpa reload); akses langsung/crawler = halaman statis nyata.
const nav = $('#nav');
const urlFor = id => id === 'home' ? BASE : BASE + id + '/';
function tid(t) { return `<a class="nlink" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span> ${t.name}</a>`; }
function buildNav(filter = '') {
  const f = filter.toLowerCase().trim();
  let html = `<a class="nlink" data-id="home" href="${BASE}"><span class="e">🏠</span> Beranda</a>`;
  for (const g of GROUPS) {
    const arr = TOOLS.filter(t => t.grp === g && (!f || (t.name + ' ' + t.id + ' ' + t.desc).toLowerCase().includes(f)));
    if (!arr.length) continue;
    html += `<div class="grp">${g}</div>` + arr.map(tid).join('');
  }
  nav.innerHTML = html;
  nav.querySelectorAll('.nlink').forEach(a => a.addEventListener('click', e => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return; e.preventDefault(); go(a.dataset.id, true); document.body.classList.remove('nav-open'); }));
  markActive();
}
function markActive() { const id = current(); nav.querySelectorAll('.nlink').forEach(a => a.classList.toggle('on', a.dataset.id === id)); }
function current() {
  let p = decodeURIComponent(location.pathname);
  if (p.startsWith(BASE)) p = p.slice(BASE.length);
  p = p.replace(/index\.html?$/i, '').replace(/^\/+|\/+$/g, '');
  const id = p.split('/')[0];
  if (!id) return 'home';
  if (TOOLS.some(t => t.id === id)) return id;
  return document.body.dataset.tool && TOOLS.some(t => t.id === document.body.dataset.tool) ? document.body.dataset.tool : 'home';
}
function setMeta(title, desc) { document.title = title; const md = document.querySelector('meta[name="description"]'); if (md && desc) md.setAttribute('content', desc); }

function renderHome() {
  runCleanup();
  const grid = g => TOOLS.filter(t => t.grp === g).map(t => `<a class="hcard" data-id="${t.id}" href="${urlFor(t.id)}"><span class="e">${t.e}</span><span><b>${t.name}</b><span>${esc(t.desc)}</span></span></a>`).join('');
  const root = $('#tool');
  $('#ttl').textContent = 'Beranda'; $('#desc').textContent = '';
  root.innerHTML = `<div class="home-hero">
      <h2>Semua alat <span class="g">developer &amp; keamanan</span> dalam satu tempat.</h2>
      <p>DevSec Toolbox adalah kumpulan ${TOOLS.length} alat yang sering dibutuhkan sehari-hari — dari decode JWT, enkripsi AES, hash, hingga QR &amp; regex. Semuanya berjalan <b>100% di dalam browser-mu</b>: tidak ada server, tidak ada login, dan <b>tidak ada data yang dikirim ke mana pun</b>. Aman dipakai bahkan untuk token &amp; secret sensitif.</p>
      <div class="home-badges">
        <span class="hb">🔒 <b>On-device</b> — nol jaringan</span>
        <span class="hb">⚡ <b>Instan</b> — tanpa instal</span>
        <span class="hb">✅ <b>Teruji</b> — vs nilai standar</span>
        <span class="hb">🆓 <b>Gratis</b> — tanpa iklan</span>
      </div>
    </div>
    ${GROUPS.map(g => `<div class="home-grp">${g}</div><div class="home-grid">${grid(g)}</div>`).join('')}`;
  root.querySelectorAll('.hcard').forEach(a => a.addEventListener('click', e => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button) return; e.preventDefault(); go(a.dataset.id, true); }));
  setMeta(HOME_TITLE, HOME_DESC);
  markActive(); const m = $('.main'); if (m) m.scrollTop = 0;
}

function open(id) {
  runCleanup();
  if (id === 'home') return renderHome();
  const t = TOOLS.find(x => x.id === id) || TOOLS[0];
  $('#ttl').textContent = t.name; $('#desc').textContent = t.desc;
  const root = $('#tool'); root.innerHTML = '';
  const pb = el('div', 'purpose'); pb.innerHTML = `<span class="pi">${t.e}</span><div class="pt">${t.tujuan || esc(t.desc)}${t.contoh ? '<div class="ex"><button type="button" id="_ex">▶ Coba contoh</button></div>' : ''}</div>`;
  root.appendChild(pb);
  const bodyWrap = el('div'); root.appendChild(bodyWrap); t.body(bodyWrap);
  if (t.contoh) $('#_ex', pb).addEventListener('click', () => t.contoh(bodyWrap));
  setMeta(t.name + ' — DevSec Toolbox', t.desc);
  markActive(); const m = $('.main'); if (m) m.scrollTop = 0;
}

function go(id, push) { if (push) { const u = urlFor(id); if (location.pathname !== u) history.pushState({ id }, '', u); } open(id); }
addEventListener('popstate', () => open(current()));
$('#search').addEventListener('input', e => buildNav(e.target.value));
$('#menutgl').addEventListener('click', () => document.body.classList.toggle('nav-open'));
buildNav(); open(current());

window.__DS = { tools: TOOLS.map(t => t.id), groups: GROUPS, get active() { return current(); }, open(id) { go(id, true); } };
