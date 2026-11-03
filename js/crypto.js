/* Senha, criptografia e cópia local. Tudo roda no navegador: o que vai para a nuvem é só texto cifrado. */
(function (root) {
  'use strict';
  const enc = new TextEncoder(), dec = new TextDecoder();
  const ITER = 120000;
  const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
  const b64 = b => { let s = ''; new Uint8Array(b).forEach(x => s += String.fromCharCode(x)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const norm = pw => String(pw || '').trim().toLowerCase();       // a senha não diferencia maiúsculas de minúsculas

  async function bits(pw, sal) {
    const k = await crypto.subtle.importKey('raw', enc.encode(norm(pw)), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(sal), iterations: ITER }, k, 256);
  }
  async function sha256hex(t) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(t))); }

  // chaves a partir da senha: auth (prova que a senha está certa) e enc (cifra os dados)
  async function chaves(pw) {
    return { auth: hex(await bits(pw, 'cv-auth-v1')), enc: b64(await bits(pw, 'cv-enc-v1')) };
  }
  const importar = raw => crypto.subtle.importKey('raw', unb64(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);

  async function gzip(bytes) {
    if (typeof CompressionStream === 'undefined') return null;
    const s = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  async function gunzip(bytes) {
    const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }

  // objeto -> texto cifrado (1 byte de formato + IV + dados)
  async function cifrar(obj, encRaw) {
    const cru = enc.encode(JSON.stringify(obj));
    const gz = await gzip(cru);
    const corpo = new Uint8Array(gz ? gz.length + 1 : cru.length + 1);
    corpo[0] = gz ? 1 : 0; corpo.set(gz || cru, 1);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await importar(encRaw), corpo));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
    return 'cv1:' + b64(out);
  }
  async function decifrar(texto, encRaw) {
    if (!texto || !String(texto).startsWith('cv1:')) throw new Error('formato desconhecido');
    const b = unb64(String(texto).slice(4));
    const corpo = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, await importar(encRaw), b.slice(12)));
    const dados = corpo[0] === 1 ? await gunzip(corpo.slice(1)) : corpo.slice(1);
    return JSON.parse(dec.decode(dados));
  }
  root.CVCrypto = { chaves, sha256hex, cifrar, decifrar };
})(typeof window !== 'undefined' ? window : globalThis);
