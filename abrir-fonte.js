// uso: node abrir-fonte.js "senha" fonte.enc pasta-destino   (desfaz o fonte.enc)
const fs = require('fs'), path = require('path');
const { webcrypto } = require('crypto'); globalThis.crypto = webcrypto; globalThis.window = globalThis;
require('./js/crypto.js');
(async () => { const [s, f, d] = process.argv.slice(2); const k = await CVCrypto.chaves(s);
  const o = await CVCrypto.decifrar(fs.readFileSync(f, 'utf8'), k.enc);
  for (const [n, t] of Object.entries(o)) { const p = path.join(d, n); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, t); }
  console.log(Object.keys(o).length, 'arquivos em', d); })();
