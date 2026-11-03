(function () {
  'use strict';
  const C = window.CVCrypto, CFG = window.CV_CONFIG;
  const $ = s => document.querySelector(s);
  const guardar = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) { /* sem armazenamento */ } };
  const ler = k => { try { return localStorage.getItem(k); } catch (e) { return null; } };

  function tela(erro, msg) {
    const t = $('#trava'); t.hidden = false; $('#app').hidden = true;
    t.innerHTML = `<div class="trava-in"><form class="balao${erro ? ' erro' : ''}" id="f-senha" autocomplete="off">
        <h1>Qual é a senha?</h1><p>Digite para entrar.</p>
        <label for="senha" style="position:absolute;left:-9999px">Senha</label>
        <input id="senha" class="campo" type="password" autocomplete="current-password" placeholder="Digite aqui">
        <p class="msg-erro" id="msg-erro" role="alert">${erro ? (msg || 'Senha incorreta. Tente de novo.') : ''}</p>
        <button class="btn cheio grande" style="width:100%">Entrar</button>
        <label class="lembrar"><input type="checkbox" id="lembrar" checked> Manter neste aparelho</label>
      </form></div>`;
    $('#f-senha').addEventListener('submit', async ev => {
      ev.preventDefault();
      const b = $('#f-senha button'); b.disabled = true;
      try {
        const k = await C.chaves($('#senha').value);
        if ((await C.sha256hex(k.auth)) !== CFG.authHash) return tela(true);
        await abrir(k, $('#lembrar').checked);
      } catch (e) { tela(true, 'Não consegui abrir agora. Confira a internet e tente de novo.'); }
    });
    setTimeout(() => { const i = $('#senha'); if (i) i.focus(); }, 30);
  }

  // o programa fica cifrado no servidor: só com a senha certa ele é aberto
  async function abrir(k, lembrar) {
    const r = await fetch('app.bin', { cache: 'no-cache' });
    if (!r.ok) throw new Error('sem pacote');
    const pacote = await C.decifrar(await r.text(), k.enc);
    window.CV_CHAVES = k;
    window.CV_WORKER_URL = URL.createObjectURL(new Blob([pacote.worker], { type: 'text/javascript' }));
    const st = document.createElement('style'); st.textContent = pacote.css; document.head.appendChild(st);
    for (const js of pacote.js) { const s = document.createElement('script'); s.textContent = js; document.head.appendChild(s); }
    guardar('cv_sessao', lembrar ? JSON.stringify(k) : null);
    $('#trava').hidden = true; $('#trava').innerHTML = '';
    window.CVApp.iniciar();
  }

  window.addEventListener('DOMContentLoaded', async () => {
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) { $('#trava').innerHTML = '<div class="trava-in"><div class="balao"><h1>Use o link https</h1></div></div>'; return; }
    try {
      const k = JSON.parse(ler('cv_sessao') || 'null');
      if (k && k.auth && (await C.sha256hex(k.auth)) === CFG.authHash) { await abrir(k, true); return; }
    } catch (e) { guardar('cv_sessao', null); }
    tela(false);
  });
})();
