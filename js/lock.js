(function () {
  'use strict';
  const C = window.CVCrypto, CFG = window.CV_CONFIG;
  const $ = s => document.querySelector(s);
  const guardar = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) { /* sem armazenamento */ } };

  function tela(erro, msg) {
    const t = $('#trava'); t.hidden = false; $('#app').hidden = true;
    t.innerHTML = `<div class="trava-in"><form class="balao${erro ? ' erro' : ''}" id="f-senha" autocomplete="off">
        <h1>Qual é a senha?</h1><p>Digite para entrar.</p>
        <label for="senha" style="position:absolute;left:-9999px">Senha</label>
        <input id="senha" class="campo" type="password" autocomplete="current-password" placeholder="Digite aqui">
        <p class="msg-erro" id="msg-erro" role="alert">${erro ? (msg || 'Senha incorreta. Tente de novo.') : ''}</p>
        <div class="trava-botoes"><button class="btn cheio grande" value="app">Entrar</button><button class="btn grande" value="ia">Usar IA</button></div>
      </form></div>`;
    $('#f-senha').addEventListener('submit', async ev => {
      ev.preventDefault();
      const ia = !!(ev.submitter && ev.submitter.value === 'ia');
      document.querySelectorAll('#f-senha button').forEach(x => { x.disabled = true; });
      try {
        const k = await C.chaves($('#senha').value);
        if ((await C.sha256hex(k.auth)) !== (ia ? CFG.authHashIA : CFG.authHash)) return tela(true);
        await abrir(k, ia);
      } catch (e) { tela(true, 'Não consegui abrir agora. Confira a internet e tente de novo.'); }
    });
    setTimeout(() => { const i = $('#senha'); if (i) i.focus(); }, 30);
  }

  // o programa fica cifrado no servidor: só com a senha certa ele é aberto
  async function abrir(k, ia) {
    const r = await fetch(ia ? 'ia.bin' : 'app.bin', { cache: 'no-cache' });
    if (!r.ok) throw new Error('sem pacote');
    const pacote = await C.decifrar(await r.text(), k.enc);
    window.CV_CHAVES = k;
    if (pacote.worker) window.CV_WORKER_URL = URL.createObjectURL(new Blob([pacote.worker], { type: 'text/javascript' }));
    const st = document.createElement('style'); st.textContent = pacote.css; document.head.appendChild(st);
    for (const js of pacote.js) { const s = document.createElement('script'); s.textContent = js; document.head.appendChild(s); }
    vigiarInatividade();
    $('#trava').hidden = true; $('#trava').innerHTML = '';
    (ia ? window.CVIAApp : window.CVApp).iniciar();
  }

  // sem interação por 5 minutos: bloqueia (recarrega, e a senha some da memória). Não bloqueia no meio de um envio.
  function vigiarInatividade() {
    const LIMITE = (CFG.inativoMs || 5 * 60 * 1000);
    let t;
    const zerar = () => { clearTimeout(t); t = setTimeout(bloquear, LIMITE); };
    const bloquear = () => { if (window.CVApp && window.CVApp.ocupado && window.CVApp.ocupado()) return zerar(); location.reload(); };
    ['pointerdown', 'pointermove', 'keydown', 'wheel', 'scroll', 'touchstart'].forEach(e => window.addEventListener(e, zerar, { passive: true, capture: true }));
    zerar();
  }
  window.addEventListener('pageshow', ev => { if (ev.persisted) location.reload(); });   // voltou pelo "voltar" do navegador: pede a senha

  window.addEventListener('DOMContentLoaded', async () => {
    guardar('cv_sessao', null);                                    // nada de manter conectado
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) { $('#trava').innerHTML = '<div class="trava-in"><div class="balao"><h1>Use o link https</h1></div></div>'; return; }
    tela(false);
  });
})();
