(function(){
  const canvas = document.getElementById('screen');
  const canvasGb = document.getElementById('screen-gb');
  const canvasPager = document.getElementById('screen-pager');
  const ctx = canvas.getContext('2d');
  const ctxGb = canvasGb ? canvasGb.getContext('2d') : null;
  const ctxPager = canvasPager ? canvasPager.getContext('2d') : null;
  // Enable high-DPI backing store and high-quality smoothing
  function setupHiDPI(){
    const DPR = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    const logical = 128;
    canvas.width = logical * DPR;
    canvas.height = logical * DPR;
    ctx.imageSmoothingEnabled = true;
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
    if (canvasGb && ctxGb) {
      canvasGb.width = logical * DPR;
      canvasGb.height = logical * DPR;
      ctxGb.imageSmoothingEnabled = true;
      try { ctxGb.imageSmoothingQuality = 'high'; } catch {}
    }
    if (canvasPager && ctxPager) {
      canvasPager.width = logical * DPR;
      canvasPager.height = logical * DPR;
      ctxPager.imageSmoothingEnabled = true;
      try { ctxPager.imageSmoothingQuality = 'high'; } catch {}
    }
  }
  setupHiDPI();
  window.addEventListener('resize', setupHiDPI);
  const statusEl = document.getElementById('status');
  const statusEls = document.querySelectorAll('.status-text');
  const deviceShell = document.getElementById('deviceShell');
  const themeNameEl = document.getElementById('themeName');
  const themePrev = document.getElementById('themePrev');
  const themeNext = document.getElementById('themeNext');

  // Build WS URL from current page host. Supports optional token in page URL (?token=...)
  function getWsUrl(){
    const p = new URLSearchParams(location.search);
    const token = p.get('token');
    const host = location.hostname || 'raspberrypi.local';
    const port = p.get('port') || '8765';
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const q = token ? `?token=${encodeURIComponent(token)}` : '';
    return `${proto}://${host}:${port}/${q}`.replace(/\/\/\//,'//');
  }

  let ws = null;
  let reconnectTimer = null;
  const pressed = new Set(); // keyboard pressed state

  function setStatus(txt){
    if (statusEl) statusEl.textContent = txt;
    if (statusEls && statusEls.length) {
      statusEls.forEach(el => { el.textContent = txt; });
    }
  }

  // Handheld themes (frontend-only)
  const themes = [
    { id: 'neon', label: 'Neon' },
    { id: 'gameboy', label: 'Game Boy' },
    { id: 'pager', label: 'Pager' },
  ];
  let themeIndex = 0;

  function applyTheme(){
    const t = themes[themeIndex];
    if (!deviceShell) return;
    deviceShell.classList.remove('theme-neon', 'theme-gameboy', 'theme-pager');
    deviceShell.classList.add(`theme-${t.id}`);
    deviceShell.setAttribute('data-theme', t.id);
    if (themeNameEl) themeNameEl.textContent = t.label;
  }

  function nextTheme(dir){
    themeIndex = (themeIndex + dir + themes.length) % themes.length;
    applyTheme();
  }

  function connect(){
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    const url = getWsUrl();
    try{
      ws = new WebSocket(url);
    } catch(e){
      setStatus('WebSocket failed to construct');
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      setStatus('Connected');
    };

    ws.onmessage = (ev) => {
      try{
        const msg = JSON.parse(ev.data);
        if (msg.type === 'frame' && msg.data){
          const img = new Image();
          img.onload = () => {
            try {
              ctx.clearRect(0,0,canvas.width,canvas.height);
              ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
              if (ctxGb && canvasGb) {
                ctxGb.clearRect(0,0,canvasGb.width,canvasGb.height);
                ctxGb.drawImage(img, 0, 0, canvasGb.width, canvasGb.height);
              }
              if (ctxPager && canvasPager) {
                ctxPager.clearRect(0,0,canvasPager.width,canvasPager.height);
                ctxPager.drawImage(img, 0, 0, canvasPager.width, canvasPager.height);
              }
            } catch {}
          };
          img.src = 'data:image/jpeg;base64,' + msg.data;
        }
      }catch{}
    };

    ws.onclose = () => {
      setStatus('Disconnected – reconnecting…');
      scheduleReconnect();
    };

    ws.onerror = () => {
      try { ws.close(); } catch {}
    };
  }

  function scheduleReconnect(){
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(()=>{
      reconnectTimer = null;
      connect();
    }, 1000);
  }

  function sendInput(button, state){
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try{
      ws.send(JSON.stringify({ type: 'input', button, state }));
    }catch{}
  }

  // Mouse/touch buttons
  function bindButtons(){
    const buttons = document.querySelectorAll('[data-btn]');
    buttons.forEach(btn => {
      const name = btn.getAttribute('data-btn');
      const press = () => { btn.classList.add('active'); sendInput(name, 'press'); };
      const release = () => { btn.classList.remove('active'); sendInput(name, 'release'); };
      btn.addEventListener('mousedown', press);
      btn.addEventListener('mouseup', release);
      btn.addEventListener('mouseleave', release);
      btn.addEventListener('touchstart', (e)=>{ e.preventDefault(); press(); }, {passive:false});
      btn.addEventListener('touchend', (e)=>{ e.preventDefault(); release(); }, {passive:false});
      btn.addEventListener('touchcancel', (e)=>{ e.preventDefault(); release(); }, {passive:false});
    });
  }

  // Keyboard mapping
  const KEYMAP = new Map([
    ['ArrowUp','UP'],
    ['ArrowDown','DOWN'],
    ['ArrowLeft','LEFT'],
    ['ArrowRight','RIGHT'],
    ['Enter','OK'],
    ['NumpadEnter','OK'],
    ['Digit1','KEY1'],
    ['Digit2','KEY2'],
    ['Digit3','KEY3'],
    ['Escape','KEY3'],
  ]);

  function bindKeyboard(){
    window.addEventListener('keydown', (e)=>{
      const btn = KEYMAP.get(e.code) || KEYMAP.get(e.key);
      if (!btn) return;
      if (pressed.has(btn)) return; // avoid repeats
      pressed.add(btn);
      sendInput(btn, 'press');
      e.preventDefault();
    });
    window.addEventListener('keyup', (e)=>{
      const btn = KEYMAP.get(e.code) || KEYMAP.get(e.key);
      if (!btn) return;
      pressed.delete(btn);
      sendInput(btn, 'release');
      e.preventDefault();
    });
    window.addEventListener('blur', ()=>{
      // Release everything on blur to avoid stuck keys
      for (const btn of pressed){ sendInput(btn, 'release'); }
      pressed.clear();
    });
  }

  bindButtons();
  bindKeyboard();
  if (themePrev) themePrev.addEventListener('click', () => nextTheme(-1));
  if (themeNext) themeNext.addEventListener('click', () => nextTheme(1));
  applyTheme();
  connect();
})();
