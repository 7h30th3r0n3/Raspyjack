(function(){
  const canvas = document.getElementById('screen');
  const ctx = canvas.getContext('2d');
  // Enable high-DPI backing store and high-quality smoothing
  function setupHiDPI(){
    const DPR = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    const logical = 128;
    canvas.width = logical * DPR;
    canvas.height = logical * DPR;
    ctx.imageSmoothingEnabled = true;
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
  }
  setupHiDPI();
  window.addEventListener('resize', setupHiDPI);
  const statusEl = document.getElementById('status');

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

  function setStatus(txt){ statusEl.textContent = txt; }

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
  connect();
})();
