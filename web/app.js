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
  const themeBar = document.getElementById('themeBar');
  const tabDevice = document.getElementById('tabDevice');
  const tabLoot = document.getElementById('tabLoot');
  const deviceTab = document.getElementById('deviceTab');
  const lootTab = document.getElementById('lootTab');
  const lootList = document.getElementById('lootList');
  const lootPathEl = document.getElementById('lootPath');
  const lootUpBtn = document.getElementById('lootUp');
  const lootStatus = document.getElementById('lootStatus');

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

  function getApiUrl(path, params = {}){
    const p = new URLSearchParams(location.search);
    const token = p.get('token');
    if (token) params.token = token;
    const qs = new URLSearchParams(params).toString();
    const base = location.origin;
    return `${base}${path}${qs ? `?${qs}` : ''}`;
  }

  let ws = null;
  let reconnectTimer = null;
  const pressed = new Set(); // keyboard pressed state
  let activeTab = 'device';
  let lootState = { path: '', parent: '' };

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

  function setActiveTab(tab){
    activeTab = tab;
    const isDevice = tab === 'device';
    if (deviceTab) deviceTab.classList.toggle('hidden', !isDevice);
    if (lootTab) lootTab.classList.toggle('hidden', isDevice);
    if (themeBar) themeBar.classList.toggle('hidden', !isDevice);
    if (tabDevice) {
      tabDevice.classList.toggle('bg-emerald-500/10', isDevice);
      tabDevice.classList.toggle('text-emerald-300', isDevice);
      tabDevice.classList.toggle('border-emerald-400/30', isDevice);
      tabDevice.classList.toggle('bg-slate-800/40', !isDevice);
      tabDevice.classList.toggle('text-slate-300', !isDevice);
      tabDevice.classList.toggle('border-slate-400/20', !isDevice);
    }
    if (tabLoot) {
      tabLoot.classList.toggle('bg-emerald-500/10', !isDevice);
      tabLoot.classList.toggle('text-emerald-300', !isDevice);
      tabLoot.classList.toggle('border-emerald-400/30', !isDevice);
      tabLoot.classList.toggle('bg-slate-800/40', isDevice);
      tabLoot.classList.toggle('text-slate-300', isDevice);
      tabLoot.classList.toggle('border-slate-400/20', isDevice);
    }
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

  function formatBytes(bytes){
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    const value = bytes / Math.pow(k, i);
    return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${sizes[i]}`;
  }

  function formatTime(ts){
    try{
      const d = new Date(ts * 1000);
      return d.toLocaleString();
    }catch{
      return '';
    }
  }

  function buildLootPath(parent, name){
    return parent ? `${parent}/${name}` : name;
  }

  function setLootStatus(text){
    if (lootStatus) lootStatus.textContent = text;
  }

  function setLootPath(text){
    if (lootPathEl) lootPathEl.textContent = text ? `/${text}` : '/';
  }

  function updateLootUp(){
    if (!lootUpBtn) return;
    const disabled = !lootState.parent;
    lootUpBtn.disabled = disabled;
    lootUpBtn.classList.toggle('opacity-40', disabled);
    lootUpBtn.classList.toggle('cursor-not-allowed', disabled);
  }

  function renderLoot(items){
    if (!lootList) return;
    if (!items.length){
      lootList.innerHTML = '<div class="px-3 py-4 text-sm text-slate-400">No files found.</div>';
      return;
    }
    const rows = items.map(item => {
      const icon = item.type === 'dir' ? '📁' : '📄';
      const meta = item.type === 'dir' ? 'Folder' : `${formatBytes(item.size)} · ${formatTime(item.mtime)}`;
      const safeName = item.name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const encodedName = encodeURIComponent(item.name);
      return `
        <button class="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-slate-800/60 transition loot-item" data-type="${item.type}" data-name="${encodedName}">
          <span class="text-lg">${icon}</span>
          <div class="flex-1 min-w-0">
            <div class="text-sm text-slate-100 truncate">${safeName}</div>
            <div class="text-[11px] text-slate-400">${meta}</div>
          </div>
          <div class="text-xs text-slate-400">${item.type === 'dir' ? 'Open' : 'Download'}</div>
        </button>
      `;
    }).join('');
    lootList.innerHTML = rows;
  }

  async function loadLoot(path = ''){
    setLootStatus('Loading...');
    try{
      const url = getApiUrl('/api/loot/list', { path });
      const res = await fetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'Failed to load');
      }
      lootState = { path: data.path || '', parent: data.parent || '' };
      setLootPath(lootState.path);
      updateLootUp();
      renderLoot(data.items || []);
      setLootStatus('Ready');
    }catch(e){
      setLootStatus('Failed to load loot');
      renderLoot([]);
    }
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
  if (tabDevice) tabDevice.addEventListener('click', () => setActiveTab('device'));
  if (tabLoot) tabLoot.addEventListener('click', () => {
    setActiveTab('loot');
    if (lootList && !lootList.dataset.loaded){
      loadLoot('');
      lootList.dataset.loaded = '1';
    }
  });
  if (lootUpBtn) lootUpBtn.addEventListener('click', () => {
    if (lootState.parent !== undefined){
      loadLoot(lootState.parent || '');
    }
  });
  if (lootList) lootList.addEventListener('click', (e) => {
    const btn = e.target.closest('.loot-item');
    if (!btn) return;
    const encoded = btn.getAttribute('data-name') || '';
    const name = decodeURIComponent(encoded);
    const type = btn.getAttribute('data-type');
    const nextPath = buildLootPath(lootState.path, name);
    if (type === 'dir'){
      loadLoot(nextPath);
    } else {
      const url = getApiUrl('/api/loot/download', { path: nextPath });
      window.open(url, '_blank');
    }
  });
  applyTheme();
  setActiveTab('device');
  connect();
})();
