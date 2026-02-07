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
  const navDevice = document.getElementById('navDevice');
  const navLoot = document.getElementById('navLoot');
  const navPayloads = document.getElementById('navPayloads');
  const themesToggle = document.getElementById('themesToggle');
  const themesList = document.getElementById('themesList');
  const themeButtons = document.querySelectorAll('[data-theme]');
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebarBackdrop');
  const menuToggle = document.getElementById('menuToggle');
  const deviceTab = document.getElementById('deviceTab');
  const lootTab = document.getElementById('lootTab');
  const payloadsTab = document.getElementById('payloadsTab');
  const lootList = document.getElementById('lootList');
  const lootPathEl = document.getElementById('lootPath');
  const lootUpBtn = document.getElementById('lootUp');
  const lootStatus = document.getElementById('lootStatus');
  const lootPreview = document.getElementById('lootPreview');
  const lootPreviewTitle = document.getElementById('lootPreviewTitle');
  const lootPreviewBody = document.getElementById('lootPreviewBody');
  const lootPreviewClose = document.getElementById('lootPreviewClose');
  const lootPreviewDownload = document.getElementById('lootPreviewDownload');
  const lootPreviewMeta = document.getElementById('lootPreviewMeta');
  const payloadCategories = document.getElementById('payloadCategories');
  const payloadList = document.getElementById('payloadList');
  const payloadStatus = document.getElementById('payloadStatus');
  const payloadsRefresh = document.getElementById('payloadsRefresh');
  const payloadStop = document.getElementById('payloadStop');

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
  let payloadState = { categories: [], active: null };

  function setStatus(txt){
    if (statusEl) statusEl.textContent = txt;
    if (statusEls && statusEls.length) {
      statusEls.forEach(el => { el.textContent = txt; });
    }
  }

  function setPayloadStatus(txt){
    if (payloadStatus) payloadStatus.textContent = txt;
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
    themeButtons.forEach(btn => {
      const isActive = btn.getAttribute('data-theme') === t.id;
      btn.classList.toggle('bg-emerald-500/20', isActive);
      btn.classList.toggle('text-emerald-200', isActive);
      btn.classList.toggle('border-emerald-400/40', isActive);
      btn.classList.toggle('bg-slate-900/40', !isActive);
      btn.classList.toggle('text-slate-300', !isActive);
      btn.classList.toggle('border-slate-500/20', !isActive);
    });
  }

  function setSidebarOpen(open){
    if (!sidebar) return;
    sidebar.classList.toggle('-translate-x-full', !open);
    sidebar.classList.toggle('translate-x-0', open);
    if (sidebarBackdrop) {
      sidebarBackdrop.classList.toggle('hidden', !open);
    }
  }

  function setNavActive(btn, active){
    if (!btn) return;
    btn.classList.toggle('bg-emerald-500/10', active);
    btn.classList.toggle('text-emerald-300', active);
    btn.classList.toggle('border-emerald-400/30', active);
    btn.classList.toggle('shadow-[0_0_16px_rgba(16,185,129,0.15)]', active);
    btn.classList.toggle('bg-slate-800/40', !active);
    btn.classList.toggle('text-slate-300', !active);
    btn.classList.toggle('border-slate-400/20', !active);
  }

  function setActiveTab(tab){
    activeTab = tab;
    const isDevice = tab === 'device';
    if (deviceTab) deviceTab.classList.toggle('hidden', !isDevice);
    if (lootTab) lootTab.classList.toggle('hidden', tab !== 'loot');
    if (payloadsTab) payloadsTab.classList.toggle('hidden', tab !== 'payloads');
    setNavActive(navDevice, isDevice);
    setNavActive(navLoot, tab === 'loot');
    setNavActive(navPayloads, tab === 'payloads');
    setSidebarOpen(false);
  }

  function setThemeById(id){
    const idx = themes.findIndex(t => t.id === id);
    if (idx >= 0){
      themeIndex = idx;
      applyTheme();
    }
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
    const disabled = !lootState.path;
    lootUpBtn.disabled = disabled;
    lootUpBtn.classList.toggle('opacity-40', disabled);
    lootUpBtn.classList.toggle('cursor-not-allowed', disabled);
  }

  function openPreview({ title, content, meta, downloadUrl }){
    if (!lootPreview) return;
    if (lootPreviewTitle) lootPreviewTitle.textContent = title || 'Preview';
    if (lootPreviewBody) lootPreviewBody.textContent = content || '';
    if (lootPreviewMeta) lootPreviewMeta.textContent = meta || '';
    if (lootPreviewDownload) lootPreviewDownload.href = downloadUrl || '#';
    lootPreview.classList.remove('hidden');
  }

  function closePreview(){
    if (!lootPreview) return;
    lootPreview.classList.add('hidden');
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

  async function previewLootFile(path, name){
    setLootStatus('Loading preview...');
    try{
      const url = getApiUrl('/api/loot/view', { path });
      const res = await fetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'preview_failed');
      }
      const meta = `${formatBytes(data.size || 0)} · ${formatTime(data.mtime || 0)}${data.truncated ? ' · truncated' : ''}`;
      const downloadUrl = getApiUrl('/api/loot/download', { path });
      openPreview({
        title: name,
        content: data.content || '',
        meta,
        downloadUrl
      });
      setLootStatus('Ready');
    }catch(e){
      setLootStatus('Preview unavailable');
      const downloadUrl = getApiUrl('/api/loot/download', { path });
      window.open(downloadUrl, '_blank');
    }
  }

  async function loadPayloads(){
    setPayloadStatus('Loading...');
    try{
      const url = getApiUrl('/api/payloads/list');
      const res = await fetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'payloads_failed');
      }
      payloadState.categories = data.categories || [];
      if (!payloadState.active && payloadState.categories.length){
        payloadState.active = payloadState.categories[0].id;
      }
      renderPayloadCategories();
      renderPayloadList();
      setPayloadStatus('Ready');
    }catch(e){
      setPayloadStatus('Failed to load');
      if (payloadCategories) payloadCategories.innerHTML = '';
      if (payloadList) payloadList.innerHTML = '<div class="text-xs text-slate-500">No payloads available.</div>';
    }
  }

  function renderPayloadCategories(){
    if (!payloadCategories) return;
    const cats = payloadState.categories || [];
    if (!cats.length){
      payloadCategories.innerHTML = '<div class="text-xs text-slate-500">No categories.</div>';
      return;
    }
    payloadCategories.innerHTML = cats.map(cat => {
      const active = payloadState.active === cat.id;
      const base = 'w-full px-3 py-2 rounded-xl text-left text-xs font-semibold border transition';
      const cls = active
        ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.12)]'
        : 'border-slate-400/20 bg-slate-800/40 text-slate-300 hover:text-white hover:bg-slate-700/50';
      return `<button type="button" data-cat="${cat.id}" class="${base} ${cls}">${cat.label}</button>`;
    }).join('');
  }

  function renderPayloadList(){
    if (!payloadList) return;
    const cat = payloadState.categories.find(c => c.id === payloadState.active);
    if (!cat || !cat.items || !cat.items.length){
      payloadList.innerHTML = '<div class="text-xs text-slate-500">No payloads in this category.</div>';
      return;
    }
    payloadList.innerHTML = cat.items.map(item => `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/40 p-3 flex flex-col gap-2 shadow-[0_0_12px_rgba(15,23,42,0.35)]">
        <div class="text-sm font-semibold text-slate-100">${item.name}</div>
        <div class="text-[11px] text-slate-500">${cat.label}</div>
        <div class="flex items-center gap-2">
          <button type="button" data-start="${item.path}" class="px-3 py-1.5 text-xs rounded-lg bg-emerald-600/80 border border-emerald-300/30 text-white hover:bg-emerald-500/80 transition">Start</button>
          <button type="button" data-stop="1" class="px-3 py-1.5 text-xs rounded-lg bg-slate-800/70 border border-slate-600/40 text-slate-200 hover:bg-slate-700/70 transition">Stop</button>
        </div>
      </div>
    `).join('');
  }

  async function startPayload(path){
    setPayloadStatus('Starting...');
    try{
      const url = getApiUrl('/api/payloads/start');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        throw new Error(data && data.error ? data.error : 'start_failed');
      }
      setPayloadStatus('Launched');
    }catch(e){
      setPayloadStatus('Start failed');
    }
  }

  function sendInput(button, state){
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try{
      ws.send(JSON.stringify({ type: 'input', button, state }));
    }catch{}
  }

  function tapInput(button){
    sendInput(button, 'press');
    setTimeout(() => sendInput(button, 'release'), 120);
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
  if (navDevice) navDevice.addEventListener('click', () => setActiveTab('device'));
  if (navLoot) navLoot.addEventListener('click', () => {
    setActiveTab('loot');
    if (lootList && !lootList.dataset.loaded){
      loadLoot('');
      lootList.dataset.loaded = '1';
    }
  });
  if (navPayloads) navPayloads.addEventListener('click', () => {
    setActiveTab('payloads');
    if (payloadList && !payloadList.dataset.loaded){
      loadPayloads();
      payloadList.dataset.loaded = '1';
    }
  });
  if (themesToggle) themesToggle.addEventListener('click', () => {
    if (themesList) themesList.classList.toggle('hidden');
  });
  themeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-theme');
      if (id) setThemeById(id);
    });
  });
  if (menuToggle) menuToggle.addEventListener('click', () => setSidebarOpen(true));
  if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', () => setSidebarOpen(false));
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
      previewLootFile(nextPath, name);
    }
  });
  if (payloadCategories) payloadCategories.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-cat]');
    if (!btn) return;
    const id = btn.getAttribute('data-cat');
    if (!id) return;
    payloadState.active = id;
    renderPayloadCategories();
    renderPayloadList();
  });
  if (payloadList) payloadList.addEventListener('click', (e) => {
    const startBtn = e.target.closest('[data-start]');
    if (startBtn){
      const path = startBtn.getAttribute('data-start');
      if (path) startPayload(path);
      return;
    }
    const stopBtn = e.target.closest('[data-stop]');
    if (stopBtn){
      tapInput('KEY3');
    }
  });
  if (payloadsRefresh) payloadsRefresh.addEventListener('click', () => loadPayloads());
  if (payloadStop) payloadStop.addEventListener('click', () => tapInput('KEY3'));
  if (lootPreviewClose) lootPreviewClose.addEventListener('click', closePreview);
  if (lootPreview) lootPreview.addEventListener('click', (e) => {
    if (e.target === lootPreview) closePreview();
  });
  applyTheme();
  setActiveTab('device');
  connect();
})();
