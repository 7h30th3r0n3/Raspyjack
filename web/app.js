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
  const navSystem = document.getElementById('navSystem');
  const navLoot = document.getElementById('navLoot');
  const navSettings = document.getElementById('navSettings');
  const navPayloadStudio = document.getElementById('navPayloadStudio');
  const themeButtons = document.querySelectorAll('[data-theme]');
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebarBackdrop');
  const menuToggle = document.getElementById('menuToggle');
  const deviceTab = document.getElementById('deviceTab');
  const systemDropdown = document.getElementById('systemDropdown');
  const settingsTab = document.getElementById('settingsTab');
  const lootTab = document.getElementById('lootTab');
  const systemStatus = document.getElementById('systemStatus');
  const sysCpuValue = document.getElementById('sysCpuValue');
  const sysCpuBar = document.getElementById('sysCpuBar');
  const sysTempValue = document.getElementById('sysTempValue');
  const sysMemValue = document.getElementById('sysMemValue');
  const sysMemMeta = document.getElementById('sysMemMeta');
  const sysMemBar = document.getElementById('sysMemBar');
  const sysDiskValue = document.getElementById('sysDiskValue');
  const sysDiskMeta = document.getElementById('sysDiskMeta');
  const sysDiskBar = document.getElementById('sysDiskBar');
  const sysUptime = document.getElementById('sysUptime');
  const sysLoad = document.getElementById('sysLoad');
  const sysPayload = document.getElementById('sysPayload');
  const sysInterfaces = document.getElementById('sysInterfaces');
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
  const payloadSidebar = document.getElementById('payloadSidebar');
  const payloadStatus = document.getElementById('payloadStatus');
  const payloadStatusDot = document.getElementById('payloadStatusDot');
  const payloadsRefresh = document.getElementById('payloadsRefresh');
  const settingsStatus = document.getElementById('settingsStatus');
  const discordWebhookInput = document.getElementById('discordWebhookInput');
  const discordWebhookSave = document.getElementById('discordWebhookSave');
  const discordWebhookClear = document.getElementById('discordWebhookClear');
  const terminalEl = document.getElementById('terminal');
  const shellStatusEl = document.getElementById('shellStatus');
  const shellConnectBtn = document.getElementById('shellConnect');
  const shellDisconnectBtn = document.getElementById('shellDisconnect');
  const authModal = document.getElementById('authModal');
  const authModalTitle = document.getElementById('authModalTitle');
  const authModalMessage = document.getElementById('authModalMessage');
  const authModalUsername = document.getElementById('authModalUsername');
  const authModalPassword = document.getElementById('authModalPassword');
  const authModalPasswordConfirm = document.getElementById('authModalPasswordConfirm');
  const authModalToken = document.getElementById('authModalToken');
  const authModalError = document.getElementById('authModalError');
  const authModalToggleRecovery = document.getElementById('authModalToggleRecovery');
  const authModalConfirm = document.getElementById('authModalConfirm');
  const authModalCancel = document.getElementById('authModalCancel');
  const authModalClose = document.getElementById('authModalClose');

  // Build WS URL from current page host.
  function getWsUrl(){
    const p = new URLSearchParams(location.search);
    const host = location.hostname || 'raspberrypi.local';
    const port = p.get('port') || '8765';
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    return `${proto}://${host}:${port}/`.replace(/\/\/\//,'//');
  }

  function getApiUrl(path, params = {}){
    const qs = new URLSearchParams(params).toString();
    const base = location.origin;
    return `${base}${path}${qs ? `?${qs}` : ''}`;
  }

  function getForwardSearch(){
    try{
      const u = new URL(window.location.href);
      u.searchParams.delete('token');
      const qs = u.searchParams.toString();
      return qs ? `?${qs}` : '';
    }catch{
      return '';
    }
  }

  const AUTH_STORAGE_KEY = 'rj.authToken';
  let authToken = '';
  let wsTicket = '';
  let authPromptResolver = null;
  let authInFlight = null;
  let authMode = 'login';
  let authRecoveryMode = false;

  function saveAuthToken(token){
    authToken = String(token || '').trim();
    try{
      if (authToken){
        sessionStorage.setItem(AUTH_STORAGE_KEY, authToken);
      } else {
        sessionStorage.removeItem(AUTH_STORAGE_KEY);
      }
    }catch{}
  }

  function loadAuthToken(){
    try{
      const stored = (sessionStorage.getItem(AUTH_STORAGE_KEY) || '').trim();
      if (stored) authToken = stored;
    }catch{}

    // One-time migration: accept token from URL, then remove it.
    try{
      const u = new URL(window.location.href);
      const token = (u.searchParams.get('token') || '').trim();
      if (token){
        saveAuthToken(token);
        u.searchParams.delete('token');
        window.history.replaceState({}, '', u.toString());
      }
    }catch{}
  }

  function setAuthError(msg){
    if (!authModalError) return;
    const text = String(msg || '').trim();
    authModalError.textContent = text;
    authModalError.classList.toggle('hidden', !text);
  }

  function setAuthMode(mode, message){
    authMode = mode;
    if (authModalTitle){
      authModalTitle.textContent = mode === 'bootstrap' ? 'Create Admin Account' : 'Login Required';
    }
    if (authModalMessage){
      authModalMessage.textContent = message || (mode === 'bootstrap'
        ? 'Set the first admin account for this device.'
        : 'Log in to continue.');
    }
    const isBootstrap = mode === 'bootstrap';
    if (authModalPasswordConfirm) authModalPasswordConfirm.classList.toggle('hidden', !isBootstrap);
    if (authModalUsername) authModalUsername.classList.toggle('hidden', authRecoveryMode);
    if (authModalPassword) authModalPassword.classList.toggle('hidden', authRecoveryMode);
    if (authModalToken) authModalToken.classList.toggle('hidden', !authRecoveryMode);
    if (authModalToggleRecovery){
      authModalToggleRecovery.classList.toggle('hidden', isBootstrap);
      authModalToggleRecovery.textContent = authRecoveryMode ? 'Use username/password login' : 'Use recovery token instead';
    }
    if (authModalConfirm) authModalConfirm.textContent = isBootstrap ? 'Create Admin' : 'Login';
  }

  function setRecoveryMode(enabled){
    authRecoveryMode = !!enabled;
    setAuthMode(authMode, authModalMessage ? authModalMessage.textContent : '');
    setAuthError('');
    if (authRecoveryMode){
      if (authModalToken) authModalToken.focus();
    } else if (authModalUsername) {
      authModalUsername.focus();
    }
  }

  function resolveAuthPrompt(payload){
    if (!authPromptResolver) return;
    const resolver = authPromptResolver;
    authPromptResolver = null;
    if (authModal) authModal.classList.add('hidden');
    resolver(payload || null);
  }

  function promptForAuth(message, mode = 'login'){
    if (!authModal || !authModalConfirm || !authModalCancel || !authModalClose){
      return Promise.resolve(null);
    }
    if (authPromptResolver){
      return Promise.resolve(null);
    }
    if (authModalUsername) authModalUsername.value = '';
    if (authModalPassword) authModalPassword.value = '';
    if (authModalPasswordConfirm) authModalPasswordConfirm.value = '';
    if (authModalToken) authModalToken.value = authToken || '';
    authRecoveryMode = false;
    setAuthMode(mode, message);
    setAuthError('');
    authModal.classList.remove('hidden');
    setTimeout(() => {
      try {
        if (mode === 'bootstrap'){
          authModalUsername && authModalUsername.focus();
        } else if (authModalUsername) {
          authModalUsername.focus();
        }
      } catch {}
    }, 10);
    return new Promise(resolve => {
      authPromptResolver = resolve;
    });
  }

  function authHeaders(extra){
    const headers = Object.assign({}, extra || {});
    if (authToken){
      headers.Authorization = `Bearer ${authToken}`;
    }
    return headers;
  }

  async function apiFetch(url, options = {}, allowRetry = true){
    const merged = Object.assign({}, options);
    merged.headers = authHeaders(merged.headers);
    merged.credentials = 'include';
    const res = await fetch(url, merged);
    if (res.status === 401 && allowRetry){
      const ok = await ensureAuthenticated('Session expired. Log in again.');
      if (ok){
        return apiFetch(url, options, false);
      }
    }
    return res;
  }

  async function fetchBootstrapStatus(){
    try{
      const res = await fetch(getApiUrl('/api/auth/bootstrap-status'), { cache: 'no-store' });
      const data = await res.json();
      return !!(res.ok && data && data.initialized);
    }catch{
      return true;
    }
  }

  async function fetchAuthMe(){
    try{
      const res = await fetch(getApiUrl('/api/auth/me'), {
        cache: 'no-store',
        credentials: 'include',
        headers: authHeaders({}),
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data && data.authenticated ? data : null;
    }catch{
      return null;
    }
  }

  async function attemptBootstrap(message){
    const input = await promptForAuth(message || 'Set the first admin account for this device.', 'bootstrap');
    if (!input) return false;
    const username = String(input.username || '').trim();
    const password = String(input.password || '');
    const confirm = String(input.confirm || '');
    if (!username || !password){
      setAuthError('Username and password are required.');
      return attemptBootstrap(message);
    }
    if (password !== confirm){
      setAuthError('Passwords do not match.');
      return attemptBootstrap(message);
    }
    try{
      const res = await fetch(getApiUrl('/api/auth/bootstrap'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok){
        if (res.status === 409){
          return attemptLogin('Admin already exists. Log in to continue.');
        }
        setAuthError(data && data.error ? data.error : 'Bootstrap failed');
        return attemptBootstrap(message);
      }
      saveAuthToken('');
      return true;
    }catch{
      setAuthError('Bootstrap request failed.');
      return attemptBootstrap(message);
    }
  }

  async function attemptLogin(message){
    const input = await promptForAuth(message || 'Log in to continue.', 'login');
    if (!input) return false;

    if (input.recovery){
      const token = String(input.token || '').trim();
      if (!token){
        setAuthError('Recovery token is required.');
        return attemptLogin(message);
      }
      saveAuthToken(token);
      try{
        const meRes = await fetch(getApiUrl('/api/auth/me'), {
          cache: 'no-store',
          headers: authHeaders({}),
          credentials: 'include',
        });
        if (!meRes.ok){
          setAuthError('Invalid recovery token.');
          return attemptLogin(message);
        }
        return true;
      }catch{
        setAuthError('Recovery auth failed.');
        return attemptLogin(message);
      }
    }

    const username = String(input.username || '').trim();
    const password = String(input.password || '');
    if (!username || !password){
      setAuthError('Username and password are required.');
      return attemptLogin(message);
    }
    try{
      const res = await fetch(getApiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok){
        setAuthError(data && data.error ? data.error : 'Login failed');
        return attemptLogin(message);
      }
      saveAuthToken('');
      return true;
    }catch{
      setAuthError('Login request failed.');
      return attemptLogin(message);
    }
  }

  async function refreshWsTicket(){
    wsTicket = '';
    if (authToken) return;
    try{
      const res = await fetch(getApiUrl('/api/auth/ws-ticket'), {
        method: 'POST',
        credentials: 'include',
      });
      const data = await res.json();
      if (res.ok && data && data.ticket){
        wsTicket = String(data.ticket);
      }
    }catch{}
  }

  async function ensureAuthenticated(message){
    if (authInFlight){
      return authInFlight;
    }
    authInFlight = (async () => {
      const me = await fetchAuthMe();
      if (me){
        await refreshWsTicket();
        return true;
      }

    const initialized = await fetchBootstrapStatus();
    if (!initialized){
      const bootOk = await attemptBootstrap(message);
      if (!bootOk) return false;
      await refreshWsTicket();
      return true;
    }
    const loginOk = await attemptLogin(message);
    if (!loginOk) return false;
    await refreshWsTicket();
    return true;
    })();
    try{
      return await authInFlight;
    } finally {
      authInFlight = null;
    }
  }

  let ws = null;
  let reconnectTimer = null;
  const pressed = new Set(); // keyboard pressed state
  let activeTab = 'device';
  let lootState = { path: '', parent: '' };
  let payloadState = { categories: [], open: {}, activePath: null };
  let term = null;
  let fitAddon = null;
  let shellOpen = false;
  let terminalHasFocus = false;
  let shellWanted = false;
  let systemOpen = false;
  let wsAuthenticated = true;

  function setStatus(txt){
    if (statusEl) statusEl.textContent = txt;
    if (statusEls && statusEls.length) {
      statusEls.forEach(el => { el.textContent = txt; });
    }
  }

  function setPayloadStatus(txt){
    if (payloadStatus) payloadStatus.textContent = txt;
    if (payloadStatusDot){
      const active = /running|starting|stopping|launched/i.test(String(txt || ''));
      payloadStatusDot.classList.toggle('running', active);
    }
  }

  function setSystemStatus(txt){
    if (systemStatus) systemStatus.textContent = txt;
  }

  function setShellStatus(txt){
    if (shellStatusEl) shellStatusEl.textContent = txt;
  }

  function setSettingsStatus(txt){
    if (settingsStatus) settingsStatus.textContent = txt;
  }

  // Handheld themes (frontend-only)
  const themes = [
    { id: 'neon', label: 'Neon' },
    { id: 'gameboy', label: 'Game Boy' },
    { id: 'pager', label: 'Pager' },
  ];
  const THEME_STORAGE_KEY = 'rj.defaultTheme';
  let themeIndex = 0;

  function saveThemePreference(themeId){
    try{
      localStorage.setItem(THEME_STORAGE_KEY, themeId);
    }catch{}
  }

  function loadThemePreference(){
    try{
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (!saved) return;
      const idx = themes.findIndex(t => t.id === saved);
      if (idx >= 0) themeIndex = idx;
    }catch{}
  }

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
    if (settingsTab) settingsTab.classList.toggle('hidden', tab !== 'settings');
    if (lootTab) lootTab.classList.toggle('hidden', tab !== 'loot');
    setNavActive(navDevice, isDevice);
    setNavActive(navLoot, tab === 'loot');
    setNavActive(navSettings, tab === 'settings');
    setSidebarOpen(false);
  }

  function setSystemOpen(open){
    systemOpen = !!open;
    if (systemDropdown){
      systemDropdown.classList.toggle('hidden', !systemOpen);
    }
    setNavActive(navSystem, systemOpen);
    if (systemOpen){
      loadSystemStatus();
    }
  }

  function setThemeById(id){
    const idx = themes.findIndex(t => t.id === id);
    if (idx >= 0){
      themeIndex = idx;
      applyTheme();
      saveThemePreference(id);
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
      wsAuthenticated = true;
      if (wsTicket){
        try{
          ws.send(JSON.stringify({ type: 'auth_session', ticket: wsTicket }));
        }catch{}
      } else if (authToken){
        try{
          ws.send(JSON.stringify({ type: 'auth', token: authToken }));
        }catch{}
      }
      if (shellWanted) {
        sendShellOpen();
      }
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
          return;
        }
        if (msg.type === 'auth_required'){
          wsAuthenticated = false;
          if (wsTicket){
            try{
              ws.send(JSON.stringify({ type: 'auth_session', ticket: wsTicket }));
            }catch{}
            return;
          }
          if (authToken){
            try{
              ws.send(JSON.stringify({ type: 'auth', token: authToken }));
            }catch{}
            return;
          }
          ensureAuthenticated('Authentication required to use WebSocket.')
            .then(() => {
              if (!ws || ws.readyState !== WebSocket.OPEN) return;
              if (wsTicket){
                try{
                  ws.send(JSON.stringify({ type: 'auth_session', ticket: wsTicket }));
                }catch{}
              } else if (authToken){
                try{
                  ws.send(JSON.stringify({ type: 'auth', token: authToken }));
                }catch{}
              }
            });
          return;
        }
        if (msg.type === 'auth_ok'){
          wsAuthenticated = true;
          setStatus('Authenticated');
          if (shellWanted) sendShellOpen();
          return;
        }
        if (msg.type === 'auth_error'){
          wsAuthenticated = false;
          setStatus('Auth failed');
          return;
        }
        if (msg.type === 'shell_ready'){
          shellOpen = true;
          setShellStatus('Connected');
          sendShellResize();
          return;
        }
        if (msg.type === 'shell_out' && msg.data){
          ensureTerminal();
          if (term) term.write(msg.data);
          return;
        }
        if (msg.type === 'shell_exit'){
          shellOpen = false;
          setShellStatus('Exited');
        }
      }catch{}
    };

    ws.onclose = () => {
      setStatus('Disconnected – reconnecting…');
      setShellStatus('Disconnected');
      shellOpen = false;
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

  function ensureTerminal(){
    if (!terminalEl) return null;
    if (!window.Terminal){
      setShellStatus('xterm missing');
      return null;
    }
    if (!term){
      term = new window.Terminal({
        cursorBlink: true,
        fontSize: 13,
        theme: {
          background: 'transparent',
          foreground: '#e2e8f0',
          cursor: '#94a3b8'
        }
      });
      if (window.FitAddon && window.FitAddon.FitAddon){
        fitAddon = new window.FitAddon.FitAddon();
        term.loadAddon(fitAddon);
      }
      term.open(terminalEl);
      term.onData(data => sendShellInput(data));
      if (terminalEl){
        terminalEl.addEventListener('focusin', () => { terminalHasFocus = true; });
        terminalEl.addEventListener('focusout', () => { terminalHasFocus = false; });
        terminalEl.addEventListener('mousedown', () => {
          try { term.focus(); } catch {}
        });
      }
      if (fitAddon){
        try { fitAddon.fit(); } catch {}
      }
      term.write('RaspyJack shell ready.\\r\\n');
    }
    return term;
  }

  function sendShellInput(data){
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!shellOpen) return;
    try{
      ws.send(JSON.stringify({ type: 'shell_in', data }));
    }catch{}
  }

  function sendShellOpen(){
    shellWanted = true;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ensureTerminal();
    setShellStatus('Opening...');
    try{
      ws.send(JSON.stringify({ type: 'shell_open' }));
    }catch{}
  }

  function sendShellClose(){
    shellWanted = false;
    if (ws && ws.readyState === WebSocket.OPEN){
      try{
        ws.send(JSON.stringify({ type: 'shell_close' }));
      }catch{}
    }
    shellOpen = false;
    setShellStatus('Closed');
  }

  function sendShellResize(){
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (!shellOpen || !term) return;
    if (fitAddon){
      try { fitAddon.fit(); } catch {}
    }
    try{
      ws.send(JSON.stringify({ type: 'shell_resize', cols: term.cols, rows: term.rows }));
    }catch{}
  }

  function formatBytes(bytes){
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    const value = bytes / Math.pow(k, i);
    return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${sizes[i]}`;
  }

  function formatDuration(totalSec){
    const s = Math.max(0, Number(totalSec || 0) | 0);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function pct(used, total){
    if (!total || total <= 0) return 0;
    return Math.max(0, Math.min(100, (used / total) * 100));
  }

  function bar(el, value){
    if (!el) return;
    el.style.width = `${Math.max(0, Math.min(100, value)).toFixed(1)}%`;
  }

  async function loadSystemStatus(){
    setSystemStatus('Loading...');
    try{
      const url = getApiUrl('/api/system/status');
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'system_failed');
      }

      const cpu = Number(data.cpu_percent || 0);
      const memUsed = Number(data.mem_used || 0);
      const memTotal = Number(data.mem_total || 0);
      const diskUsed = Number(data.disk_used || 0);
      const diskTotal = Number(data.disk_total || 0);
      const memPct = pct(memUsed, memTotal);
      const diskPct = pct(diskUsed, diskTotal);

      if (sysCpuValue) sysCpuValue.textContent = `${cpu.toFixed(1)}%`;
      if (sysTempValue) {
        if (data.temp_c === null || data.temp_c === undefined){
          sysTempValue.textContent = '--.- C';
        } else {
          sysTempValue.textContent = `${Number(data.temp_c).toFixed(1)} C`;
        }
      }
      bar(sysCpuBar, cpu);

      if (sysMemValue) sysMemValue.textContent = `${memPct.toFixed(1)}%`;
      if (sysMemMeta) sysMemMeta.textContent = `${formatBytes(memUsed)} / ${formatBytes(memTotal)}`;
      bar(sysMemBar, memPct);

      if (sysDiskValue) sysDiskValue.textContent = `${diskPct.toFixed(1)}%`;
      if (sysDiskMeta) sysDiskMeta.textContent = `${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`;
      bar(sysDiskBar, diskPct);

      if (sysUptime) sysUptime.textContent = formatDuration(data.uptime_s);
      if (sysLoad) sysLoad.textContent = Array.isArray(data.load) ? data.load.join(', ') : '-';
      if (sysPayload) sysPayload.textContent = data.payload_running ? (data.payload_path || 'running') : 'none';

      if (sysInterfaces){
        const ifaces = Array.isArray(data.interfaces) ? data.interfaces : [];
        if (!ifaces.length){
          sysInterfaces.innerHTML = '<div class="text-slate-500">No active interfaces</div>';
        } else {
          sysInterfaces.innerHTML = ifaces
            .map(i => `<div><span class="text-emerald-300">${String(i.name || '-')}</span>: ${String(i.ipv4 || '-')}</div>`)
            .join('');
        }
      }

      setSystemStatus('Live');
    } catch (e){
      setSystemStatus('Unavailable');
    }
  }

  async function loadDiscordWebhook(){
    setSettingsStatus('Loading...');
    try{
      const url = getApiUrl('/api/settings/discord_webhook');
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'settings_failed');
      }
      if (discordWebhookInput) discordWebhookInput.value = String(data.url || '');
      setSettingsStatus(data.configured ? 'Webhook configured' : 'No webhook configured');
    } catch(e){
      setSettingsStatus('Failed to load settings');
    }
  }

  async function saveDiscordWebhook(url){
    setSettingsStatus('Saving...');
    try{
      const endpoint = getApiUrl('/api/settings/discord_webhook');
      const res = await apiFetch(endpoint, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: String(url || '').trim() }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        throw new Error(data && data.error ? data.error : 'save_failed');
      }
      setSettingsStatus(data.status === 'cleared' ? 'Webhook cleared' : 'Webhook saved');
    } catch(e){
      setSettingsStatus('Failed to save webhook');
    }
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
      const res = await apiFetch(url, { cache: 'no-store' });
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
      const res = await apiFetch(url, { cache: 'no-store' });
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
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'payloads_failed');
      }
      payloadState.categories = data.categories || [];
      payloadState.categories.forEach((cat, idx) => {
        if (payloadState.open[cat.id] === undefined) {
          payloadState.open[cat.id] = idx === 0;
        }
      });
      renderPayloadSidebar();
      setPayloadStatus('Ready');
    }catch(e){
      setPayloadStatus('Failed to load');
      if (payloadSidebar) payloadSidebar.innerHTML = '<div class="text-xs text-slate-500 px-2">No payloads available.</div>';
    }
  }

  function renderPayloadSidebar(){
    if (!payloadSidebar) return;
    const cats = payloadState.categories || [];
    if (!cats.length){
      payloadSidebar.innerHTML = '<div class="text-xs text-slate-500 px-2">No categories.</div>';
      return;
    }
    payloadSidebar.innerHTML = cats.map(cat => {
      const isOpen = payloadState.open[cat.id];
      const items = (cat.items || []).map(item => `
        <div class="flex items-center justify-between gap-2 px-2 py-1 rounded-lg bg-slate-900/40 border border-slate-800/70">
          <div class="text-[11px] text-slate-200 truncate">${item.name}</div>
          ${(() => {
            const isActive = payloadState.activePath === item.path;
            const disabled = !!payloadState.activePath;
            const startCls = disabled
              ? 'px-2 py-0.5 text-[10px] rounded-md bg-slate-800/80 border border-slate-700/40 text-slate-500 cursor-not-allowed'
              : 'px-2 py-0.5 text-[10px] rounded-md bg-emerald-600/80 border border-emerald-300/30 text-white hover:bg-emerald-500/80 transition';
            const stopBtn = isActive
              ? '<button type="button" data-stop="1" class="px-2 py-0.5 text-[10px] rounded-md bg-rose-600/80 border border-rose-300/30 text-white hover:bg-rose-500/80 transition">Stop</button>'
              : '<span class="px-2 py-0.5 text-[10px] rounded-md bg-slate-900/60 border border-slate-800/40 text-slate-600">Idle</span>';
            return `
          <div class="flex items-center gap-1">
            <button type="button" data-start="${item.path}" ${disabled ? 'disabled' : ''} class="${startCls}">Start</button>
            ${stopBtn}
          </div>`;
          })()}
        </div>
      `).join('');
      return `
        <div class="rounded-xl border border-slate-800/70 bg-slate-950/40">
          <button type="button" data-cat="${cat.id}" class="w-full px-3 py-2 text-left text-xs font-semibold text-slate-200 flex items-center justify-between">
            <span>${cat.label}</span>
            <span class="text-slate-400">${isOpen ? '▾' : '▸'}</span>
          </button>
          <div class="${isOpen ? '' : 'hidden'} px-2 pb-2 space-y-1">
            ${items || '<div class="text-[11px] text-slate-500 px-1">Empty</div>'}
          </div>
        </div>
      `;
    }).join('');
  }

  async function startPayload(path){
    setPayloadStatus('Starting...');
    try{
      const url = getApiUrl('/api/payloads/start');
      const res = await apiFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        throw new Error(data && data.error ? data.error : 'start_failed');
      }
      payloadState.activePath = path;
      renderPayloadSidebar();
      setPayloadStatus('Launched');
    }catch(e){
      setPayloadStatus('Start failed');
    }
  }

  async function pollPayloadStatus(){
    try{
      const url = getApiUrl('/api/payloads/status');
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        return;
      }
      const running = !!data.running;
      const path = running ? (data.path || null) : null;
      if (payloadState.activePath !== path){
        payloadState.activePath = path;
        renderPayloadSidebar();
      }
      setPayloadStatus(running ? 'Running' : 'Ready');
    }catch(e){
      setPayloadStatus('Ready');
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
      if (terminalHasFocus) return;
      const btn = KEYMAP.get(e.code) || KEYMAP.get(e.key);
      if (!btn) return;
      if (pressed.has(btn)) return; // avoid repeats
      pressed.add(btn);
      sendInput(btn, 'press');
      e.preventDefault();
    });
    window.addEventListener('keyup', (e)=>{
      if (terminalHasFocus) return;
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
  if (shellConnectBtn) shellConnectBtn.addEventListener('click', sendShellOpen);
  if (shellDisconnectBtn) shellDisconnectBtn.addEventListener('click', sendShellClose);
  window.addEventListener('resize', () => {
    if (shellOpen) sendShellResize();
  });
  if (navDevice) navDevice.addEventListener('click', () => setActiveTab('device'));
  if (navSystem) navSystem.addEventListener('click', () => {
    setSystemOpen(!systemOpen);
  });
  if (navLoot) navLoot.addEventListener('click', () => {
    setActiveTab('loot');
    if (lootList && !lootList.dataset.loaded){
      loadLoot('');
      lootList.dataset.loaded = '1';
    }
  });
  if (navSettings) navSettings.addEventListener('click', () => {
    setActiveTab('settings');
    loadDiscordWebhook();
  });
  if (navPayloadStudio) navPayloadStudio.href = './ide.html' + getForwardSearch();
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
  if (payloadSidebar) payloadSidebar.addEventListener('click', (e) => {
    const catBtn = e.target.closest('[data-cat]');
    if (catBtn){
      const id = catBtn.getAttribute('data-cat');
      if (id){
        payloadState.open[id] = !payloadState.open[id];
        renderPayloadSidebar();
      }
      return;
    }
    const startBtn = e.target.closest('[data-start]');
    if (startBtn){
      const path = startBtn.getAttribute('data-start');
      if (path) startPayload(path);
      return;
    }
    const stopBtn = e.target.closest('[data-stop]');
    if (stopBtn){
      setPayloadStatus('Stopping...');
      tapInput('KEY3');
    }
  });
  if (payloadsRefresh) payloadsRefresh.addEventListener('click', () => loadPayloads());
  if (discordWebhookSave) discordWebhookSave.addEventListener('click', () => {
    saveDiscordWebhook(discordWebhookInput ? discordWebhookInput.value : '');
  });
  if (discordWebhookClear) discordWebhookClear.addEventListener('click', () => {
    if (discordWebhookInput) discordWebhookInput.value = '';
    saveDiscordWebhook('');
  });
  if (lootPreviewClose) lootPreviewClose.addEventListener('click', closePreview);
  if (lootPreview) lootPreview.addEventListener('click', (e) => {
    if (e.target === lootPreview) closePreview();
  });
  if (authModalConfirm) authModalConfirm.addEventListener('click', () => {
    resolveAuthPrompt({
      recovery: authRecoveryMode,
      token: authModalToken ? authModalToken.value : '',
      username: authModalUsername ? authModalUsername.value : '',
      password: authModalPassword ? authModalPassword.value : '',
      confirm: authModalPasswordConfirm ? authModalPasswordConfirm.value : '',
    });
  });
  if (authModalCancel) authModalCancel.addEventListener('click', () => resolveAuthPrompt(null));
  if (authModalClose) authModalClose.addEventListener('click', () => resolveAuthPrompt(null));
  if (authModal) authModal.addEventListener('click', (e) => {
    if (e.target === authModal) resolveAuthPrompt(null);
  });
  if (authModalToggleRecovery) authModalToggleRecovery.addEventListener('click', () => {
    setRecoveryMode(!authRecoveryMode);
  });
  const authSubmitFromEnter = (e) => {
    if (e.key === 'Enter'){
      e.preventDefault();
      resolveAuthPrompt({
        recovery: authRecoveryMode,
        token: authModalToken ? authModalToken.value : '',
        username: authModalUsername ? authModalUsername.value : '',
        password: authModalPassword ? authModalPassword.value : '',
        confirm: authModalPasswordConfirm ? authModalPasswordConfirm.value : '',
      });
    } else if (e.key === 'Escape'){
      e.preventDefault();
      resolveAuthPrompt(null);
    }
  };
  if (authModalToken) authModalToken.addEventListener('keydown', authSubmitFromEnter);
  if (authModalUsername) authModalUsername.addEventListener('keydown', authSubmitFromEnter);
  if (authModalPassword) authModalPassword.addEventListener('keydown', authSubmitFromEnter);
  if (authModalPasswordConfirm) authModalPasswordConfirm.addEventListener('keydown', authSubmitFromEnter);
  loadAuthToken();
  loadThemePreference();
  applyTheme();
  setActiveTab('device');
  const startAfterAuth = () => {
    ensureAuthenticated('Log in to access RaspyJack WebUI.').then((ok) => {
      if (!ok){
        setTimeout(startAfterAuth, 0);
        return;
      }
      connect();
      loadPayloads();
      setInterval(pollPayloadStatus, 1500);
      setInterval(() => {
        if (systemOpen){
          loadSystemStatus();
        }
      }, 3000);
    });
  };
  startAfterAuth();
})();
