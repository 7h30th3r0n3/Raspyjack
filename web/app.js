(function(){
  const shared = window.RJShared || {};
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
  const nmapVizModal = document.getElementById('nmapVizModal');
  const nmapVizTitle = document.getElementById('nmapVizTitle');
  const nmapVizMeta = document.getElementById('nmapVizMeta');
  const nmapVizStatus = document.getElementById('nmapVizStatus');
  const nmapVizBody = document.getElementById('nmapVizBody');
  const nmapVizError = document.getElementById('nmapVizError');
  const nmapVizClose = document.getElementById('nmapVizClose');
  const nmapVizDownloadXml = document.getElementById('nmapVizDownloadXml');
  const nmapVizDownloadJson = document.getElementById('nmapVizDownloadJson');
  const nmapVizFilterVuln = document.getElementById('nmapVizFilterVuln');
  const payloadSidebar = document.getElementById('payloadSidebar');
  const payloadStatus = document.getElementById('payloadStatus');
  const payloadStatusDot = document.getElementById('payloadStatusDot');
  const payloadsRefresh = document.getElementById('payloadsRefresh');
  const settingsStatus = document.getElementById('settingsStatus');
  const discordWebhookInput = document.getElementById('discordWebhookInput');
  const discordWebhookSave = document.getElementById('discordWebhookSave');
  const discordWebhookClear = document.getElementById('discordWebhookClear');
  const tailscaleSettingsStatus = document.getElementById('tailscaleSettingsStatus');
  const tailscaleInstallBtn = document.getElementById('tailscaleInstallBtn');
  const tailscaleReauthBtn = document.getElementById('tailscaleReauthBtn');
  const tailscaleModal = document.getElementById('tailscaleModal');
  const tailscaleKeyInput = document.getElementById('tailscaleKeyInput');
  const tailscaleModalError = document.getElementById('tailscaleModalError');
  const tailscaleModalStatus = document.getElementById('tailscaleModalStatus');
  const tailscaleModalSave = document.getElementById('tailscaleModalSave');
  const tailscaleModalCancel = document.getElementById('tailscaleModalCancel');
  const tailscaleModalClose = document.getElementById('tailscaleModalClose');
  const terminalEl = document.getElementById('terminal');
  const shellStatusEl = document.getElementById('shellStatus');
  const shellConnectBtn = document.getElementById('shellConnect');
  const shellDisconnectBtn = document.getElementById('shellDisconnect');
  const logoutBtn = document.getElementById('logoutBtn');
  const authModal = document.getElementById('authModal');
  const authModalTitle = document.getElementById('authModalTitle');
  const authModalMessage = document.getElementById('authModalMessage');
  const authModalUsername = document.getElementById('authModalUsername');
  const authModalPassword = document.getElementById('authModalPassword');
  const authModalPasswordConfirm = document.getElementById('authModalPasswordConfirm');
  const authModalToken = document.getElementById('authModalToken');
  const authModalRules = document.getElementById('authModalRules');
  const authModalError = document.getElementById('authModalError');
  const authModalToggleRecovery = document.getElementById('authModalToggleRecovery');
  const authModalConfirm = document.getElementById('authModalConfirm');
  const authModalCancel = document.getElementById('authModalCancel');
  const authModalClose = document.getElementById('authModalClose');

  // Build WS URL from current page host.
  function getWsUrl(){
    if (shared.getWsUrl) return shared.getWsUrl(location);
    if (location.protocol === 'https:'){
      return `${location.origin.replace(/^https:/, 'wss:')}/ws`;
    }
    const p = new URLSearchParams(location.search);
    const host = location.hostname || 'raspberrypi.local';
    const port = p.get('port') || '8765';
    return `ws://${host}:${port}/`.replace(/\/\/\//,'//');
  }

  function getApiUrl(path, params = {}){
    if (shared.getApiUrl) return shared.getApiUrl(path, params, location);
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

  function escapeHtml(value){
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function encodeData(value){
    return encodeURIComponent(String(value ?? ''));
  }

  const AUTH_STORAGE_KEY = 'rj.authToken';
  let authToken = '';
  let wsTicket = '';
  let authPromptResolver = null;
  let authInFlight = null;
  let authMode = 'login';
  let authRecoveryMode = false;
  let tailscaleReauthMode = false;

  function saveAuthToken(token){
    if (shared.saveToken){
      authToken = shared.saveToken(AUTH_STORAGE_KEY, token);
      return;
    }
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
    if (shared.loadToken){
      const stored = shared.loadToken(AUTH_STORAGE_KEY);
      if (stored) authToken = stored;
    } else {
      try{
        const stored = (sessionStorage.getItem(AUTH_STORAGE_KEY) || '').trim();
        if (stored) authToken = stored;
      }catch{}
    }

    const migrated = shared.migrateTokenFromUrl ? shared.migrateTokenFromUrl(AUTH_STORAGE_KEY, 'token') : '';
    if (migrated) authToken = migrated;
    if (migrated) return;

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
    if (authModalRules) authModalRules.classList.toggle('hidden', !isBootstrap);
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
    if (shared.authHeaders) return shared.authHeaders(authToken, extra);
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
    if (shared.fetchBootstrapStatus){
      return shared.fetchBootstrapStatus(getApiUrl.bind(null));
    }
    try{
      const res = await fetch(getApiUrl('/api/auth/bootstrap-status'), { cache: 'no-store' });
      const data = await res.json();
      return !!(res.ok && data && data.initialized);
    }catch{
      return true;
    }
  }

  async function fetchAuthMe(){
    if (shared.fetchAuthMe){
      return shared.fetchAuthMe(getApiUrl.bind(null), authToken);
    }
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
    if (username.length < 3){
      setAuthError('username must be at least 3 characters');
      return attemptBootstrap(message);
    }
    if (username.length > 32){
      setAuthError('username too long');
      return attemptBootstrap(message);
    }
    if (password.length < 8){
      setAuthError('password must be at least 8 characters');
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
    if (shared.refreshWsTicket){
      wsTicket = await shared.refreshWsTicket(getApiUrl.bind(null), authToken);
      return;
    }
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

  async function logoutUser(){
    try{
      await fetch(getApiUrl('/api/auth/logout'), { method: 'POST', credentials: 'include' });
    }catch{}
    saveAuthToken('');
    wsTicket = '';
    try{
      if (ws) ws.close();
    }catch{}
    window.location.reload();
  }

  let ws = null;
  let reconnectTimer = null;
  const pressed = new Set(); // keyboard pressed state
  let activeTab = 'device';
  let lootState = { path: '', parent: '' };
  let nmapVizState = { data: null, jsonUrl: '' };
  let payloadState = { categories: [], open: {}, activePath: null };
  let term = null;
  let fitAddon = null;
  let shellOpen = false;
  let terminalHasFocus = false;
  let shellWanted = false;
  let systemOpen = false;
  let wsAuthenticated = true;

  function applyStatusTone(el, txt){
    if (!el) return;
    const s = String(txt || '').toLowerCase();
    el.classList.remove('status-tone-ok', 'status-tone-warn', 'status-tone-bad');
    if (/connected|authenticated|ready|live|saved|configured|launched|running/.test(s)) {
      el.classList.add('status-tone-ok');
    } else if (/loading|connecting|opening|reconnecting|stopping/.test(s)) {
      el.classList.add('status-tone-warn');
    } else if (/failed|unavailable|disconnected|error|denied/.test(s)) {
      el.classList.add('status-tone-bad');
    }
  }

  function setStatus(txt){
    if (statusEl) {
      statusEl.textContent = txt;
      applyStatusTone(statusEl, txt);
    }
    if (statusEls && statusEls.length) {
      statusEls.forEach(el => {
        el.textContent = txt;
        applyStatusTone(el, txt);
      });
    }
  }

  function setPayloadStatus(txt){
    if (payloadStatus) {
      payloadStatus.textContent = txt;
      applyStatusTone(payloadStatus, txt);
    }
    if (payloadStatusDot){
      const active = /running|starting|stopping|launched/i.test(String(txt || ''));
      payloadStatusDot.classList.toggle('running', active);
    }
  }

  function setSystemStatus(txt){
    if (systemStatus) {
      systemStatus.textContent = txt;
      applyStatusTone(systemStatus, txt);
    }
  }

  function setShellStatus(txt){
    if (shellStatusEl) {
      shellStatusEl.textContent = txt;
      applyStatusTone(shellStatusEl, txt);
    }
  }

  function setSettingsStatus(txt){
    if (settingsStatus) {
      settingsStatus.textContent = txt;
      applyStatusTone(settingsStatus, txt);
    }
  }

  function setTailscaleStatus(txt){
    if (tailscaleSettingsStatus){
      tailscaleSettingsStatus.textContent = txt;
      applyStatusTone(tailscaleSettingsStatus, txt);
    }
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
    btn.classList.toggle('nav-active', active);
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
            .map(i => `<div><span class="text-emerald-300">${escapeHtml(String(i.name || '-'))}</span>: ${escapeHtml(String(i.ipv4 || '-'))}</div>`)
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

  function applyTailscaleDataToUI(data){
    if (!tailscaleSettingsStatus) return;
    const installed = !!data.installed;
    const installing = !!data.installing;
    const backendState = data.backend_state || (installed ? 'Unknown' : 'Not installed');

    if (tailscaleInstallBtn){
      const installingNow = !!installing && !installed;
      tailscaleInstallBtn.classList.toggle('hidden', installed);
      tailscaleInstallBtn.disabled = installingNow;
      tailscaleInstallBtn.classList.toggle('opacity-50', installingNow);
      tailscaleInstallBtn.classList.toggle('cursor-not-allowed', installingNow);
    }
    if (tailscaleReauthBtn){
      const showReauth = installed;
      const disabledReauth = !!installing;
      tailscaleReauthBtn.classList.toggle('hidden', !showReauth);
      tailscaleReauthBtn.disabled = disabledReauth;
      tailscaleReauthBtn.classList.toggle('opacity-50', disabledReauth);
      tailscaleReauthBtn.classList.toggle('cursor-not-allowed', disabledReauth);
    }

    if (installing){
      setTailscaleStatus('Installing Tailscale…');
    } else if (!installed){
      setTailscaleStatus('Not installed');
    } else {
      setTailscaleStatus(`Installed (state: ${backendState || 'Running'})`);
    }
  }

  async function loadTailscaleSettings(skipLoadingState){
    if (!tailscaleSettingsStatus) return;
    if (!skipLoadingState) setTailscaleStatus('Loading...');
    try{
      const url = getApiUrl('/api/settings/tailscale');
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'tailscale_failed');
      }
      applyTailscaleDataToUI(data);
    } catch(e){
      setTailscaleStatus('Failed to load Tailscale');
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

  function openTailscaleModal(){
    if (!tailscaleModal) return;
    if (tailscaleKeyInput) tailscaleKeyInput.value = '';
    if (tailscaleModalError){
      tailscaleModalError.textContent = '';
      tailscaleModalError.classList.add('hidden');
    }
    if (tailscaleModalStatus) tailscaleModalStatus.textContent = '';
    tailscaleModal.classList.remove('hidden');
    if (tailscaleKeyInput) tailscaleKeyInput.focus();
  }

  function closeTailscaleModal(){
    if (!tailscaleModal) return;
    tailscaleModal.classList.add('hidden');
  }

  let tailscaleInstallPollTimer = null;

  function startTailscaleInstallPoll(){
    if (tailscaleInstallPollTimer) clearInterval(tailscaleInstallPollTimer);
    const poll = async () => {
      try{
        const url = getApiUrl('/api/settings/tailscale');
        const res = await apiFetch(url, { cache: 'no-store' });
        const data = await res.json();
        if (!res.ok) return;
        applyTailscaleDataToUI(data);
        const installed = !!data.installed;
        const installing = !!data.installing;
        if (installed && !installing){
          clearInterval(tailscaleInstallPollTimer);
          tailscaleInstallPollTimer = null;
        }
      }catch(e){
        // ignore poll errors; next interval will retry
      }
    };
    tailscaleInstallPollTimer = setInterval(poll, 2000);
    poll();
  }

  async function submitTailscaleInstall(){
    if (!tailscaleKeyInput) return;
    const key = String(tailscaleKeyInput.value || '').trim();
    if (!key){
      if (tailscaleModalError){
        tailscaleModalError.textContent = 'Auth key required';
        tailscaleModalError.classList.remove('hidden');
      }
      return;
    }
    if (!key.startsWith('tskey-')){
      if (tailscaleModalError){
        tailscaleModalError.textContent = "Auth key must start with 'tskey-'.";
        tailscaleModalError.classList.remove('hidden');
      }
      return;
    }
    if (tailscaleModalError){
      tailscaleModalError.textContent = '';
      tailscaleModalError.classList.add('hidden');
    }
    if (tailscaleModalStatus) tailscaleModalStatus.textContent = tailscaleReauthMode ? 'Starting re-auth…' : 'Starting install…';
    const setDisabled = (flag) => {
      if (tailscaleKeyInput) tailscaleKeyInput.disabled = flag;
      if (tailscaleModalSave) tailscaleModalSave.disabled = flag;
      if (tailscaleModalCancel) tailscaleModalCancel.disabled = flag;
    };
    setDisabled(true);
    try{
      const endpoint = getApiUrl('/api/settings/tailscale');
      const res = await apiFetch(endpoint, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auth_key: key, reauth: tailscaleReauthMode }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        const msg = data && data.error ? data.error : 'install_failed';
        throw new Error(msg);
      }
      if (tailscaleModalStatus) tailscaleModalStatus.textContent = tailscaleReauthMode ? 'Re-authenticating…' : 'Installing Tailscale…';
      closeTailscaleModal();
      setTailscaleStatus(tailscaleReauthMode ? 'Re-authenticating…' : 'Installing Tailscale…');
      startTailscaleInstallPoll();
    } catch(e){
      const msg = e && e.message ? e.message : 'Failed to start install';
      if (tailscaleModalError){
        tailscaleModalError.textContent = msg;
        tailscaleModalError.classList.remove('hidden');
      }
    } finally{
      setDisabled(false);
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

  function setNmapVizStatus(text){
    if (!nmapVizStatus) return;
    nmapVizStatus.textContent = text || 'Ready';
    applyStatusTone(nmapVizStatus, text || 'Ready');
  }

  function setNmapVizError(message){
    if (!nmapVizError) return;
    const text = String(message || '').trim();
    nmapVizError.textContent = text;
    nmapVizError.classList.toggle('hidden', !text);
  }

  function revokeNmapJsonUrl(){
    if (!nmapVizState.jsonUrl) return;
    try { URL.revokeObjectURL(nmapVizState.jsonUrl); } catch {}
    nmapVizState.jsonUrl = '';
  }

  function closeNmapViz(){
    if (!nmapVizModal) return;
    nmapVizModal.classList.add('hidden');
    setNmapVizError('');
    setNmapVizStatus('Ready');
  }

  function hasStructuredData(value){
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === 'object') return Object.keys(value).length > 0;
    return value !== null && value !== undefined && value !== '';
  }

  function formatSeverityLabel(value){
    const text = String(value || 'unknown').toLowerCase();
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function getSeverityClasses(value){
    const severity = String(value || 'unknown').toLowerCase();
    if (severity === 'critical') return 'border-rose-400/30 bg-rose-500/15 text-rose-200';
    if (severity === 'high') return 'border-orange-400/30 bg-orange-500/15 text-orange-200';
    if (severity === 'medium') return 'border-amber-400/30 bg-amber-500/15 text-amber-200';
    if (severity === 'low') return 'border-sky-400/30 bg-sky-500/15 text-sky-200';
    return 'border-slate-500/30 bg-slate-800/60 text-slate-300';
  }

  function formatScriptContext(script){
    if (!script || !script.context) return 'Host script';
    if (script.context.scope === 'port'){
      const port = script.context.port ?? '?';
      const proto = script.context.protocol || '?';
      return `Port ${port}/${proto}`;
    }
    return 'Host script';
  }

  function toPrettyJson(value){
    try{
      return JSON.stringify(value, null, 2);
    }catch{
      return String(value || '');
    }
  }

  function isNmapLootXml(parentPath, name){
    const current = String(parentPath || '');
    const fileName = String(name || '');
    return /\.xml$/i.test(fileName) && (current === 'Nmap' || current.startsWith('Nmap/'));
  }

  function renderNmapSummaryCards(data, hosts){
    const hostCount = hosts.length;
    const upCount = hosts.filter(host => String(host && host.status || '').toLowerCase() === 'up').length;
    const portCount = hosts.reduce((sum, host) => sum + ((host && Array.isArray(host.ports)) ? host.ports.length : 0), 0);
    const vulnCount = hosts.reduce((sum, host) => sum + ((host && Array.isArray(host.vulnerabilities)) ? host.vulnerabilities.length : 0), 0);
    const elapsed = data && data.stats && data.stats.elapsed ? `${Number(data.stats.elapsed).toFixed(2)}s` : 'Unknown';
    const cards = [
      { label: 'Hosts', value: String(hostCount), tone: 'text-emerald-200' },
      { label: 'Up', value: String(upCount), tone: 'text-cyan-200' },
      { label: 'Ports', value: String(portCount), tone: 'text-slate-100' },
      { label: 'Vulnerabilities', value: String(vulnCount), tone: vulnCount ? 'text-rose-200' : 'text-slate-100' },
      { label: 'Elapsed', value: elapsed, tone: 'text-slate-100' },
    ];
    return `
      <div class="grid grid-cols-2 xl:grid-cols-5 gap-3">
        ${cards.map(card => `
          <div class="rounded-xl border border-slate-800/70 bg-slate-900/50 px-4 py-3">
            <div class="text-[11px] uppercase tracking-[0.18em] text-slate-500">${escapeHtml(card.label)}</div>
            <div class="mt-2 text-lg font-semibold ${card.tone}">${escapeHtml(card.value)}</div>
          </div>
        `).join('')}
      </div>
    `;
  }

  function renderVulnerabilityList(vulnerabilities){
    if (!Array.isArray(vulnerabilities) || !vulnerabilities.length){
      return '<div class="text-xs text-slate-500">No vulnerabilities identified.</div>';
    }
    return vulnerabilities.map(vuln => {
      const refs = Array.isArray(vuln.references) ? vuln.references : [];
      const portLabel = vuln.port ? ` · Port ${escapeHtml(String(vuln.port))}/${escapeHtml(String(vuln.protocol || '?'))}` : '';
      return `
        <div class="rounded-xl border ${getSeverityClasses(vuln.severity)} px-3 py-3">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-xs font-semibold">${escapeHtml(vuln.id || 'Finding')}</span>
            <span class="px-2 py-0.5 rounded-full border text-[10px] ${getSeverityClasses(vuln.severity)}">${escapeHtml(formatSeverityLabel(vuln.severity))}</span>
            <span class="text-[11px] text-slate-400">${escapeHtml(vuln.source_script_id || 'script')}${portLabel}</span>
          </div>
          <div class="mt-2 text-xs text-slate-100 whitespace-pre-wrap">${escapeHtml(vuln.description || 'No description available.')}</div>
          ${refs.length ? `<div class="mt-2 text-[11px] text-slate-400">Refs: ${escapeHtml(refs.join(', '))}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  function renderPortList(ports){
    if (!Array.isArray(ports) || !ports.length){
      return '<div class="text-xs text-slate-500">No port data in this scan.</div>';
    }
    return `
      <div class="space-y-2">
        ${ports.map(port => {
          const serviceBits = [port.service, port.product, port.version].filter(Boolean);
          return `
            <div class="rounded-xl border border-slate-800/70 bg-slate-900/40 px-3 py-3">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="text-sm text-slate-100 font-medium">${escapeHtml(String(port.port ?? '?'))}/${escapeHtml(String(port.protocol || '?'))}</div>
                <div class="flex flex-wrap items-center gap-2">
                  <span class="px-2 py-0.5 rounded-full border text-[10px] ${String(port.state || '').toLowerCase() === 'open' ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200' : 'border-slate-600/40 bg-slate-800/70 text-slate-300'}">${escapeHtml(String(port.state || 'unknown'))}</span>
                  ${port.scripts && port.scripts.length ? `<span class="text-[11px] text-slate-400">${escapeHtml(String(port.scripts.length))} scripts</span>` : ''}
                </div>
              </div>
              <div class="mt-2 text-xs text-slate-300">${escapeHtml(serviceBits.join(' · ') || 'Service metadata unavailable')}</div>
              ${port.extrainfo ? `<div class="mt-1 text-[11px] text-slate-500">${escapeHtml(String(port.extrainfo))}</div>` : ''}
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  function renderOsSection(osInfo){
    if (!osInfo || (!osInfo.name && !(Array.isArray(osInfo.matches) && osInfo.matches.length))){
      return '<div class="text-xs text-slate-500">No OS detection data in this scan.</div>';
    }
    const matches = Array.isArray(osInfo.matches) ? osInfo.matches.slice(0, 3) : [];
    return `
      <div class="space-y-2">
        <div class="rounded-xl border border-slate-800/70 bg-slate-900/40 px-3 py-3">
          <div class="text-sm font-medium text-slate-100">${escapeHtml(String(osInfo.name || 'Best match unavailable'))}</div>
          <div class="mt-1 text-[11px] text-slate-400">Accuracy: ${escapeHtml(String(osInfo.accuracy ?? 'unknown'))}</div>
        </div>
        ${matches.map(match => `
          <div class="rounded-xl border border-slate-800/70 bg-slate-950/40 px-3 py-2">
            <div class="text-xs text-slate-200">${escapeHtml(String(match.name || 'Unknown match'))}</div>
            <div class="text-[11px] text-slate-500">Accuracy ${escapeHtml(String(match.accuracy ?? 'unknown'))}</div>
          </div>
        `).join('')}
      </div>
    `;
  }

  function renderScriptOutputs(scripts){
    if (!Array.isArray(scripts) || !scripts.length){
      return '<div class="text-xs text-slate-500">No script output in this scan.</div>';
    }
    return scripts.map(script => {
      const structured = hasStructuredData(script.structured)
        ? `<div class="mt-3"><div class="text-[11px] uppercase tracking-[0.16em] text-slate-500 mb-1">Structured</div><pre class="text-[11px] text-cyan-100 whitespace-pre-wrap rounded-lg border border-slate-800/70 bg-slate-950/70 p-3 overflow-auto">${escapeHtml(toPrettyJson(script.structured))}</pre></div>`
        : '';
      const vulnerabilities = Array.isArray(script.vulnerabilities) && script.vulnerabilities.length
        ? `<div class="mt-3 space-y-2">${renderVulnerabilityList(script.vulnerabilities)}</div>`
        : '';
      return `
        <details class="rounded-xl border border-slate-800/70 bg-slate-900/45 px-3 py-3 group">
          <summary class="flex flex-wrap items-center gap-2 cursor-pointer list-none">
            <span class="text-xs font-semibold text-slate-100">${escapeHtml(String(script.id || 'script'))}</span>
            <span class="text-[11px] text-slate-400">${escapeHtml(formatScriptContext(script))}</span>
            ${script.is_vulnerability ? `<span class="px-2 py-0.5 rounded-full border text-[10px] border-rose-400/30 bg-rose-500/15 text-rose-200">Vulnerability</span>` : ''}
          </summary>
          <div class="mt-3 text-[11px] uppercase tracking-[0.16em] text-slate-500 mb-1">Raw Output</div>
          <pre class="text-[11px] text-slate-100 whitespace-pre-wrap rounded-lg border border-slate-800/70 bg-slate-950/70 p-3 overflow-auto">${escapeHtml(String(script.output || 'No raw output available.'))}</pre>
          ${structured}
          ${vulnerabilities}
        </details>
      `;
    }).join('');
  }

  function renderHostCard(host){
    const hostnames = Array.isArray(host.hostnames) && host.hostnames.length ? host.hostnames.join(', ') : 'No hostnames';
    const ports = Array.isArray(host.ports) ? host.ports : [];
    const vulnerabilities = Array.isArray(host.vulnerabilities) ? host.vulnerabilities : [];
    const scripts = Array.isArray(host.raw_scripts) ? host.raw_scripts : [];
    const highest = host && host.severity_summary ? host.severity_summary.highest : null;
    return `
      <section class="rounded-2xl border border-slate-800/70 bg-slate-950/45 overflow-hidden">
        <div class="px-4 py-4 border-b border-slate-800/70 bg-slate-900/45">
          <div class="flex flex-wrap items-center gap-2">
            <div class="text-base font-semibold text-slate-100">${escapeHtml(String(host.ip || 'Unknown host'))}</div>
            <span class="px-2 py-0.5 rounded-full border text-[10px] ${String(host.status || '').toLowerCase() === 'up' ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200' : 'border-slate-600/40 bg-slate-800/70 text-slate-300'}">${escapeHtml(String(host.status || 'unknown'))}</span>
            ${highest ? `<span class="px-2 py-0.5 rounded-full border text-[10px] ${getSeverityClasses(highest)}">${escapeHtml(formatSeverityLabel(highest))}</span>` : ''}
          </div>
          <div class="mt-2 text-xs text-slate-400">${escapeHtml(hostnames)}</div>
          <div class="mt-2 flex flex-wrap gap-3 text-[11px] text-slate-500">
            <span>MAC: ${escapeHtml(String(host.mac || 'n/a'))}</span>
            <span>Vendor: ${escapeHtml(String(host.vendor || 'n/a'))}</span>
            <span>Ports: ${escapeHtml(String(ports.length))}</span>
            <span>Findings: ${escapeHtml(String(vulnerabilities.length))}</span>
          </div>
        </div>
        <div class="grid xl:grid-cols-2 gap-4 p-4">
          <div>
            <div class="text-[11px] uppercase tracking-[0.18em] text-slate-500 mb-2">Ports & Services</div>
            ${renderPortList(ports)}
          </div>
          <div>
            <div class="text-[11px] uppercase tracking-[0.18em] text-slate-500 mb-2">OS Detection</div>
            ${renderOsSection(host.os)}
          </div>
        </div>
        <div class="grid xl:grid-cols-2 gap-4 px-4 pb-4">
          <div>
            <div class="text-[11px] uppercase tracking-[0.18em] text-slate-500 mb-2">Vulnerabilities</div>
            ${renderVulnerabilityList(vulnerabilities)}
          </div>
          <div>
            <div class="text-[11px] uppercase tracking-[0.18em] text-slate-500 mb-2">Script Outputs</div>
            <div class="space-y-2">${renderScriptOutputs(scripts)}</div>
          </div>
        </div>
      </section>
    `;
  }

  function renderNmapVisualization(){
    if (!nmapVizBody) return;
    const data = nmapVizState.data;
    if (!data){
      nmapVizBody.innerHTML = '<div class="text-sm text-slate-400">No Nmap data loaded.</div>';
      return;
    }

    const allHosts = Array.isArray(data.hosts) ? data.hosts : [];
    const vulnerableOnly = !!(nmapVizFilterVuln && nmapVizFilterVuln.checked);
    const hosts = vulnerableOnly
      ? allHosts.filter(host => Array.isArray(host.vulnerabilities) && host.vulnerabilities.length)
      : allHosts;
    const warnings = Array.isArray(data.warnings) ? data.warnings : [];
    const args = data && data.scan ? data.scan.args : '';
    const rawXmlSection = data.raw_xml
      ? `<details class="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-3"><summary class="cursor-pointer text-xs font-semibold text-slate-200">Raw XML</summary><pre class="mt-3 text-[11px] text-slate-100 whitespace-pre-wrap rounded-lg border border-slate-800/70 bg-slate-950/70 p-3 overflow-auto">${escapeHtml(String(data.raw_xml || ''))}</pre></details>`
      : '';
    const warningsSection = warnings.length
      ? `<div class="rounded-xl border border-amber-400/20 bg-amber-500/10 px-4 py-3 text-xs text-amber-100">Warnings: ${escapeHtml(warnings.join(' | '))}</div>`
      : '';

    nmapVizBody.innerHTML = `
      ${renderNmapSummaryCards(data, hosts)}
      ${args ? `<div class="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-3 text-xs text-slate-300"><span class="text-slate-500 uppercase tracking-[0.16em] mr-2">Args</span>${escapeHtml(String(args))}</div>` : ''}
      ${warningsSection}
      <div class="space-y-4">
        ${hosts.length ? hosts.map(renderHostCard).join('') : '<div class="rounded-xl border border-slate-800/70 bg-slate-900/45 px-4 py-6 text-sm text-slate-400">No hosts match the current filter.</div>'}
      </div>
      ${rawXmlSection}
    `;
  }

  async function loadNmapVisualization(path, name){
    if (!nmapVizModal) return;
    const xmlUrl = getApiUrl('/api/loot/download', { path });
    if (nmapVizTitle) nmapVizTitle.textContent = name || 'Nmap Visualization';
    if (nmapVizMeta) nmapVizMeta.textContent = path ? `/${path}` : '';
    if (nmapVizDownloadXml) nmapVizDownloadXml.href = xmlUrl;
    if (nmapVizFilterVuln) nmapVizFilterVuln.checked = false;
    setNmapVizError('');
    setNmapVizStatus('Loading...');
    nmapVizState.data = null;
    revokeNmapJsonUrl();
    if (nmapVizBody) nmapVizBody.innerHTML = '<div class="text-sm text-slate-400">Parsing XML and normalizing results...</div>';
    nmapVizModal.classList.remove('hidden');

    try{
      const url = getApiUrl('/api/loot/nmap', { path, include_raw: '1' });
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        throw new Error(data && data.error ? data.error : 'Failed to parse Nmap XML');
      }
      nmapVizState.data = data;
      if (nmapVizMeta){
        const metaBits = [
          path ? `/${path}` : '',
          data && data.scan && data.scan.version ? `Nmap ${data.scan.version}` : '',
          data && data.stats && data.stats.time_str ? data.stats.time_str : '',
        ].filter(Boolean);
        nmapVizMeta.textContent = metaBits.join(' · ');
      }
      if (nmapVizDownloadJson){
        const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        nmapVizState.jsonUrl = URL.createObjectURL(jsonBlob);
        nmapVizDownloadJson.href = nmapVizState.jsonUrl;
        nmapVizDownloadJson.download = String(name || 'nmap').replace(/\.xml$/i, '.json');
      }
      renderNmapVisualization();
      setNmapVizStatus('Ready');
    }catch(e){
      setNmapVizStatus('Parse failed');
      setNmapVizError(e && e.message ? e.message : 'Failed to parse Nmap XML');
      if (nmapVizBody) nmapVizBody.innerHTML = '<div class="text-sm text-slate-400">The XML file could not be visualized.</div>';
    }
  }

  function renderLoot(items){
    if (!lootList) return;
    if (!items.length){
      lootList.innerHTML = '<div class="px-3 py-4 text-sm text-slate-400">No files found.</div>';
      return;
    }
    const rows = items.map(item => {
      const itemType = item && item.type === 'dir' ? 'dir' : 'file';
      const icon = itemType === 'dir' ? '📁' : '📄';
      const meta = itemType === 'dir' ? 'Folder' : `${formatBytes(item.size)} · ${formatTime(item.mtime)}`;
      const safeName = escapeHtml(item.name || '');
      const encodedName = encodeData(item.name || '');
      const vizAction = isNmapLootXml(lootState.path, item.name)
        ? `<span role="button" tabindex="0" title="Visualize Nmap XML" aria-label="Visualize Nmap XML" data-visualize-nmap="${encodedName}" class="ml-2 inline-flex h-6 w-6 items-center justify-center rounded-md border border-emerald-400/20 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 transition align-middle"><i class="fa-solid fa-network-wired pointer-events-none text-[11px]"></i></span>`
        : '';
      return `
        <button class="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-slate-800/60 transition loot-item" data-type="${itemType}" data-name="${encodedName}">
          <span class="text-lg">${icon}</span>
          <div class="flex-1 min-w-0">
            <div class="text-sm text-slate-100 truncate"><span>${safeName}</span>${vizAction}</div>
            <div class="text-[11px] text-slate-400">${escapeHtml(meta)}</div>
          </div>
          <div class="text-xs text-slate-400">${itemType === 'dir' ? 'Open' : 'Download'}</div>
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
      const catId = String(cat?.id || '');
      const catIdEncoded = encodeData(catId);
      const catLabel = escapeHtml(String(cat?.label || catId || 'Category'));
      const isOpen = !!payloadState.open[catId];
      const items = (cat.items || []).map(item => {
        const itemName = escapeHtml(String(item?.name || 'payload'));
        const itemPath = String(item?.path || '');
        const itemPathEncoded = encodeData(itemPath);
        const isActive = payloadState.activePath === itemPath;
        const disabled = !!payloadState.activePath;
        const startCls = disabled
          ? 'px-2 py-0.5 text-[10px] rounded-md bg-slate-800/80 border border-slate-700/40 text-slate-500 cursor-not-allowed'
          : 'px-2 py-0.5 text-[10px] rounded-md bg-emerald-600/80 border border-emerald-300/30 text-white hover:bg-emerald-500/80 transition';
        const stopBtn = isActive
          ? '<button type="button" data-stop="1" class="px-2 py-0.5 text-[10px] rounded-md bg-rose-600/80 border border-rose-300/30 text-white hover:bg-rose-500/80 transition">Stop</button>'
          : '<span class="px-2 py-0.5 text-[10px] rounded-md bg-slate-900/60 border border-slate-800/40 text-slate-600">Idle</span>';
        return `
        <div class="flex items-center justify-between gap-2 px-2 py-1 rounded-lg bg-slate-900/40 border border-slate-800/70">
          <div class="text-[11px] text-slate-200 truncate">${itemName}</div>
          <div class="flex items-center gap-1">
            <button type="button" data-start="${itemPathEncoded}" ${disabled ? 'disabled' : ''} class="${startCls}">Start</button>
            ${stopBtn}
          </div>
        </div>
      `;
      }).join('');
      return `
        <div class="rounded-xl border border-slate-800/70 bg-slate-950/40">
          <button type="button" data-cat="${catIdEncoded}" class="w-full px-3 py-2 text-left text-xs font-semibold text-slate-200 flex items-center justify-between">
            <span>${catLabel}</span>
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
    const isTypingFocus = () => {
      const el = document.activeElement;
      if (!el) return false;
      const tag = String(el.tagName || '').toUpperCase();
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || !!el.isContentEditable;
    };

    window.addEventListener('keydown', (e)=>{
      if (terminalHasFocus || isTypingFocus()) return;
      const btn = KEYMAP.get(e.code) || KEYMAP.get(e.key);
      if (!btn) return;
      if (pressed.has(btn)) return; // avoid repeats
      pressed.add(btn);
      sendInput(btn, 'press');
      e.preventDefault();
    });
    window.addEventListener('keyup', (e)=>{
      if (terminalHasFocus || isTypingFocus()) return;
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
  if (logoutBtn) logoutBtn.addEventListener('click', logoutUser);
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
    loadTailscaleSettings();
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
    const vizBtn = e.target.closest('[data-visualize-nmap]');
    if (vizBtn){
      e.preventDefault();
      const encodedViz = vizBtn.getAttribute('data-visualize-nmap') || '';
      const vizName = decodeURIComponent(encodedViz);
      const vizPath = buildLootPath(lootState.path, vizName);
      loadNmapVisualization(vizPath, vizName);
      return;
    }
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
      const encodedId = catBtn.getAttribute('data-cat') || '';
      const id = decodeURIComponent(encodedId);
      if (id){
        payloadState.open[id] = !payloadState.open[id];
        renderPayloadSidebar();
      }
      return;
    }
    const startBtn = e.target.closest('[data-start]');
    if (startBtn){
      const encodedPath = startBtn.getAttribute('data-start') || '';
      const path = decodeURIComponent(encodedPath);
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
  if (tailscaleInstallBtn) tailscaleInstallBtn.addEventListener('click', () => {
    tailscaleReauthMode = false;
    openTailscaleModal();
  });
  if (tailscaleReauthBtn) tailscaleReauthBtn.addEventListener('click', () => {
    tailscaleReauthMode = true;
    openTailscaleModal();
  });
  if (tailscaleModalSave) tailscaleModalSave.addEventListener('click', submitTailscaleInstall);
  if (tailscaleModalCancel) tailscaleModalCancel.addEventListener('click', closeTailscaleModal);
  if (tailscaleModalClose) tailscaleModalClose.addEventListener('click', closeTailscaleModal);
  if (tailscaleModal) tailscaleModal.addEventListener('click', (e) => {
    if (e.target === tailscaleModal) closeTailscaleModal();
  });
  if (lootPreviewClose) lootPreviewClose.addEventListener('click', closePreview);
  if (lootPreview) lootPreview.addEventListener('click', (e) => {
    if (e.target === lootPreview) closePreview();
  });
  if (nmapVizClose) nmapVizClose.addEventListener('click', closeNmapViz);
  if (nmapVizModal) nmapVizModal.addEventListener('click', (e) => {
    if (e.target === nmapVizModal) closeNmapViz();
  });
  if (nmapVizFilterVuln) nmapVizFilterVuln.addEventListener('change', renderNmapVisualization);
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

  let payloadPollTimer = null;
  let systemPollTimer = null;

  function schedulePayloadPoll(){
    if (payloadPollTimer) clearTimeout(payloadPollTimer);
    const delay = document.hidden ? 6000 : 1500;
    payloadPollTimer = setTimeout(async () => {
      await pollPayloadStatus();
      schedulePayloadPoll();
    }, delay);
  }

  function scheduleSystemPoll(){
    if (systemPollTimer) clearTimeout(systemPollTimer);
    const delay = document.hidden ? 10000 : 3000;
    systemPollTimer = setTimeout(async () => {
      if (systemOpen){
        await loadSystemStatus();
      }
      scheduleSystemPoll();
    }, delay);
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden){
      if (systemOpen) loadSystemStatus();
      pollPayloadStatus();
    }
    schedulePayloadPoll();
    scheduleSystemPoll();
  });

  const startAfterAuth = () => {
    ensureAuthenticated('Log in to access RaspyJack WebUI.').then((ok) => {
      if (!ok){
        setTimeout(startAfterAuth, 0);
        return;
      }
      connect();
      loadPayloads();
      schedulePayloadPoll();
      scheduleSystemPoll();
    });
  };
  startAfterAuth();
})();
