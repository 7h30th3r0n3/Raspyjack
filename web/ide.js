(function(){
  const shared = window.RJShared || {};
  // ------------------------ DOM references ------------------------
  const ideStatusEl = document.getElementById('ideStatus');
  const treeContainer = document.getElementById('treeContainer');
  const refreshTreeBtn = document.getElementById('refreshTree');
  const newFileBtn = document.getElementById('newFileBtn');
  const newFolderBtn = document.getElementById('newFolderBtn');
  const currentPathEl = document.getElementById('currentPath');
  const dirtyFlagEl = document.getElementById('dirtyFlag');
  const payloadRunStateEl = document.getElementById('payloadRunState');
  const saveBtn = document.getElementById('saveBtn');
  const runBtn = document.getElementById('runBtn');
  const stopBtn = document.getElementById('stopBtn');
  const editorTextarea = document.getElementById('editor');
  const logoutBtn = document.getElementById('logoutBtn');
  const restartUiBtn = document.getElementById('restartUiBtn');
  const restartUiModal = document.getElementById('restartUiModal');
  const restartUiModalConfirm = document.getElementById('restartUiModalConfirm');
  const restartUiModalCancel = document.getElementById('restartUiModalCancel');
  const restartUiModalClose = document.getElementById('restartUiModalClose');
  const restartUiModalError = document.getElementById('restartUiModalError');
  const wsStatusEl = document.getElementById('wsStatus');
  const canvas = document.getElementById('screen-gb') || document.getElementById('screen');
  const ctx = canvas ? canvas.getContext('2d') : null;
  const entryModal = document.getElementById('entryModal');
  const entryModalTitle = document.getElementById('entryModalTitle');
  const entryModalFolder = document.getElementById('entryModalFolder');
  const entryModalName = document.getElementById('entryModalName');
  const entryModalConfirm = document.getElementById('entryModalConfirm');
  const entryModalCancel = document.getElementById('entryModalCancel');
  const entryModalClose = document.getElementById('entryModalClose');
  const renameModal = document.getElementById('renameModal');
  const renameModalPath = document.getElementById('renameModalPath');
  const renameModalName = document.getElementById('renameModalName');
  const renameModalConfirm = document.getElementById('renameModalConfirm');
  const renameModalCancel = document.getElementById('renameModalCancel');
  const renameModalClose = document.getElementById('renameModalClose');
  const treeContextMenu = document.getElementById('treeContextMenu');
  const treeContextMenuPanel = document.getElementById('treeContextMenuPanel');
  const ctxRenameBtn = document.getElementById('ctxRename');
  const ctxDeleteBtn = document.getElementById('ctxDelete');
  const deleteModal = document.getElementById('deleteModal');
  const deleteModalPath = document.getElementById('deleteModalPath');
  const deleteModalConfirm = document.getElementById('deleteModalConfirm');
  const deleteModalCancel = document.getElementById('deleteModalCancel');
  const deleteModalClose = document.getElementById('deleteModalClose');
  const unsavedModal = document.getElementById('unsavedModal');
  const unsavedModalConfirm = document.getElementById('unsavedModalConfirm');
  const unsavedModalCancel = document.getElementById('unsavedModalCancel');
  const unsavedModalClose = document.getElementById('unsavedModalClose');
  const saveBeforeRunModal = document.getElementById('saveBeforeRunModal');
  const saveBeforeRunModalConfirm = document.getElementById('saveBeforeRunModalConfirm');
  const saveBeforeRunModalCancel = document.getElementById('saveBeforeRunModalCancel');
  const saveBeforeRunModalClose = document.getElementById('saveBeforeRunModalClose');
  const noticeModal = document.getElementById('noticeModal');
  const noticeModalTitle = document.getElementById('noticeModalTitle');
  const noticeModalMessage = document.getElementById('noticeModalMessage');
  const noticeModalConfirm = document.getElementById('noticeModalConfirm');
  const noticeModalClose = document.getElementById('noticeModalClose');
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
  const leftPanel = document.getElementById('leftPanel');
  const resizeHandle = document.getElementById('resizeHandle');

  // ------------------------ Helpers ------------------------
  function applyStatusTone(el, txt){
    if (!el) return;
    const s = String(txt || '').toLowerCase();
    el.classList.remove('status-tone-ok', 'status-tone-warn', 'status-tone-bad');
    if (/connected|authenticated|ready|saved|launched|active|ok/.test(s)) {
      el.classList.add('status-tone-ok');
    } else if (/loading|connecting|starting|running|reconnecting/.test(s)) {
      el.classList.add('status-tone-warn');
    } else if (/failed|error|denied|disconnected/.test(s)) {
      el.classList.add('status-tone-bad');
    }
  }

  function setIdeStatus(text){
    if (ideStatusEl) {
      ideStatusEl.textContent = text;
      applyStatusTone(ideStatusEl, text);
    }
  }

  function getSearchParams(){
    try {
      return new URLSearchParams(location.search);
    } catch {
      return new URLSearchParams();
    }
  }

  function getApiUrl(path, params = {}){
    if (shared.getApiUrl) return shared.getApiUrl(path, params, location);
    const qs = new URLSearchParams(params).toString();
    const base = location.origin;
    return `${base}${path}${qs ? `?${qs}` : ''}`;
  }

  function getWsUrl(){
    if (shared.getWsUrl) return shared.getWsUrl(location);
    if (location.protocol === 'https:'){
      return `${location.origin.replace(/^https:/, 'wss:')}/ws`;
    }
    const p = getSearchParams();
    const host = location.hostname || 'raspberrypi.local';
    const port = p.get('port') || '8765';
    return `ws://${host}:${port}/`.replace(/\/\/\//,'//');
  }

  const AUTH_STORAGE_KEY = 'rj.authToken';
  let authToken = '';
  let wsTicket = '';
  let authPromptResolver = null;
  let restartUiPromptResolver = null;
  let unsavedPromptResolver = null;
  let saveBeforeRunPromptResolver = null;
  let noticePromptResolver = null;
  let authInFlight = null;
  let authMode = 'login';
  let authRecoveryMode = false;

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

  function bytesFromString(s){
    return new TextEncoder().encode(s).length;
  }

  function escapeHtml(value){
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeAttr(value){
    return escapeHtml(value);
  }

  function getFileIcon(filename){
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const iconMap = {
      'py': 'fa-brands fa-python',      // Python
      'js': 'fa-brands fa-js',          // JavaScript
      'ts': 'fa-brands fa-js',          // TypeScript
      'json': 'fa-file-code',           // JSON
      'md': 'fa-file-lines',            // Markdown
      'txt': 'fa-file-lines',           // Text
      'log': 'fa-file-lines',           // Log
      'sh': 'fa-terminal',              // Shell script
      'bash': 'fa-terminal',            // Bash
      'yml': 'fa-file-code',            // YAML
      'yaml': 'fa-file-code',           // YAML
      'conf': 'fa-gear',                // Config
      'ini': 'fa-gear',                 // Config
      'cfg': 'fa-gear',                 // Config
      'xml': 'fa-file-code',            // XML
      'html': 'fa-brands fa-html5',     // HTML
      'css': 'fa-brands fa-css3-alt',   // CSS
      'php': 'fa-brands fa-php',        // PHP
      'sql': 'fa-database',             // SQL
      'c': 'fa-file-code',              // C
      'cpp': 'fa-file-code',            // C++
      'h': 'fa-file-code',              // Header
      'hpp': 'fa-file-code',            // C++ Header
      'java': 'fa-brands fa-java',      // Java
      'go': 'fa-file-code',             // Go
      'rs': 'fa-file-code',             // Rust
      'rb': 'fa-gem',                   // Ruby
      'pl': 'fa-file-code',             // Perl
      'r': 'fa-file-code',              // R
      'png': 'fa-image',                // Image
      'jpg': 'fa-image',                // Image
      'jpeg': 'fa-image',               // Image
      'gif': 'fa-image',                // Image
      'svg': 'fa-image',                // SVG
      'zip': 'fa-file-zipper',          // Archive
      'tar': 'fa-file-zipper',          // Archive
      'gz': 'fa-file-zipper',           // Archive
      'pdf': 'fa-file-pdf',             // PDF
    };
    return iconMap[ext] || 'fa-file'; // default file icon
  }

  // ------------------------ File tree state ------------------------
  let treeData = null;
  let expandedPaths = new Set();
  let selectedPath = null;   // currently opened file
  let currentFolder = '';    // folder used for create operations
  let ctxTargetPath = null;
  let ctxTargetType = null;
  let payloadActivePath = null;
  let payloadRunPending = false;
  let payloadStopPending = false;

  function normalizePayloadPath(path){
    return String(path || '').replace(/\\/g, '/').replace(/^\/+/, '');
  }

  function updatePayloadRunUi(){
    const selected = normalizePayloadPath(selectedPath);
    const running = normalizePayloadPath(payloadActivePath);
    const hasSelection = !!selected;
    const runningAny = !!running;
    const runningSelected = runningAny && selected && selected === running;

    if (runBtn){
      runBtn.disabled = !hasSelection || runningAny || payloadRunPending;
      runBtn.innerHTML = payloadRunPending
        ? '<i class="fa-solid fa-spinner fa-spin text-[10px]"></i> Starting...'
        : '<i class="fa-solid fa-play text-[10px]"></i> Run';
    }

    if (stopBtn){
      stopBtn.disabled = !runningAny || payloadStopPending;
      stopBtn.innerHTML = payloadStopPending
        ? '<i class="fa-solid fa-spinner fa-spin text-[10px]"></i> Stopping...'
        : '<i class="fa-solid fa-stop text-[10px]"></i> Stop';
    }

    if (payloadRunStateEl){
      if (payloadRunPending){
        payloadRunStateEl.textContent = 'Starting...';
        payloadRunStateEl.className = 'text-amber-300';
      } else if (payloadStopPending){
        payloadRunStateEl.textContent = 'Stopping...';
        payloadRunStateEl.className = 'text-amber-300';
      } else if (runningAny){
        payloadRunStateEl.textContent = runningSelected ? 'Running (current file)' : 'Running (another payload)';
        payloadRunStateEl.className = 'text-emerald-300';
      } else {
        payloadRunStateEl.textContent = 'Idle';
        payloadRunStateEl.className = 'text-slate-400';
      }
    }
  }

  function setCurrentFolder(path){
    currentFolder = (path === undefined || path === null) ? '' : path;
    if (treeContainer){
      treeContainer.querySelectorAll('.folder-node').forEach(el => {
        const p = el.getAttribute('data-path') || '';
        el.classList.toggle('active', p === currentFolder);
      });
    }
  }

  function setSelectedPath(path){
    selectedPath = path || null;
    if (currentPathEl){
      currentPathEl.textContent = path ? `payloads/${path}` : 'No file selected';
    }
    if (saveBtn) saveBtn.disabled = !path;
    if (runBtn) runBtn.disabled = !path;
    // update active highlighting
    if (treeContainer){
      treeContainer.querySelectorAll('.file-node').forEach(el => {
        const p = el.getAttribute('data-path') || '';
        el.classList.toggle('active', !!path && p === path);
      });
    }
    // when a file is selected, also track its parent folder
    if (path){
      const parts = path.split('/');
      parts.pop();
      const folder = parts.join('/');
      setCurrentFolder(folder);
    }
    updatePayloadRunUi();
  }

  function hideContextMenu(){
    if (treeContextMenu){
      treeContextMenu.classList.add('hidden');
    }
    ctxTargetPath = null;
    ctxTargetType = null;
  }

  function showContextMenu(x, y, path, type){
    if (!treeContextMenu || !treeContextMenuPanel) return;
    ctxTargetPath = path;
    ctxTargetType = type;
    treeContextMenu.classList.remove('hidden');
    treeContextMenu.style.left = `${x}px`;
    treeContextMenu.style.top = `${y}px`;

    // Adjust to keep menu on-screen
    const rect = treeContextMenuPanel.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let left = x;
    let top = y;
    if (rect.right > vw){
      left = Math.max(0, x - rect.width);
    }
    if (rect.bottom > vh){
      top = Math.max(0, y - rect.height);
    }
    treeContextMenu.style.left = `${left}px`;
    treeContextMenu.style.top = `${top}px`;
  }

  // ------------------------ CodeMirror editor ------------------------
  let editor = null;
  let isDirty = false;

  function setDirty(dirty){
    isDirty = !!dirty;
    if (dirtyFlagEl){
      dirtyFlagEl.classList.toggle('hidden', !dirty);
    }
  }

  function ensureEditor(){
    if (editor || !editorTextarea || !window.CodeMirror) return;
    editor = CodeMirror.fromTextArea(editorTextarea, {
      mode: 'python',
      theme: 'monokai',
      lineNumbers: true,
      indentUnit: 4,
      indentWithTabs: false,
      lineWrapping: true,
      autofocus: true,
    });
    editor.on('change', () => {
      if (selectedPath){
        setDirty(true);
      }
    });
  }

  // ------------------------ Tree rendering ------------------------
  function renderTreeNode(node, depth){
    const container = document.createElement('div');
    const isDir = node.type === 'dir';
    const indent = depth * 14;

    const row = document.createElement('div');
    row.className = 'flex items-center text-[11px] text-slate-200 hover:bg-slate-800/60 rounded-md px-1 py-0.5';
    row.style.paddingLeft = `${indent}px`;

    if (isDir){
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'mr-1 text-slate-400 hover:text-slate-200';
      const open = expandedPaths.has(node.path || '');
      toggle.textContent = open ? '▾' : '▸';
      toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        const key = node.path || '';
        if (expandedPaths.has(key)){
          expandedPaths.delete(key);
        } else {
          expandedPaths.add(key);
        }
        renderTree();
      });
      row.appendChild(toggle);
    } else {
      const icon = document.createElement('i');
      icon.className = `file-icon mr-1 ${getFileIcon(node.name)}`;
      row.appendChild(icon);
    }

    const label = document.createElement('div');
    label.className = 'flex-1 min-w-0 truncate';
    label.textContent = node.name;
    row.appendChild(label);

    if (!isDir){
      row.classList.add('file-node');
      row.setAttribute('data-path', node.path || '');
      if (selectedPath && node.path === selectedPath){
        row.classList.add('active');
      }
      row.addEventListener('click', () => {
        onFileSelected(node.path || '');
      });
    } else {
      row.classList.add('folder-node');
      row.setAttribute('data-path', node.path || '');
      row.addEventListener('click', () => {
        setSelectedPath(null);
        setCurrentFolder(node.path || '');
      });
    }

    container.appendChild(row);

    if (isDir && node.children && node.children.length && expandedPaths.has(node.path || '')){
      const childrenWrapper = document.createElement('div');
      node.children.forEach(child => {
        childrenWrapper.appendChild(renderTreeNode(child, depth + 1));
      });
      container.appendChild(childrenWrapper);
    }
    return container;
  }

  function renderTree(){
    if (!treeContainer) return;
    treeContainer.innerHTML = '';
    if (!treeData){
      treeContainer.innerHTML = '<div class="text-[11px] text-slate-500 px-1 py-1">No payloads directory found.</div>';
      return;
    }
    expandedPaths.add(''); // always expand root
    treeContainer.appendChild(renderTreeNode(treeData, 0));
  }

  async function loadTree(){
    setIdeStatus('Loading tree...');
    try{
      const url = getApiUrl('/api/payloads/tree');
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'tree_failed');
      }
      treeData = data;
      if (!expandedPaths.size){
        expandedPaths.add('');
      }
      renderTree();
      // restore selection highlights after re-render
      if (selectedPath){
        setSelectedPath(selectedPath);
      } else if (currentFolder){
        setCurrentFolder(currentFolder);
      }
      setIdeStatus('Ready');
    }catch(e){
      console.error(e);
      setIdeStatus('Failed to load tree');
      if (treeContainer){
        treeContainer.innerHTML = '<div class="text-[11px] text-rose-400 px-1 py-1">Failed to load payload tree.</div>';
      }
    }
  }

  // ------------------------ File operations ------------------------
  async function onFileSelected(path){
    if (!path) return;
    if (isDirty){
      const ok = await promptDiscardUnsavedChanges();
      if (!ok) return;
    }
    setIdeStatus('Loading file...');
    try{
      const url = getApiUrl('/api/payloads/file', { path });
      const res = await apiFetch(url, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'load_failed');
      }
      ensureEditor();
      if (editor){
        editor.setValue(data.content || '');
        editor.focus();
      }
      setSelectedPath(data.path || path);
      setDirty(false);
      setIdeStatus('Ready');
    }catch(e){
      console.error(e);
      setIdeStatus('Failed to load file');
    }
  }

  async function saveCurrentFile(){
    if (!selectedPath || !editor) return false;
    const content = editor.getValue();
    const sizeBytes = bytesFromString(content);
    if (sizeBytes > 512 * 1024){
      await showNoticeModal({
        title: 'File Too Large',
        message: 'File is too large to save via WebUI (limit 512 KB).',
        tone: 'amber',
      });
      return false;
    }
    setIdeStatus('Saving...');
    try{
      const url = getApiUrl('/api/payloads/file');
      const res = await apiFetch(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: selectedPath, content })
      });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'save_failed');
      }
      setDirty(false);
      setIdeStatus('Saved');
      return true;
    }catch(e){
      console.error(e);
      setIdeStatus('Save failed');
      await showNoticeModal({
        title: 'Save Failed',
        message: 'Failed to save file.',
        tone: 'rose',
      });
      return false;
    }
  }

  let pendingEntryType = null;
  let pendingEntryBase = '';
  let pendingRenamePath = null;

  async function performCreateEntry(type, rel){
    setIdeStatus(`Creating ${type}...`);
    try{
      const url = getApiUrl('/api/payloads/entry');
      const body = { path: rel, type };
      if (type === 'file'){
        body.content = '#!/usr/bin/env python3\n\n\"\"\"\nRaspyJack payload\n\"\"\"\n\n';
      }
      const res = await apiFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'create_failed');
      }
      setIdeStatus('Created');
      await loadTree();
    }catch(e){
      console.error(e);
      setIdeStatus('Create failed');
      await showNoticeModal({
        title: 'Create Failed',
        message: `Failed to create ${type}.`,
        tone: 'rose',
      });
    }
  }

  function openEntryModal(type){
    pendingEntryType = type;
    const base = currentFolder || (selectedPath ? selectedPath.split('/').slice(0, -1).join('/') : '');
    pendingEntryBase = base || '';
    if (entryModalTitle){
      entryModalTitle.textContent = type === 'dir' ? 'New Folder' : 'New File';
    }
    if (entryModalFolder){
      const folderLabel = pendingEntryBase ? `payloads/${pendingEntryBase}` : 'payloads/';
      entryModalFolder.textContent = folderLabel;
    }
    if (entryModalName){
      entryModalName.value = '';
      entryModalName.placeholder = type === 'dir' ? 'Folder name' : 'Filename (e.g. my_payload.py)';
    }
    if (entryModal){
      entryModal.classList.remove('hidden');
    }
    if (entryModalName){
      setTimeout(() => entryModalName.focus(), 10);
    }
  }

  function closeEntryModal(){
    if (entryModal){
      entryModal.classList.add('hidden');
    }
    pendingEntryType = null;
    pendingEntryBase = '';
  }

  async function handleEntryConfirm(){
    if (!pendingEntryType || !entryModalName) return;
    const raw = entryModalName.value.trim();
    if (!raw) return;
    const rel = pendingEntryBase ? `${pendingEntryBase}/${raw}` : raw;
    await performCreateEntry(pendingEntryType, rel);
    closeEntryModal();
  }

  function createEntry(type){
    openEntryModal(type);
  }

  async function performRename(oldPath, newName){
    const parts = oldPath.split('/');
    const parent = parts.slice(0, -1).join('/');
    const newPath = parent ? `${parent}/${newName}` : newName;
    setIdeStatus('Renaming...');
    try{
      const url = getApiUrl('/api/payloads/entry');
      const res = await apiFetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_path: oldPath, new_path: newPath })
      });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'rename_failed');
      }
      if (selectedPath === oldPath){
        setSelectedPath(data.new_path || newPath);
      }
      setIdeStatus('Renamed');
      await loadTree();
    }catch(e){
      console.error(e);
      setIdeStatus('Rename failed');
      await showNoticeModal({
        title: 'Rename Failed',
        message: 'Failed to rename entry.',
        tone: 'rose',
      });
    }
  }

  function openRenameModal(path){
    if (!path) return;
    pendingRenamePath = path;
    const parts = path.split('/');
    const oldName = parts[parts.length - 1] || 'payloads';
    if (renameModalPath){
      renameModalPath.textContent = path || 'payloads/';
    }
    if (renameModalName){
      renameModalName.value = oldName;
      renameModalName.select();
    }
    if (renameModal){
      renameModal.classList.remove('hidden');
    }
  }

  function closeRenameModal(){
    if (renameModal){
      renameModal.classList.add('hidden');
    }
    pendingRenamePath = null;
  }

  async function handleRenameConfirm(){
    if (!pendingRenamePath || !renameModalName) return;
    const newName = renameModalName.value.trim();
    if (!newName) return;
    await performRename(pendingRenamePath, newName);
    closeRenameModal();
  }

  function renameEntry(path){
    openRenameModal(path);
  }

  let pendingDeletePath = null;

  function openDeleteModal(path){
    if (!path) return;
    pendingDeletePath = path;
    if (deleteModalPath){
      deleteModalPath.textContent = path || 'payloads/';
    }
    if (deleteModal){
      deleteModal.classList.remove('hidden');
    }
  }

  function closeDeleteModal(){
    if (deleteModal){
      deleteModal.classList.add('hidden');
    }
    pendingDeletePath = null;
  }

  async function handleDeleteConfirm(){
    if (!pendingDeletePath) return;
    const path = pendingDeletePath;
    closeDeleteModal();
    setIdeStatus('Deleting...');
    try{
      const url = getApiUrl('/api/payloads/entry', { path });
      const res = await apiFetch(url, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok || data.error){
        throw new Error(data.error || 'delete_failed');
      }
      if (selectedPath === path){
        setSelectedPath(null);
        if (editor){
          editor.setValue('');
        }
        setDirty(false);
      }
      setIdeStatus('Deleted');
      await loadTree();
    }catch(e){
      console.error(e);
      setIdeStatus('Delete failed');
      await showNoticeModal({
        title: 'Delete Failed',
        message: 'Failed to delete entry.',
        tone: 'rose',
      });
    }
  }

  function deleteEntry(path){
    openDeleteModal(path);
  }

  // ------------------------ Run payload ------------------------
  async function runCurrentPayload(){
    if (!selectedPath) return;
    if (normalizePayloadPath(payloadActivePath)) return;
    // if dirty, offer to save first
    if (isDirty){
      const ok = await promptSaveBeforeRun();
      if (!ok) return;
      const saved = await saveCurrentFile();
      if (!saved) return;
    }
    payloadRunPending = true;
    updatePayloadRunUi();
    setIdeStatus('Starting payload...');
    try{
      const url = getApiUrl('/api/payloads/run');
      const res = await apiFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: selectedPath })
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        throw new Error(data.error || 'run_failed');
      }
      payloadActivePath = normalizePayloadPath(selectedPath);
      payloadStopPending = false;
      updatePayloadRunUi();
      setIdeStatus('Payload launched');
    }catch(e){
      console.error(e);
      setIdeStatus('Run failed');
      await showNoticeModal({
        title: 'Run Failed',
        message: 'Failed to start payload.',
        tone: 'rose',
      });
    }finally{
      payloadRunPending = false;
      updatePayloadRunUi();
    }
  }

  async function pollPayloadStatus(){
    try{
      const res = await apiFetch(getApiUrl('/api/payloads/status'), { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok){
        return;
      }
      payloadActivePath = data && data.running ? normalizePayloadPath(data.path) : null;
      if (!payloadActivePath){
        payloadRunPending = false;
        payloadStopPending = false;
      }
      updatePayloadRunUi();
    }catch{}
  }

  async function stopCurrentPayload(){
    if (!normalizePayloadPath(payloadActivePath)) return;
    payloadStopPending = true;
    updatePayloadRunUi();
    setIdeStatus('Stopping payload...');
    try{
      sendInput('KEY3', 'press');
      setTimeout(() => sendInput('KEY3', 'release'), 120);
      setTimeout(() => { pollPayloadStatus(); }, 300);
    }catch(e){
      console.error(e);
      setIdeStatus('Stop failed');
    }finally{
      setTimeout(() => {
        payloadStopPending = false;
        updatePayloadRunUi();
      }, 800);
    }
  }

  function setRestartUiError(msg){
    if (!restartUiModalError) return;
    const text = String(msg || '').trim();
    restartUiModalError.textContent = text;
    restartUiModalError.classList.toggle('hidden', !text);
  }

  function resolveRestartUiPrompt(value){
    if (!restartUiPromptResolver) return;
    const resolver = restartUiPromptResolver;
    restartUiPromptResolver = null;
    if (restartUiModal) restartUiModal.classList.add('hidden');
    resolver(!!value);
  }

  function resolveUnsavedPrompt(value){
    if (!unsavedPromptResolver) return;
    const resolver = unsavedPromptResolver;
    unsavedPromptResolver = null;
    if (unsavedModal) unsavedModal.classList.add('hidden');
    resolver(!!value);
  }

  function promptDiscardUnsavedChanges(){
    if (!unsavedModal || !unsavedModalConfirm || !unsavedModalCancel || !unsavedModalClose){
      return Promise.resolve(false);
    }
    if (unsavedPromptResolver){
      return Promise.resolve(false);
    }
    unsavedModal.classList.remove('hidden');
    return new Promise(resolve => {
      unsavedPromptResolver = resolve;
    });
  }

  function resolveSaveBeforeRunPrompt(value){
    if (!saveBeforeRunPromptResolver) return;
    const resolver = saveBeforeRunPromptResolver;
    saveBeforeRunPromptResolver = null;
    if (saveBeforeRunModal) saveBeforeRunModal.classList.add('hidden');
    resolver(!!value);
  }

  function promptSaveBeforeRun(){
    if (!saveBeforeRunModal || !saveBeforeRunModalConfirm || !saveBeforeRunModalCancel || !saveBeforeRunModalClose){
      return Promise.resolve(false);
    }
    if (saveBeforeRunPromptResolver){
      return Promise.resolve(false);
    }
    saveBeforeRunModal.classList.remove('hidden');
    return new Promise(resolve => {
      saveBeforeRunPromptResolver = resolve;
    });
  }

  function applyNoticeTone(tone){
    if (!noticeModalTitle || !noticeModalConfirm) return;
    const titleToneClasses = ['text-rose-300', 'text-amber-300', 'text-emerald-300'];
    const btnToneClasses = [
      'bg-rose-600/80', 'border-rose-300/30', 'hover:bg-rose-500/80',
      'bg-amber-600/80', 'border-amber-300/30', 'hover:bg-amber-500/80',
      'bg-emerald-600/80', 'border-emerald-300/30', 'hover:bg-emerald-500/80',
    ];
    noticeModalTitle.classList.remove(...titleToneClasses);
    noticeModalConfirm.classList.remove(...btnToneClasses);
    if (tone === 'amber'){
      noticeModalTitle.classList.add('text-amber-300');
      noticeModalConfirm.classList.add('bg-amber-600/80', 'border-amber-300/30', 'hover:bg-amber-500/80');
      return;
    }
    if (tone === 'emerald'){
      noticeModalTitle.classList.add('text-emerald-300');
      noticeModalConfirm.classList.add('bg-emerald-600/80', 'border-emerald-300/30', 'hover:bg-emerald-500/80');
      return;
    }
    noticeModalTitle.classList.add('text-rose-300');
    noticeModalConfirm.classList.add('bg-rose-600/80', 'border-rose-300/30', 'hover:bg-rose-500/80');
  }

  function resolveNoticePrompt(){
    if (!noticePromptResolver) return;
    const resolver = noticePromptResolver;
    noticePromptResolver = null;
    if (noticeModal) noticeModal.classList.add('hidden');
    resolver();
  }

  function showNoticeModal({ title = 'Notice', message = 'Something went wrong.', tone = 'rose', buttonText = 'OK' } = {}){
    if (!noticeModal || !noticeModalTitle || !noticeModalMessage || !noticeModalConfirm || !noticeModalClose){
      return Promise.resolve();
    }
    if (noticePromptResolver){
      return Promise.resolve();
    }
    noticeModalTitle.textContent = title;
    noticeModalMessage.textContent = message;
    noticeModalConfirm.textContent = buttonText;
    applyNoticeTone(tone);
    noticeModal.classList.remove('hidden');
    return new Promise(resolve => {
      noticePromptResolver = resolve;
    });
  }

  function promptRestartUi(){
    if (!restartUiModal || !restartUiModalConfirm || !restartUiModalCancel || !restartUiModalClose){
      return Promise.resolve(false);
    }
    if (restartUiPromptResolver){
      return Promise.resolve(false);
    }
    setRestartUiError('');
    restartUiModal.classList.remove('hidden');
    return new Promise(resolve => {
      restartUiPromptResolver = resolve;
    });
  }

  async function restartUi(){
    const confirmed = await promptRestartUi();
    if (!confirmed) return;
    if (restartUiBtn) restartUiBtn.disabled = true;
    setIdeStatus('Restarting UI...');
    try{
      const res = await apiFetch(getApiUrl('/api/system/restart-ui'), { method: 'POST' });
      const data = await res.json();
      if (!res.ok || !data || !data.ok){
        throw new Error((data && data.error) ? data.error : 'restart_failed');
      }
      setIdeStatus('UI restart requested');
    }catch(e){
      console.error(e);
      setIdeStatus('UI restart failed');
      setRestartUiError('Failed to restart UI.');
      if (restartUiModal) restartUiModal.classList.remove('hidden');
    }finally{
      if (restartUiBtn) restartUiBtn.disabled = false;
    }
  }

  // ------------------------ WebSocket preview & input ------------------------
  let ws = null;
  let reconnectTimer = null;
  let wsAuthenticated = true;

  function setWsStatus(text){
    if (wsStatusEl) {
      wsStatusEl.textContent = text;
      applyStatusTone(wsStatusEl, text);
    }
  }

  function setupHiDPI(){
    if (!canvas || !ctx) return;
    const DPR = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    const logical = 128;
    canvas.width = logical * DPR;
    canvas.height = logical * DPR;
    ctx.imageSmoothingEnabled = true;
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
  }

  function sendInput(button, state){
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try{
      ws.send(JSON.stringify({ type: 'input', button, state }));
    }catch{}
  }

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

  function connectWs(){
    if (!canvas || !ctx) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    const url = getWsUrl();
    try{
      ws = new WebSocket(url);
    }catch(e){
      setWsStatus('WS error');
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      setWsStatus('Connected');
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
    };

    ws.onmessage = (ev) => {
      try{
        const msg = JSON.parse(ev.data);
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
          setWsStatus('Authenticated');
          return;
        }
        if (msg.type === 'auth_error'){
          wsAuthenticated = false;
          setWsStatus('Auth failed');
          return;
        }
        if (msg.type === 'frame' && msg.data){
          const img = new Image();
          img.onload = () => {
            try{
              ctx.clearRect(0,0,canvas.width,canvas.height);
              ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            }catch{}
          };
          img.src = 'data:image/jpeg;base64,' + msg.data;
        }
      }catch{}
    };

    ws.onerror = () => {
      try { ws.close(); } catch {}
    };

    ws.onclose = () => {
      setWsStatus('Disconnected – reconnecting…');
      scheduleReconnect();
    };
  }

  function scheduleReconnect(){
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectWs();
    }, 1200);
  }

  // =====================================================================
  //  TEMPLATE DATA (ported from raspyjack-ide-studio/templatesData.ts)
  // =====================================================================
  const TEMPLATES_DATA = [
    {
      id: 'wifi-scanner', name: 'WiFi Scanner', category: 'wifi', filename: 'wifi_scanner.py',
      description: 'Scan and display nearby WiFi networks with signal strength',
      code: `#!/usr/bin/env python3
"""
RaspyJack WiFi Scanner
======================
Scans for nearby WiFi networks and displays them on the LCD.
Press KEY1 to scan, KEY3 to exit.
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import subprocess
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

# Configuration
PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
SCAN_TIMEOUT = 10
WIFI_INTERFACE = "wlan1"

# GPIO Setup
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

# LCD Setup
LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show(lines):
    if isinstance(lines, str):
        lines = [lines]
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 5
    for line in lines[:9]:
        draw.text((4, y), line[:21], font=font, fill="#00FF00")
        y += 13
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def scan_networks():
    show(["Scanning WiFi...", f"Interface: {WIFI_INTERFACE}", f"Timeout: {SCAN_TIMEOUT}s"])
    subprocess.run("rm -f /tmp/wifi_scan*", shell=True)
    cmd = f"timeout {SCAN_TIMEOUT} airodump-ng --band abg --output-format csv -w /tmp/wifi_scan {WIFI_INTERFACE}"
    subprocess.run(cmd, shell=True, capture_output=True)
    networks = []
    try:
        with open('/tmp/wifi_scan-01.csv', 'r') as f:
            content = f.read()
        if 'Station MAC' in content:
            content = content.split('Station MAC')[0]
        for line in content.split('\\n'):
            if ',' in line and 'BSSID' not in line:
                parts = line.split(',')
                if len(parts) > 13:
                    essid = parts[13].strip()
                    power = parts[8].strip()
                    if essid and power:
                        networks.append(f"{essid[:14]} {power}dBm")
    except:
        pass
    return networks[:8]

def main():
    show(["WiFi Scanner Ready", "", "KEY1: Scan Networks", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            networks = scan_networks()
            if networks:
                show(["Networks Found:"] + networks)
            else:
                show(["No networks found", "Check interface"])
            time.sleep(3)
            show(["WiFi Scanner Ready", "", "KEY1: Scan Networks", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("WiFi Scanner: exited cleanly.")
`
    },
    {
      id: 'ble-scanner', name: 'BLE Device Scanner', category: 'ble', filename: 'ble_scanner.py',
      description: 'Discover nearby Bluetooth Low Energy devices',
      code: `#!/usr/bin/env python3
"""
RaspyJack BLE Scanner
=====================
Scans for nearby BLE devices and displays them.
Press KEY1 to scan, KEY3 to exit.
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
SCAN_DURATION = 10

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show(lines):
    if isinstance(lines, str):
        lines = [lines]
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 5
    for line in lines[:9]:
        draw.text((4, y), line[:21], font=font, fill="#00FFFF")
        y += 13
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def scan_ble():
    show(["Scanning BLE...", f"Duration: {SCAN_DURATION}s"])
    devices = []
    try:
        from bluepy.btle import Scanner, DefaultDelegate
        class ScanDelegate(DefaultDelegate):
            def __init__(self):
                DefaultDelegate.__init__(self)
        scanner = Scanner().withDelegate(ScanDelegate())
        found = scanner.scan(SCAN_DURATION)
        for dev in found:
            name = dev.getValueText(9) or dev.addr[:8]
            rssi = dev.rssi
            devices.append(f"{name[:12]} {rssi}dB")
    except ImportError:
        show(["bluepy not found!", "Install with:", "pip3 install bluepy"])
        time.sleep(3)
    except Exception as e:
        show(["Scan error:", str(e)[:18]])
        time.sleep(2)
    return devices[:7]

def main():
    show(["BLE Scanner Ready", "", "KEY1: Scan Devices", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            devices = scan_ble()
            if devices:
                show(["Devices Found:"] + devices)
            else:
                show(["No devices found"])
            time.sleep(3)
            show(["BLE Scanner Ready", "", "KEY1: Scan Devices", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("BLE Scanner: exited cleanly.")
`
    },
    {
      id: 'network-nmap', name: 'Network Nmap Scanner', category: 'network', filename: 'nmap_scanner.py',
      description: 'Run Nmap scans on the local network with auto-scheduling',
      code: `#!/usr/bin/env python3
"""
RaspyJack Nmap Scanner
======================
Run network scans and save results to loot directory.
KEY1: Run scan now, KEY2: Toggle auto-scan, KEY3: Exit
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import subprocess
import threading
from datetime import datetime
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
INTERFACE = "eth0"
LOOT_DIR = "/root/Raspyjack/loot/Nmap/"
SCAN_INTERVAL = 3600

os.makedirs(LOOT_DIR, exist_ok=True)

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True
auto_scan = False
scan_stop = threading.Event()

def cleanup(*_):
    global running
    running = False
    scan_stop.set()

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show(lines):
    if isinstance(lines, str):
        lines = [lines]
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 10
    for line in lines[:8]:
        w = draw.textbbox((0, 0), line, font=font)[2]
        draw.text(((WIDTH - w) // 2, y), line, font=font, fill="#FF6600")
        y += 14
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def get_target():
    cmd = f"ip -4 addr show {INTERFACE} | awk '/inet / {{ print $2 }}'"
    return subprocess.check_output(cmd, shell=True).decode().strip()

def run_scan():
    target = get_target()
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output = f"{LOOT_DIR}scan_{ts}.txt"
    show(["Nmap Scan", "Running...", target])
    subprocess.run(["nmap", "-T4", "-oN", output, target], check=True)
    show(["Scan Complete!", ts])
    time.sleep(2)

def auto_scan_loop():
    while not scan_stop.is_set():
        if auto_scan:
            run_scan()
        scan_stop.wait(SCAN_INTERVAL)

def main():
    global auto_scan
    thread = threading.Thread(target=auto_scan_loop, daemon=True)
    thread.start()
    show(["Nmap Scanner", "", "KEY1: Scan Now", "KEY2: Auto Toggle", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            run_scan()
            show(["Nmap Scanner", f"Auto: {'ON' if auto_scan else 'OFF'}", "KEY1: Scan Now", "KEY2: Auto Toggle", "KEY3: Exit"])
        elif btn == "KEY2":
            while pressed_button(): time.sleep(0.05)
            auto_scan = not auto_scan
            show([f"Auto Scan: {'ON' if auto_scan else 'OFF'}"])
            time.sleep(1)
            show(["Nmap Scanner", f"Auto: {'ON' if auto_scan else 'OFF'}", "KEY1: Scan Now", "KEY2: Auto Toggle", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        main()
    finally:
        scan_stop.set()
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Nmap Scanner: exited cleanly.")
`
    },
    {
      id: 'honeypot-basic', name: 'Basic Honeypot', category: 'honeypot', filename: 'honeypot.py',
      description: 'Listen for connections on common ports and log them',
      code: `#!/usr/bin/env python3
"""
RaspyJack Basic Honeypot
========================
Listens on common ports and logs connection attempts.
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import socket
import json
import threading
from datetime import datetime
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}
PORTS = [22, 23, 80, 8080]
LOOT_DIR = "/root/Raspyjack/loot/honeypot/"
LOG_FILE = LOOT_DIR + "connections.jsonl"

os.makedirs(LOOT_DIR, exist_ok=True)

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True
connections = []

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show(lines):
    if isinstance(lines, str):
        lines = [lines]
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 10
    for line in lines[:8]:
        w = draw.textbbox((0, 0), line, font=font)[2]
        draw.text(((WIDTH - w) // 2, y), line, font=font, fill="#FF0000")
        y += 14
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def log_connection(port, ip):
    entry = {"time": datetime.now().isoformat(), "port": port, "ip": ip}
    connections.append(entry)
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + "\\n")

def port_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1)
        while running:
            try:
                conn, addr = sock.accept()
                log_connection(port, addr[0])
                conn.close()
            except socket.timeout:
                pass
    except Exception as e:
        print(f"Port {port}: {e}")
    finally:
        sock.close()

def main():
    show(["Honeypot Starting", f"Ports: {len(PORTS)}"])
    for port in PORTS:
        t = threading.Thread(target=port_listener, args=(port,), daemon=True)
        t.start()
    time.sleep(1)
    while running:
        btn = pressed_button()
        if btn == "KEY3":
            break
        show(["Honeypot Active", f"Ports: {', '.join(map(str, PORTS))}", f"Hits: {len(connections)}", "", "KEY3: Exit"])
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print(f"Honeypot: exited. {len(connections)} connections logged.")
`
    },
    {
      id: 'utility-menu', name: 'Menu Template', category: 'utility', filename: 'menu_template.py',
      description: 'Basic menu navigation template with LCD and buttons',
      code: `#!/usr/bin/env python3
"""
RaspyJack Menu Template
=======================
A basic menu navigation template with multiple screens.
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

MENU_ITEMS = ["Option 1", "Option 2", "Option 3", "Option 4", "Exit"]

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True
selected = 0

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def show_menu():
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    draw.text((4, 4), "== MENU ==", font=font, fill="#00FF00")
    y = 24
    for i, item in enumerate(MENU_ITEMS):
        if i == selected:
            draw.rectangle((2, y-2, WIDTH-2, y+12), outline="#00FF00")
            draw.text((8, y), f"> {item}", font=font, fill="#00FF00")
        else:
            draw.text((8, y), f"  {item}", font=font, fill="#888888")
        y += 16
    LCD.LCD_ShowImage(canvas, 0, 0)

def show_action(text):
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    w = draw.textbbox((0, 0), text, font=font)[2]
    draw.text(((WIDTH - w) // 2, HEIGHT // 2 - 7), text, font=font, fill="#FFFF00")
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def handle_selection():
    global running
    item = MENU_ITEMS[selected]
    if item == "Exit":
        running = False
        return
    show_action(f"Running: {item}")
    time.sleep(2)

def main():
    global selected
    show_menu()
    while running:
        btn = pressed_button()
        if btn == "UP":
            while pressed_button(): time.sleep(0.05)
            selected = (selected - 1) % len(MENU_ITEMS)
            show_menu()
        elif btn == "DOWN":
            while pressed_button(): time.sleep(0.05)
            selected = (selected + 1) % len(MENU_ITEMS)
            show_menu()
        elif btn == "OK" or btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            handle_selection()
            if running:
                show_menu()
        elif btn == "KEY3":
            break
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("Menu Template: exited cleanly.")
`
    },
    {
      id: 'utility-status', name: 'System Status Display', category: 'utility', filename: 'system_status.py',
      description: 'Display system stats like CPU, memory, and network',
      code: `#!/usr/bin/env python3
"""
RaspyJack System Status
=======================
Display CPU, memory, disk, and network information.
"""

import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import time
import signal
import subprocess
import RPi.GPIO as GPIO
import LCD_1in44
from PIL import Image, ImageDraw, ImageFont
from payloads._input_helper import get_button

PINS = {"UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26, "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16}

GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def get_cpu_temp():
    try:
        temp = subprocess.check_output(["vcgencmd", "measure_temp"]).decode()
        return temp.replace("temp=", "").strip()
    except:
        return "N/A"

def get_cpu_usage():
    try:
        usage = subprocess.check_output(["top", "-bn1"]).decode()
        for line in usage.split("\\n"):
            if "Cpu(s)" in line or "%Cpu" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if "id" in p or "idle" in parts[i+1:i+2]:
                        idle = float(parts[i-1].replace(",", "."))
                        return f"{100 - idle:.1f}%"
        return "N/A"
    except:
        return "N/A"

def get_memory():
    try:
        mem = subprocess.check_output(["free", "-m"]).decode()
        for line in mem.split("\\n"):
            if "Mem:" in line:
                parts = line.split()
                total = int(parts[1])
                used = int(parts[2])
                return f"{used}MB / {total}MB"
        return "N/A"
    except:
        return "N/A"

def get_disk():
    try:
        disk = subprocess.check_output(["df", "-h", "/"]).decode()
        for line in disk.split("\\n"):
            if "/" in line:
                parts = line.split()
                return f"{parts[2]} / {parts[1]}"
        return "N/A"
    except:
        return "N/A"

def get_ip():
    try:
        ip = subprocess.check_output(["hostname", "-I"]).decode().strip()
        return ip.split()[0] if ip else "No IP"
    except:
        return "N/A"

def show_status():
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    lines = [
        "== SYSTEM STATUS ==",
        f"CPU: {get_cpu_usage()}",
        f"Temp: {get_cpu_temp()}",
        f"Mem: {get_memory()}",
        f"Disk: {get_disk()}",
        f"IP: {get_ip()}",
        "",
        "KEY3: Exit"
    ]
    y = 4
    for line in lines:
        color = "#00FF00" if "==" in line else "#AAFFAA"
        draw.text((4, y), line, font=font, fill=color)
        y += 14
    LCD.LCD_ShowImage(canvas, 0, 0)

def pressed_button():
    return get_button(PINS, GPIO)

def main():
    while running:
        show_status()
        for _ in range(20):
            if not running:
                break
            btn = pressed_button()
            if btn == "KEY3":
                return
            time.sleep(0.1)

if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("System Status: exited cleanly.")
`
    }
  ];

  const TEMPLATE_CATEGORIES = [
    { id: 'wifi', name: 'WiFi', icon: 'fa-solid fa-wifi' },
    { id: 'ble', name: 'BLE', icon: 'fa-brands fa-bluetooth-b' },
    { id: 'network', name: 'Network', icon: 'fa-solid fa-network-wired' },
    { id: 'honeypot', name: 'Honeypot', icon: 'fa-solid fa-shield-halved' },
    { id: 'utility', name: 'Utility', icon: 'fa-solid fa-wrench' },
  ];

  // =====================================================================
  //  PAYLOAD WIZARD (ported from raspyjack-ide-studio/PayloadWizard.tsx)
  // =====================================================================
  const WIZARD_TYPES = [
    { id: 'wifi', name: 'WiFi Attack', icon: 'fa-solid fa-wifi', description: 'Scan networks, deauth, probe requests' },
    { id: 'ble', name: 'BLE Scanner', icon: 'fa-brands fa-bluetooth-b', description: 'Bluetooth device scanning and spam' },
    { id: 'network', name: 'Network Tool', icon: 'fa-solid fa-network-wired', description: 'Nmap scans, network analysis' },
    { id: 'honeypot', name: 'Honeypot', icon: 'fa-solid fa-shield-halved', description: 'Trap and log connection attempts' },
    { id: 'utility', name: 'Utility', icon: 'fa-solid fa-wrench', description: 'Custom tool with LCD/buttons' },
  ];

  let wizardStep = 1;
  let wizardConfig = {
    type: 'utility', name: 'my_payload.py',
    wifiScanTimeout: 15, wifiDeauth: false,
    bleScanDuration: 10, bleSpam: false,
    networkNmap: true, networkInterface: 'eth0',
    honeypotPorts: '22, 23, 80, 8080', honeypotDiscord: false,
    utilityLcd: true, utilityButtons: true,
  };

  const wizardModal = document.getElementById('wizardModal');
  const wizardModalClose = document.getElementById('wizardModalClose');
  const wizardStepNum = document.getElementById('wizardStepNum');
  const wizardStepLabel = document.getElementById('wizardStepLabel');
  const wizardDots = [document.getElementById('wizardDot1'), document.getElementById('wizardDot2'), document.getElementById('wizardDot3')];
  const wizardStepContent = document.getElementById('wizardStepContent');
  const wizardBackBtn = document.getElementById('wizardBackBtn');
  const wizardNextBtn = document.getElementById('wizardNextBtn');
  const wizardGenerateBtn = document.getElementById('wizardGenerateBtn');

  function openWizard(){
    wizardStep = 1;
    wizardConfig = { type: 'utility', name: 'my_payload.py', wifiScanTimeout: 15, wifiDeauth: false, bleScanDuration: 10, bleSpam: false, networkNmap: true, networkInterface: 'eth0', honeypotPorts: '22, 23, 80, 8080', honeypotDiscord: false, utilityLcd: true, utilityButtons: true };
    renderWizardStep();
    if (wizardModal) wizardModal.classList.remove('hidden');
  }

  function closeWizard(){
    if (wizardModal) wizardModal.classList.add('hidden');
  }

  function renderWizardStep(){
    if (!wizardStepContent) return;
    // Update header
    const labels = ['Select Type', 'Configure', 'Generate'];
    if (wizardStepNum) wizardStepNum.textContent = wizardStep;
    if (wizardStepLabel) wizardStepLabel.textContent = labels[wizardStep - 1];
    wizardDots.forEach((d, i) => { if (d) d.classList.toggle('active', i < wizardStep); });
    // Show/hide buttons
    if (wizardBackBtn) wizardBackBtn.classList.toggle('hidden', wizardStep === 1);
    if (wizardNextBtn) wizardNextBtn.classList.toggle('hidden', wizardStep === 3);
    if (wizardGenerateBtn) wizardGenerateBtn.classList.toggle('hidden', wizardStep !== 3);

    // Render step content
    if (wizardStep === 1){
      wizardStepContent.innerHTML = WIZARD_TYPES.map(t => `
        <div class="wizard-type-card ${wizardConfig.type === t.id ? 'selected' : ''}" data-wizard-type="${escapeAttr(t.id)}">
          <div class="type-icon"><i class="${escapeAttr(t.icon)} ${wizardConfig.type === t.id ? 'text-emerald-400' : 'text-slate-400'}"></i></div>
          <div class="flex-1">
            <div class="text-sm font-medium text-slate-200">${escapeHtml(t.name)}</div>
            <div class="text-[10px] text-slate-400">${escapeHtml(t.description)}</div>
          </div>
          ${wizardConfig.type === t.id ? '<i class="fa-solid fa-check text-emerald-400"></i>' : ''}
        </div>
      `).join('');
      wizardStepContent.querySelectorAll('.wizard-type-card').forEach(card => {
        card.addEventListener('click', () => {
          wizardConfig.type = card.getAttribute('data-wizard-type');
          renderWizardStep();
        });
      });
    } else if (wizardStep === 2){
      let fields = `
        <div class="space-y-3">
          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Payload Name</label>
            <input type="text" id="wizCfgName" value="${escapeAttr(wizardConfig.name)}" class="w-full rounded-lg bg-slate-900/80 border border-slate-700/70 px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-emerald-400">
          </div>`;
      if (wizardConfig.type === 'wifi'){
        fields += `
          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Scan Timeout (seconds)</label>
            <input type="number" id="wizCfgWifiTimeout" value="${wizardConfig.wifiScanTimeout}" class="w-full rounded-lg bg-slate-900/80 border border-slate-700/70 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-400">
          </div>
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgWifiDeauth" ${wizardConfig.wifiDeauth ? 'checked' : ''} class="rounded border-slate-600">
            Enable deauthentication attacks
          </label>`;
      } else if (wizardConfig.type === 'ble'){
        fields += `
          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Scan Duration (seconds)</label>
            <input type="number" id="wizCfgBleDuration" value="${wizardConfig.bleScanDuration}" class="w-full rounded-lg bg-slate-900/80 border border-slate-700/70 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-400">
          </div>
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgBleSpam" ${wizardConfig.bleSpam ? 'checked' : ''} class="rounded border-slate-600">
            Include BLE spam mode
          </label>`;
      } else if (wizardConfig.type === 'network'){
        fields += `
          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Network Interface</label>
            <input type="text" id="wizCfgNetIface" value="${escapeAttr(wizardConfig.networkInterface)}" class="w-full rounded-lg bg-slate-900/80 border border-slate-700/70 px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-emerald-400">
          </div>
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgNetNmap" ${wizardConfig.networkNmap ? 'checked' : ''} class="rounded border-slate-600">
            Enable Nmap scanning
          </label>`;
      } else if (wizardConfig.type === 'honeypot'){
        fields += `
          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Listen Ports (comma-separated)</label>
            <input type="text" id="wizCfgHoneyPorts" value="${escapeAttr(wizardConfig.honeypotPorts)}" class="w-full rounded-lg bg-slate-900/80 border border-slate-700/70 px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-emerald-400">
          </div>
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgHoneyDiscord" ${wizardConfig.honeypotDiscord ? 'checked' : ''} class="rounded border-slate-600">
            Enable Discord notifications
          </label>`;
      } else {
        fields += `
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgUtilLcd" ${wizardConfig.utilityLcd ? 'checked' : ''} class="rounded border-slate-600">
            Include LCD display helpers
          </label>
          <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="wizCfgUtilBtns" ${wizardConfig.utilityButtons ? 'checked' : ''} class="rounded border-slate-600">
            Include button handling
          </label>`;
      }
      fields += '</div>';
      wizardStepContent.innerHTML = fields;
    } else if (wizardStep === 3){
      const typeInfo = WIZARD_TYPES.find(t => t.id === wizardConfig.type);
      let summary = `<ul class="text-xs text-slate-400 space-y-1 mt-1">
        <li>Type: ${escapeHtml(typeInfo ? typeInfo.name : wizardConfig.type)}</li>`;
      if (wizardConfig.type === 'wifi') summary += `<li>Scan timeout: ${wizardConfig.wifiScanTimeout}s</li><li>Deauth: ${wizardConfig.wifiDeauth ? 'Enabled' : 'Disabled'}</li>`;
      if (wizardConfig.type === 'ble') summary += `<li>Scan duration: ${wizardConfig.bleScanDuration}s</li><li>Spam mode: ${wizardConfig.bleSpam ? 'Enabled' : 'Disabled'}</li>`;
      if (wizardConfig.type === 'network') summary += `<li>Interface: ${escapeHtml(wizardConfig.networkInterface)}</li><li>Nmap: ${wizardConfig.networkNmap ? 'Enabled' : 'Disabled'}</li>`;
      if (wizardConfig.type === 'honeypot') summary += `<li>Ports: ${escapeHtml(wizardConfig.honeypotPorts)}</li><li>Discord: ${wizardConfig.honeypotDiscord ? 'Enabled' : 'Disabled'}</li>`;
      summary += '</ul>';
      wizardStepContent.innerHTML = `
        <div class="p-4 rounded-lg bg-slate-800/30 border border-slate-800/70">
          <div class="font-medium text-sm text-slate-200 flex items-center gap-2">
            <i class="${escapeAttr(typeInfo ? typeInfo.icon : 'fa-solid fa-file')} text-emerald-400"></i>
            ${escapeHtml(wizardConfig.name)}
          </div>
          ${summary}
        </div>
        <p class="text-xs text-slate-400 mt-3">Click "Generate Payload" to create your payload and open it in the editor.</p>`;
    }
  }

  function readWizardFormValues(){
    const nameEl = document.getElementById('wizCfgName');
    if (nameEl) wizardConfig.name = nameEl.value.trim() || 'my_payload.py';
    const wifiTimeout = document.getElementById('wizCfgWifiTimeout');
    if (wifiTimeout) wizardConfig.wifiScanTimeout = parseInt(wifiTimeout.value) || 15;
    const wifiDeauth = document.getElementById('wizCfgWifiDeauth');
    if (wifiDeauth) wizardConfig.wifiDeauth = wifiDeauth.checked;
    const bleDur = document.getElementById('wizCfgBleDuration');
    if (bleDur) wizardConfig.bleScanDuration = parseInt(bleDur.value) || 10;
    const bleSpam = document.getElementById('wizCfgBleSpam');
    if (bleSpam) wizardConfig.bleSpam = bleSpam.checked;
    const netIface = document.getElementById('wizCfgNetIface');
    if (netIface) wizardConfig.networkInterface = netIface.value.trim() || 'eth0';
    const netNmap = document.getElementById('wizCfgNetNmap');
    if (netNmap) wizardConfig.networkNmap = netNmap.checked;
    const honeyPorts = document.getElementById('wizCfgHoneyPorts');
    if (honeyPorts) wizardConfig.honeypotPorts = honeyPorts.value.trim() || '22, 23, 80, 8080';
    const honeyDiscord = document.getElementById('wizCfgHoneyDiscord');
    if (honeyDiscord) wizardConfig.honeypotDiscord = honeyDiscord.checked;
    const utilLcd = document.getElementById('wizCfgUtilLcd');
    if (utilLcd) wizardConfig.utilityLcd = utilLcd.checked;
    const utilBtns = document.getElementById('wizCfgUtilBtns');
    if (utilBtns) wizardConfig.utilityButtons = utilBtns.checked;
  }

  function generatePayloadCode(cfg){
    const imports = [
      '#!/usr/bin/env python3',
      '"""',
      `RaspyJack Payload - ${cfg.name}`,
      'Generated by Raspyjack IDE Studio',
      '"""',
      '',
      '# Allow imports of RaspyJack helper modules',
      'import os, sys',
      "sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))",
      '',
      'import time',
      'import signal',
      'from payloads._input_helper import get_button',
    ].join('\n');

    const gpioSetup = `
# GPIO Configuration (BCM numbering)
import RPi.GPIO as GPIO
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
`;

    const lcdSetup = `
# LCD Initialization
import LCD_1in44, LCD_Config
from PIL import Image, ImageDraw, ImageFont

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = 128, 128
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
canvas = Image.new("RGB", (WIDTH, HEIGHT), "black")
draw = ImageDraw.Draw(canvas)

def show(lines):
    """Display text on LCD."""
    if isinstance(lines, str):
        lines = [lines]
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill="black")
    y = 10
    for line in lines:
        w = draw.textbbox((0, 0), line, font=font)[2]
        draw.text(((WIDTH - w) // 2, y), line, font=font, fill="#00FF00")
        y += 14
    LCD.LCD_ShowImage(canvas, 0, 0)
`;

    const buttonHelper = `
def pressed_button():
    """Return merged WebUI/GPIO button input."""
    return get_button(PINS, GPIO)
`;

    const cleanupHandler = `
# Graceful shutdown
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)
`;

    let typeCode = '';
    if (cfg.type === 'wifi'){
      typeCode = `
# WiFi Configuration
SCAN_TIMEOUT = ${cfg.wifiScanTimeout || 15}
WIFI_INTERFACE = "wlan1"  # External WiFi dongle recommended
${cfg.wifiDeauth ? 'DEAUTH_ENABLED = True' : 'DEAUTH_ENABLED = False'}

def scan_networks():
    """Scan for WiFi networks."""
    import subprocess
    show(["Scanning WiFi...", f"Timeout: {SCAN_TIMEOUT}s"])
    cmd = f"timeout {SCAN_TIMEOUT} airodump-ng --band abg --output-format csv -w /tmp/scan {WIFI_INTERFACE}"
    subprocess.run(cmd, shell=True, capture_output=True)
    networks = []
    try:
        with open('/tmp/scan-01.csv', 'r') as f:
            pass
    except:
        pass
    return networks

def main():
    show(["WiFi Tool Ready", "KEY1: Scan", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            networks = scan_networks()
            show([f"Found {len(networks)} networks"])
            time.sleep(2)
            show(["WiFi Tool Ready", "KEY1: Scan", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)
`;
    } else if (cfg.type === 'ble'){
      typeCode = `
# BLE Configuration
SCAN_DURATION = ${cfg.bleScanDuration || 10}
${cfg.bleSpam ? 'SPAM_MODE = True' : 'SPAM_MODE = False'}

def scan_ble_devices():
    """Scan for BLE devices."""
    show(["Scanning BLE...", f"Duration: {SCAN_DURATION}s"])
    devices = []
    try:
        from bluepy.btle import Scanner
        scanner = Scanner()
        devices = scanner.scan(SCAN_DURATION)
    except ImportError:
        show(["Error:", "bluepy not found"])
        time.sleep(2)
    except Exception as e:
        show(["Scan error:", str(e)[:15]])
        time.sleep(2)
    return devices

def main():
    show(["BLE Tool Ready", "KEY1: Scan", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            devices = scan_ble_devices()
            show([f"Found {len(devices)} devices"])
            time.sleep(2)
            show(["BLE Tool Ready", "KEY1: Scan", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)
`;
    } else if (cfg.type === 'network'){
      typeCode = `
# Network Configuration
INTERFACE = "${cfg.networkInterface || 'eth0'}"
${cfg.networkNmap ? 'NMAP_ENABLED = True' : 'NMAP_ENABLED = False'}
LOOT_DIR = "/root/Raspyjack/loot/Network/"

import subprocess
os.makedirs(LOOT_DIR, exist_ok=True)

def get_local_ip():
    """Get local IP address."""
    cmd = f"ip -4 addr show {INTERFACE} | awk '/inet / {{ print $2 }}'"
    return subprocess.check_output(cmd, shell=True).decode().strip()

def run_nmap_scan():
    """Run Nmap scan on local network."""
    target = get_local_ip()
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    output = f"{LOOT_DIR}scan_{ts}.txt"
    show(["Nmap Scan", "In progress..."])
    subprocess.run(["nmap", "-T4", "-oN", output, target], check=True)
    show(["Scan complete!", ts])
    time.sleep(2)

def main():
    show(["Network Tool", "KEY1: Nmap Scan", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            run_nmap_scan()
            show(["Network Tool", "KEY1: Nmap Scan", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)
`;
    } else if (cfg.type === 'honeypot'){
      typeCode = `
# Honeypot Configuration
PORTS = [${cfg.honeypotPorts || '22, 23, 80, 8080'}]
${cfg.honeypotDiscord ? 'DISCORD_ENABLED = True' : 'DISCORD_ENABLED = False'}
LOOT_DIR = "/root/Raspyjack/loot/honeypot/"
LOG_FILE = LOOT_DIR + "connections.jsonl"

import socket
import json
import threading
os.makedirs(LOOT_DIR, exist_ok=True)

connections = []

def log_connection(port, ip):
    """Log a connection attempt."""
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "port": port, "ip": ip}
    connections.append(entry)
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + "\\n")

def honeypot_listener(port):
    """Listen on a single port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1)
        while running:
            try:
                conn, addr = sock.accept()
                log_connection(port, addr[0])
                conn.close()
            except socket.timeout:
                pass
    except Exception as e:
        print(f"Port {port} error: {e}")
    finally:
        sock.close()

def main():
    show(["Honeypot Starting", f"Ports: {len(PORTS)}"])
    threads = []
    for port in PORTS:
        t = threading.Thread(target=honeypot_listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)
    show(["Honeypot Active", f"Connections: 0", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY3":
            break
        show(["Honeypot Active", f"Connections: {len(connections)}", "KEY3: Exit"])
        time.sleep(1)
`;
    } else {
      typeCode = `
# Custom Utility Payload
def main():
    show(["Utility Ready", "KEY1: Action 1", "KEY2: Action 2", "KEY3: Exit"])
    while running:
        btn = pressed_button()
        if btn == "KEY1":
            while pressed_button(): time.sleep(0.05)
            show(["Action 1", "Executing..."])
            # TODO: Add your action here
            time.sleep(2)
            show(["Utility Ready", "KEY1: Action 1", "KEY2: Action 2", "KEY3: Exit"])
        elif btn == "KEY2":
            while pressed_button(): time.sleep(0.05)
            show(["Action 2", "Executing..."])
            # TODO: Add your action here
            time.sleep(2)
            show(["Utility Ready", "KEY1: Action 1", "KEY2: Action 2", "KEY3: Exit"])
        elif btn == "KEY3":
            break
        time.sleep(0.05)
`;
    }

    const mainBlock = `
if __name__ == "__main__":
    try:
        main()
    finally:
        LCD.LCD_Clear()
        GPIO.cleanup()
        print("${cfg.name}: exited cleanly.")
`;
    return [imports, gpioSetup, lcdSetup, buttonHelper, cleanupHandler, typeCode, mainBlock].join('\n');
  }

  function wizardGenerate(){
    readWizardFormValues();
    const code = generatePayloadCode(wizardConfig);
    ensureEditor();
    if (editor){
      editor.setValue(code);
      setDirty(true);
      // Build a path under the current folder so Save/Run work
      const filename = wizardConfig.name.endsWith('.py') ? wizardConfig.name : wizardConfig.name + '.py';
      const savePath = currentFolder ? `${currentFolder}/${filename}` : filename;
      setSelectedPath(savePath);
    }
    closeWizard();
    setIdeStatus('Payload generated');
  }

  // =====================================================================
  //  TEMPLATE LIBRARY
  // =====================================================================
  const templateModal = document.getElementById('templateModal');
  const templateModalClose = document.getElementById('templateModalClose');
  const tmplCategoryTabs = document.getElementById('tmplCategoryTabs');
  const tmplList = document.getElementById('tmplList');
  const tmplPreviewEmpty = document.getElementById('tmplPreviewEmpty');
  const tmplPreviewContent = document.getElementById('tmplPreviewContent');
  const tmplPreviewName = document.getElementById('tmplPreviewName');
  const tmplPreviewFile = document.getElementById('tmplPreviewFile');
  const tmplPreviewCode = document.getElementById('tmplPreviewCode');
  const tmplUseBtn = document.getElementById('tmplUseBtn');

  let tmplActiveCategory = 'wifi';
  let tmplSelectedId = null;

  function openTemplateLibrary(){
    tmplActiveCategory = 'wifi';
    tmplSelectedId = null;
    renderTemplateTabs();
    renderTemplateList();
    renderTemplatePreview();
    if (templateModal) templateModal.classList.remove('hidden');
  }

  function closeTemplateLibrary(){
    if (templateModal) templateModal.classList.add('hidden');
  }

  function renderTemplateTabs(){
    if (!tmplCategoryTabs) return;
    tmplCategoryTabs.innerHTML = TEMPLATE_CATEGORIES.map(cat => `
      <div class="tmpl-category-tab ${tmplActiveCategory === cat.id ? 'active' : ''}" data-tmpl-cat="${escapeAttr(cat.id)}">
        <i class="${escapeAttr(cat.icon)} text-[10px]"></i>
        <span class="hidden sm:inline ml-1">${escapeHtml(cat.name)}</span>
      </div>
    `).join('');
    tmplCategoryTabs.querySelectorAll('.tmpl-category-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        tmplActiveCategory = tab.getAttribute('data-tmpl-cat');
        tmplSelectedId = null;
        renderTemplateTabs();
        renderTemplateList();
        renderTemplatePreview();
      });
    });
  }

  function renderTemplateList(){
    if (!tmplList) return;
    const filtered = TEMPLATES_DATA.filter(t => t.category === tmplActiveCategory);
    tmplList.innerHTML = filtered.map(t => {
      const cat = TEMPLATE_CATEGORIES.find(c => c.id === t.category);
      return `
        <div class="tmpl-card ${tmplSelectedId === t.id ? 'selected' : ''}" data-tmpl-id="${escapeAttr(t.id)}">
          <div class="flex items-start gap-2">
            <i class="${escapeAttr(cat ? cat.icon : 'fa-solid fa-file')} text-xs mt-0.5 ${tmplSelectedId === t.id ? 'text-emerald-400' : 'text-slate-400'}"></i>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-xs font-medium text-slate-200">${escapeHtml(t.name)}</span>
                ${tmplSelectedId === t.id ? '<i class="fa-solid fa-check text-emerald-400 text-[10px]"></i>' : ''}
              </div>
              <div class="text-[10px] text-slate-400 line-clamp-2">${escapeHtml(t.description)}</div>
              <div class="text-[9px] font-mono text-emerald-400/60 mt-0.5">${escapeHtml(t.filename)}</div>
            </div>
          </div>
        </div>`;
    }).join('');
    tmplList.querySelectorAll('.tmpl-card').forEach(card => {
      card.addEventListener('click', () => {
        tmplSelectedId = card.getAttribute('data-tmpl-id');
        renderTemplateList();
        renderTemplatePreview();
      });
    });
  }

  function renderTemplatePreview(){
    const tmpl = TEMPLATES_DATA.find(t => t.id === tmplSelectedId);
    if (!tmpl){
      if (tmplPreviewEmpty) tmplPreviewEmpty.classList.remove('hidden');
      if (tmplPreviewContent) tmplPreviewContent.classList.add('hidden');
      return;
    }
    if (tmplPreviewEmpty) tmplPreviewEmpty.classList.add('hidden');
    if (tmplPreviewContent) tmplPreviewContent.classList.remove('hidden');
    if (tmplPreviewName) tmplPreviewName.textContent = tmpl.name;
    if (tmplPreviewFile) tmplPreviewFile.textContent = tmpl.filename;
    if (tmplPreviewCode) tmplPreviewCode.textContent = tmpl.code;
  }

  function useSelectedTemplate(){
    const tmpl = TEMPLATES_DATA.find(t => t.id === tmplSelectedId);
    if (!tmpl) return;
    ensureEditor();
    if (editor){
      editor.setValue(tmpl.code);
      setDirty(true);
      // Build a path under the current folder so Save/Run work
      const savePath = currentFolder ? `${currentFolder}/${tmpl.filename}` : tmpl.filename;
      setSelectedPath(savePath);
    }
    closeTemplateLibrary();
    setIdeStatus('Template loaded');
  }

  // =====================================================================
  //  GPIO REFERENCE PANEL
  // =====================================================================
  let gpioPanelEl = null;
  let gpioPanelVisible = false;

  function initGpioPanel(){
    const template = document.getElementById('gpioPanelTemplate');
    if (!template) return;
    const clone = template.content.cloneNode(true);
    gpioPanelEl = clone.querySelector('#gpioPanel');
    // Insert into main layout before the right preview section
    const mainEl = document.querySelector('main');
    const previewSection = mainEl ? mainEl.querySelector('section:last-child') : null;
    if (mainEl && previewSection){
      mainEl.insertBefore(gpioPanelEl, previewSection);
    }
    // Wire section toggles
    if (gpioPanelEl){
      gpioPanelEl.querySelectorAll('.gpio-section-header').forEach(header => {
        header.addEventListener('click', () => {
          const section = header.getAttribute('data-gpio-section');
          const body = gpioPanelEl.querySelector(`[data-gpio-body="${section}"]`);
          const chevron = header.querySelector('.gpio-chevron');
          if (body){
            body.classList.toggle('hidden');
            if (chevron){
              chevron.classList.toggle('fa-chevron-down', !body.classList.contains('hidden'));
              chevron.classList.toggle('fa-chevron-right', body.classList.contains('hidden'));
              chevron.classList.toggle('text-emerald-400', !body.classList.contains('hidden'));
              chevron.classList.toggle('text-slate-400', body.classList.contains('hidden'));
            }
          }
        });
      });
      // Wire copy buttons
      gpioPanelEl.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const codeBlock = btn.closest('.gpio-code-block');
          if (codeBlock){
            // Get text content without the button text
            const text = codeBlock.childNodes[0].textContent.trim();
            navigator.clipboard.writeText(text).then(() => {
              btn.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i>';
              setTimeout(() => { btn.innerHTML = '<i class="fa-regular fa-copy"></i>'; }, 1500);
            });
          }
        });
      });
      // Wire close button
      const closeBtn = gpioPanelEl.querySelector('#gpioPanelClose');
      if (closeBtn){
        closeBtn.addEventListener('click', () => toggleGpioPanel());
      }
    }
  }

  function toggleGpioPanel(){
    if (!gpioPanelEl) initGpioPanel();
    if (!gpioPanelEl) return;
    gpioPanelVisible = !gpioPanelVisible;
    gpioPanelEl.classList.toggle('hidden', !gpioPanelVisible);
    gpioPanelEl.classList.toggle('flex', gpioPanelVisible);
    // Update toolbar button active state
    const gpioToggleBtn = document.getElementById('gpioToggleBtn');
    if (gpioToggleBtn) gpioToggleBtn.classList.toggle('active', gpioPanelVisible);
  }

  // =====================================================================
  //  TOOLBAR WIRING
  // =====================================================================
  const wizardBtn = document.getElementById('wizardBtn');
  const templatesBtn = document.getElementById('templatesBtn');
  const gpioToggleBtnEl = document.getElementById('gpioToggleBtn');

  if (wizardBtn) wizardBtn.addEventListener('click', () => openWizard());
  if (templatesBtn) templatesBtn.addEventListener('click', () => openTemplateLibrary());
  if (gpioToggleBtnEl) gpioToggleBtnEl.addEventListener('click', () => toggleGpioPanel());

  // Wizard modal events
  if (wizardModalClose) wizardModalClose.addEventListener('click', () => closeWizard());
  if (wizardModal) wizardModal.addEventListener('click', (e) => { if (e.target === wizardModal) closeWizard(); });
  if (wizardBackBtn) wizardBackBtn.addEventListener('click', () => {
    if (wizardStep === 2) readWizardFormValues();
    wizardStep = Math.max(1, wizardStep - 1);
    renderWizardStep();
  });
  if (wizardNextBtn) wizardNextBtn.addEventListener('click', () => {
    if (wizardStep === 2) readWizardFormValues();
    wizardStep = Math.min(3, wizardStep + 1);
    renderWizardStep();
  });
  if (wizardGenerateBtn) wizardGenerateBtn.addEventListener('click', () => wizardGenerate());

  // Template modal events
  if (templateModalClose) templateModalClose.addEventListener('click', () => closeTemplateLibrary());
  if (templateModal) templateModal.addEventListener('click', (e) => { if (e.target === templateModal) closeTemplateLibrary(); });
  if (tmplUseBtn) tmplUseBtn.addEventListener('click', () => useSelectedTemplate());

  // ------------------------ Event bindings ------------------------
  if (refreshTreeBtn) refreshTreeBtn.addEventListener('click', () => loadTree());
  if (newFileBtn) newFileBtn.addEventListener('click', () => createEntry('file'));
  if (newFolderBtn) newFolderBtn.addEventListener('click', () => createEntry('dir'));
  if (saveBtn) saveBtn.addEventListener('click', () => saveCurrentFile());
  if (runBtn) runBtn.addEventListener('click', () => runCurrentPayload());
  if (stopBtn) stopBtn.addEventListener('click', () => stopCurrentPayload());
  if (restartUiBtn) restartUiBtn.addEventListener('click', () => restartUi());

  // Context menu for rename/delete on files and folders
  if (treeContainer){
    treeContainer.addEventListener('contextmenu', (e) => {
      const node = e.target.closest('.file-node, .folder-node');
      if (!node) return;
      e.preventDefault();
      const path = node.getAttribute('data-path') || '';
      if (!path) return;
      const type = node.classList.contains('folder-node') ? 'dir' : 'file';
      showContextMenu(e.clientX, e.clientY, path, type);
    });
  }

  if (ctxRenameBtn){
    ctxRenameBtn.addEventListener('click', () => {
      if (ctxTargetPath){
        renameEntry(ctxTargetPath);
      }
      hideContextMenu();
    });
  }

  if (ctxDeleteBtn){
    ctxDeleteBtn.addEventListener('click', () => {
      if (ctxTargetPath){
        deleteEntry(ctxTargetPath);
      }
      hideContextMenu();
    });
  }

  document.addEventListener('click', (e) => {
    if (!treeContextMenu || treeContextMenu.classList.contains('hidden')) return;
    if (!e.target.closest('#treeContextMenuPanel')){
      hideContextMenu();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape'){
      hideContextMenu();
      closeWizard();
      closeTemplateLibrary();
    }
  });

  window.addEventListener('scroll', () => {
    hideContextMenu();
  }, true);

  if (entryModalCancel) entryModalCancel.addEventListener('click', () => closeEntryModal());
  if (entryModalClose) entryModalClose.addEventListener('click', () => closeEntryModal());
  if (entryModalConfirm) entryModalConfirm.addEventListener('click', () => handleEntryConfirm());
  if (entryModal && entryModalName){
    entryModal.addEventListener('click', (e) => {
      if (e.target === entryModal) closeEntryModal();
    });
    entryModalName.addEventListener('keydown', (e) => {
      if (e.key === 'Enter'){
        e.preventDefault();
        handleEntryConfirm();
      } else if (e.key === 'Escape'){
        e.preventDefault();
        closeEntryModal();
      }
    });
  }

  if (renameModalCancel) renameModalCancel.addEventListener('click', () => closeRenameModal());
  if (renameModalClose) renameModalClose.addEventListener('click', () => closeRenameModal());
  if (renameModalConfirm) renameModalConfirm.addEventListener('click', () => handleRenameConfirm());
  if (renameModal && renameModalName){
    renameModal.addEventListener('click', (e) => {
      if (e.target === renameModal) closeRenameModal();
    });
    renameModalName.addEventListener('keydown', (e) => {
      if (e.key === 'Enter'){
        e.preventDefault();
        handleRenameConfirm();
      } else if (e.key === 'Escape'){
        e.preventDefault();
        closeRenameModal();
      }
    });
  }

  if (deleteModalCancel) deleteModalCancel.addEventListener('click', () => closeDeleteModal());
  if (deleteModalClose) deleteModalClose.addEventListener('click', () => closeDeleteModal());
  if (deleteModalConfirm) deleteModalConfirm.addEventListener('click', () => handleDeleteConfirm());
  if (deleteModal){
    deleteModal.addEventListener('click', (e) => {
      if (e.target === deleteModal) closeDeleteModal();
    });
    deleteModal.addEventListener('keydown', (e) => {
      if (e.key === 'Escape'){
        e.preventDefault();
        closeDeleteModal();
      }
    });
  }
  if (restartUiModalConfirm) restartUiModalConfirm.addEventListener('click', () => resolveRestartUiPrompt(true));
  if (restartUiModalCancel) restartUiModalCancel.addEventListener('click', () => resolveRestartUiPrompt(false));
  if (restartUiModalClose) restartUiModalClose.addEventListener('click', () => resolveRestartUiPrompt(false));
  if (restartUiModal) restartUiModal.addEventListener('click', (e) => {
    if (e.target === restartUiModal) resolveRestartUiPrompt(false);
  });
  if (unsavedModalConfirm) unsavedModalConfirm.addEventListener('click', () => resolveUnsavedPrompt(true));
  if (unsavedModalCancel) unsavedModalCancel.addEventListener('click', () => resolveUnsavedPrompt(false));
  if (unsavedModalClose) unsavedModalClose.addEventListener('click', () => resolveUnsavedPrompt(false));
  if (unsavedModal) unsavedModal.addEventListener('click', (e) => {
    if (e.target === unsavedModal) resolveUnsavedPrompt(false);
  });
  if (saveBeforeRunModalConfirm) saveBeforeRunModalConfirm.addEventListener('click', () => resolveSaveBeforeRunPrompt(true));
  if (saveBeforeRunModalCancel) saveBeforeRunModalCancel.addEventListener('click', () => resolveSaveBeforeRunPrompt(false));
  if (saveBeforeRunModalClose) saveBeforeRunModalClose.addEventListener('click', () => resolveSaveBeforeRunPrompt(false));
  if (saveBeforeRunModal) saveBeforeRunModal.addEventListener('click', (e) => {
    if (e.target === saveBeforeRunModal) resolveSaveBeforeRunPrompt(false);
  });
  if (noticeModalConfirm) noticeModalConfirm.addEventListener('click', () => resolveNoticePrompt());
  if (noticeModalClose) noticeModalClose.addEventListener('click', () => resolveNoticePrompt());
  if (noticeModal) noticeModal.addEventListener('click', (e) => {
    if (e.target === noticeModal) resolveNoticePrompt();
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

  window.addEventListener('beforeunload', (e) => {
    if (isDirty){
      e.preventDefault();
      e.returnValue = '';
      return '';
    }
  });

  // ------------------------ Resize handle ------------------------
  let isResizing = false;
  let startX = 0;
  let startWidth = 0;

  function startResize(e){
    if (!leftPanel) return;
    isResizing = true;
    startX = e.clientX || (e.touches && e.touches[0].clientX) || 0;
    startWidth = leftPanel.offsetWidth;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  }

  function doResize(e){
    if (!isResizing || !leftPanel) return;
    const currentX = e.clientX || (e.touches && e.touches[0].clientX) || 0;
    const diff = currentX - startX;
    const newWidth = startWidth + diff;
    const minWidth = 200;
    const maxWidth = window.innerWidth * 0.5; // Max 50% of window width
    const clampedWidth = Math.max(minWidth, Math.min(maxWidth, newWidth));
    leftPanel.style.width = `${clampedWidth}px`;
    leftPanel.style.flexShrink = '0';
    e.preventDefault();
  }

  function stopResize(){
    isResizing = false;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }

  if (resizeHandle && leftPanel){
    resizeHandle.addEventListener('mousedown', startResize);
    resizeHandle.addEventListener('touchstart', startResize);
    document.addEventListener('mousemove', doResize);
    document.addEventListener('touchmove', doResize);
    document.addEventListener('mouseup', stopResize);
    document.addEventListener('touchend', stopResize);
  }
  if (logoutBtn) logoutBtn.addEventListener('click', logoutUser);

  // ------------------------ Init ------------------------
  loadAuthToken();
  setupHiDPI();
  bindButtons();
  updatePayloadRunUi();

  let payloadPollTimer = null;

  function schedulePayloadPoll(){
    if (payloadPollTimer) clearTimeout(payloadPollTimer);
    const delay = document.hidden ? 6000 : 1500;
    payloadPollTimer = setTimeout(async () => {
      await pollPayloadStatus();
      schedulePayloadPoll();
    }, delay);
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden){
      pollPayloadStatus();
    }
    schedulePayloadPoll();
  });

  const startAfterAuth = () => {
    ensureAuthenticated('Log in to access Payload Studio.').then((ok) => {
      if (!ok){
        setTimeout(startAfterAuth, 0);
        return;
      }
      connectWs();
      loadTree();
      pollPayloadStatus();
      schedulePayloadPoll();
      ensureEditor();
    });
  };
  startAfterAuth();
})();

