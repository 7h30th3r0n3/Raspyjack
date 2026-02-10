(function(){
  // ------------------------ DOM references ------------------------
  const ideStatusEl = document.getElementById('ideStatus');
  const treeContainer = document.getElementById('treeContainer');
  const refreshTreeBtn = document.getElementById('refreshTree');
  const newFileBtn = document.getElementById('newFileBtn');
  const newFolderBtn = document.getElementById('newFolderBtn');
  const currentPathEl = document.getElementById('currentPath');
  const dirtyFlagEl = document.getElementById('dirtyFlag');
  const saveBtn = document.getElementById('saveBtn');
  const runBtn = document.getElementById('runBtn');
  const editorTextarea = document.getElementById('editor');
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

  // ------------------------ Helpers ------------------------
  function setIdeStatus(text){
    if (ideStatusEl) ideStatusEl.textContent = text;
  }

  function getSearchParams(){
    try {
      return new URLSearchParams(location.search);
    } catch {
      return new URLSearchParams();
    }
  }

  function getApiUrl(path, params = {}){
    const p = getSearchParams();
    const token = p.get('token');
    if (token) params.token = token;
    const qs = new URLSearchParams(params).toString();
    const base = location.origin;
    return `${base}${path}${qs ? `?${qs}` : ''}`;
  }

  function getWsUrl(){
    const p = getSearchParams();
    const token = p.get('token');
    const host = location.hostname || 'raspberrypi.local';
    const port = p.get('port') || '8765';
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const q = token ? `?token=${encodeURIComponent(token)}` : '';
    return `${proto}://${host}:${port}/${q}`.replace(/\/\/\//,'//');
  }

  function bytesFromString(s){
    return new TextEncoder().encode(s).length;
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
      const res = await fetch(url, { cache: 'no-store' });
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
      const ok = window.confirm('You have unsaved changes. Discard and open another file?');
      if (!ok) return;
    }
    setIdeStatus('Loading file...');
    try{
      const url = getApiUrl('/api/payloads/file', { path });
      const res = await fetch(url, { cache: 'no-store' });
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
      window.alert('File is too large to save via WebUI (limit 512 KB).');
      return false;
    }
    setIdeStatus('Saving...');
    try{
      const url = getApiUrl('/api/payloads/file');
      const res = await fetch(url, {
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
      window.alert('Failed to save file.');
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
      const res = await fetch(url, {
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
      window.alert(`Failed to create ${type}.`);
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
      const res = await fetch(url, {
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
      window.alert('Failed to rename entry.');
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

  async function deleteEntry(path){
    if (!path) return;
    const ok = window.confirm(`Delete "${path}"? This cannot be undone.`);
    if (!ok) return;
    setIdeStatus('Deleting...');
    try{
      const url = getApiUrl('/api/payloads/entry', { path });
      const res = await fetch(url, { method: 'DELETE' });
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
      window.alert('Failed to delete entry.');
    }
  }

  // ------------------------ Run payload ------------------------
  async function runCurrentPayload(){
    if (!selectedPath) return;
    // if dirty, offer to save first
    if (isDirty){
      const ok = window.confirm('Save changes before running?');
      if (!ok) return;
      const saved = await saveCurrentFile();
      if (!saved) return;
    }
    setIdeStatus('Starting payload...');
    try{
      const url = getApiUrl('/api/payloads/run');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: selectedPath })
      });
      const data = await res.json();
      if (!res.ok || !data.ok){
        throw new Error(data.error || 'run_failed');
      }
      setIdeStatus('Payload launched');
    }catch(e){
      console.error(e);
      setIdeStatus('Run failed');
      window.alert('Failed to start payload.');
    }
  }

  // ------------------------ WebSocket preview & input ------------------------
  let ws = null;
  let reconnectTimer = null;

  function setWsStatus(text){
    if (wsStatusEl) wsStatusEl.textContent = text;
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
    };

    ws.onmessage = (ev) => {
      try{
        const msg = JSON.parse(ev.data);
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

  // ------------------------ Event bindings ------------------------
  if (refreshTreeBtn) refreshTreeBtn.addEventListener('click', () => loadTree());
  if (newFileBtn) newFileBtn.addEventListener('click', () => createEntry('file'));
  if (newFolderBtn) newFolderBtn.addEventListener('click', () => createEntry('dir'));
  if (saveBtn) saveBtn.addEventListener('click', () => saveCurrentFile());
  if (runBtn) runBtn.addEventListener('click', () => runCurrentPayload());

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

  window.addEventListener('beforeunload', (e) => {
    if (isDirty){
      e.preventDefault();
      e.returnValue = '';
      return '';
    }
  });

  // ------------------------ Init ------------------------
  setupHiDPI();
  bindButtons();
  connectWs();
  loadTree();
  ensureEditor();
})();

