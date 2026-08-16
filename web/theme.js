(function () {
  var saved = localStorage.getItem("rj-theme") || "dark";
  window._rjTheme = saved;
  window._rjSetTheme = function (n) {
    localStorage.setItem("rj-theme", n);
    location.reload();
  };
  if (saved !== "light") return;

  // CSS variables
  var r = document.documentElement;
  r.style.colorScheme = "light";
  var v = {
    "--bg": "#f0f2f5",
    "--bg2": "#ffffff",
    "--bg3": "#f5f6f8",
    "--dim": "#6a7a8a",
    "--gdim": "#007a42",
    "--blue": "#0066aa",
    "--text": "#111827",
    "--panel": "#f8f9fb",
    "--border": "#c0c8d0",
    "--accent": "#0066aa",
    "--green": "#007a42",
    "--red": "#bb2233",
    "--orange": "#bb5500",
    "--yellow": "#887700",
    "--card": "#fff",
    "--text-dim": "#4b5563",
    "--topbar": "#e2e6ec",
    "--input-bg": "#fff",
    "--input-border": "#b0b8c4",
    "--gps": "#0066aa",
    "--glo": "#bb4400",
    "--gal": "#007744",
    "--bds": "#887700",
    "--rj-bg-0": "#f0f2f5",
    "--rj-bg-1": "#eaecf0",
    "--rj-bg-2": "#e0e4ea",
    "--rj-surface": "rgba(255,255,255,.8)",
    "--rj-surface-strong": "rgba(255,255,255,.92)",
    "--rj-border": "rgba(0,0,0,.15)",
    "--rj-border-strong": "rgba(0,0,0,.22)",
    "--rj-text": "#111827",
    "--rj-text-muted": "#4b5563",
    "--rj-accent": "#007a42",
    "--rj-accent-soft": "rgba(0,122,66,.1)",
    "--rj-danger": "#bb2233",
    "--rj-shadow": "0 2px 8px rgba(0,0,0,.08)",
    "--rj-glow": "none",
  };
  for (var k in v) r.style.setProperty(k, v[k]);

  // Light CSS
  var s = document.createElement("style");
  s.textContent =
    "body{background:var(--rj-bg-0)!important;color:#111827!important}" +
    "#sidebar,aside{background:#e4e8ee!important}" +
    "#sidebar nav>button,#sidebar nav>a,nav button[type=button],nav a.block{background:#fff!important;border-color:#bcc4cc!important;color:#111827!important}" +
    "#sidebar nav>button:hover,#sidebar nav>a:hover{background:#f0f4f8!important}" +
    "#topbar,[id*=topbar]{background:#e2e6ec!important;border-color:#c0c8d0!important}" +
    "#topbar h1,#topbar .text-emerald-300,#topbar .text-emerald-400{color:#007a42!important}" +
    "#topbar a,.text-slate-400,.text-slate-500{color:#4b5563!important}" +
    "#topbar span,.text-slate-200,.text-slate-300,.text-slate-100{color:#111827!important}" +
    "#logoutBtn{background:#fff!important;border-color:#bcc4cc!important;color:#333!important}" +
    "#payloadSearch{background:#fff!important;border-color:#b0b8c4!important;color:#111!important}" +
    "#payloadSidebar>div{background:#fff!important;border-color:#c0c8d0!important}" +
    "#payloadSidebar button{color:#333!important}" +
    ".text-emerald-300,.text-emerald-400{color:#007a42!important}" +
    "#deviceTab .terminal-wrap{border-color:#c0c8d0!important;background:#0a0a0a!important;color:#e0e0e0!important}" +
    ".terminal-wrap *,.xterm *{color:inherit!important;background:inherit!important}" +
    "#settingsTab>div,#lootTab>div{background:rgba(255,255,255,.85)!important;border-color:#c0c8d0!important}" +
    ".rounded-3xl{background:rgba(255,255,255,.85)!important;border-color:#c0c8d0!important}" +
    ".device-shell{border-color:#c0c8d0!important}" +
    "input[type=password],input[type=text]{background:#fff!important;border-color:#b0b8c4!important;color:#111!important}" +
    ".payload-status-dot.running{background:#007a42!important;box-shadow:0 0 6px rgba(0,122,66,.3)!important}" +
    // Sub-pages
    ".mode-btn,.tb,.pill,.tune-btn,.fm-btn,.tab-btn,.main-tab,.cf,.c-chip,.live-btn,.status-badge,.fix-badge{background:#fff!important;border-color:#b0b8c4!important;color:#333!important}" +
    ".mode-btn:hover,.tb:hover,.pill:hover,.tab-btn:hover,.main-tab:hover{background:#e8ecf0!important}" +
    ".mode-btn.active,.tb.on,.pill.on,.tab-btn.on,.main-tab.on,.cf.on,.c-chip.on,.live-btn.on{border-color:#0066aa!important;color:#0066aa!important;background:#e8f4ff!important}" +
    ".fix-3d{background:#e8fff0!important;border-color:#007a42!important;color:#007a42!important}" +
    ".fix-no{background:#ffe8e8!important;border-color:#bb2233!important;color:#bb2233!important}" +
    ".status-waiting{background:#fff8e0!important;color:#886600!important;border-color:#cc9900!important}" +
    ".status-capturing{background:#ffe8e8!important;color:#992233!important;border-color:#cc3344!important}" +
    ".card,.sat-card,.dev-card,.kpi-card,.stat-card,.ism-dev{background:#fff!important;border-color:#c0c8d0!important}" +
    "#panel,#pLeft,#pRight,#rightPanel,.tab-content,.sub-pane{background:#f5f6f8!important;border-color:#c0c8d0!important}" +
    "#bbar,#radioFreqBar,#pToggle,#skyHeader,#ismHeader,#cardsFilters,#skyFilters,#tabBar,#tabRow,#mainTabs,#signalHeader,#infoTabs,#ismBottomTabs{background:#e8ecf0!important;border-color:#c0c8d0!important}" +
    ".card-t,.stats-title{color:#0066aa!important}" +
    ".fg{color:#0066aa!important}" +
    "#overlay{background:rgba(240,242,245,.95)!important}" +
    "#overlay .msg{color:#4b5563!important}" +
    ".leaflet-container,.leaflet-tile-pane{background:#e8ecf0!important}" +
    ".sat-label{background:#fff!important;border-color:#c0c8d0!important;color:#111!important}" +
    "#globePane{background:radial-gradient(ellipse at center,#c8d0d8 0%,#e0e4e8 70%)!important}" +
    "#globeInfo,.gl-item{color:#4b5563!important}" +
    ".log-line,.pass-row,.stat-row,.const-row,.info-row,.sig-row,.dop-row,.sat-row{border-color:#e0e4e8!important}" +
    ".pass-row:hover,.ap:hover{background:#f0f4f8!important}" +
    ".pass-row.next{background:#e8f4ff!important;border-left-color:#0066aa!important}" +
    ".countdown{color:#0066aa!important}" +
    ".gallery-item{border-color:#c0c8d0!important;background:#fff!important}" +
    "#ismLog,.dev-details,#ismConsole,#ismExport{background:#f5f6f8!important}" +
    "#toggleBtn,#legend,#statsOverlay,#apDetail{background:#fff!important;border-color:#c0c8d0!important;color:#333!important}" +
    "#searchBox,#filterBar .fb,#filterBar select{background:#fff!important;border-color:#b0b8c4!important;color:#333!important}" +
    ".ap .name{color:#333!important}" +
    "input[type=number],select{background:#fff!important;border-color:#b0b8c4!important;color:#111!important}" +
    "::-webkit-scrollbar-thumb{background:#b0b8c4!important}";
  document.head.appendChild(s);

  // Force light styles on dynamically-classed elements after DOM ready
  function forceLight() {
    document
      .querySelectorAll(
        '[class*="bg-slate-9"],[class*="bg-slate-8"],[class*="bg-slate-950"]',
      )
      .forEach(function (el) {
        if (!el.closest(".screen-frame") && !el.closest(".terminal-wrap"))
          el.style.setProperty("background", "#fff", "important");
      });
    document.querySelectorAll('[class*="border-slate"]').forEach(function (el) {
      el.style.setProperty("border-color", "#c0c8d0", "important");
    });
    document
      .querySelectorAll(
        '[class*="text-slate-1"],[class*="text-slate-2"],[class*="text-slate-3"]',
      )
      .forEach(function (el) {
        el.style.setProperty("color", "#111827", "important");
      });
    document
      .querySelectorAll('[class*="text-slate-4"],[class*="text-slate-5"]')
      .forEach(function (el) {
        el.style.setProperty("color", "#4b5563", "important");
      });
    document
      .querySelectorAll("#settingsTab .rounded-xl,#lootTab .rounded-xl")
      .forEach(function (el) {
        el.style.setProperty("background", "#fff", "important");
        el.style.setProperty("border-color", "#c0c8d0", "important");
      });
    document
      .querySelectorAll(
        "#settingsTab button[data-theme],#settingsTab button[type=button]",
      )
      .forEach(function (el) {
        el.style.setProperty("background", "#f0f2f5", "important");
        el.style.setProperty("border-color", "#b0b8c4", "important");
        el.style.setProperty("color", "#333", "important");
      });
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", forceLight);
  else forceLight();
  // Re-run after app.js renders payloads
  setTimeout(forceLight, 1000);
  setTimeout(forceLight, 3000);
})();
