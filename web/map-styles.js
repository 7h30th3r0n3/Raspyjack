(function(){
  var THEMES = {
    dark: {
      url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
      opts: {maxZoom:19},
      bg: '#0d1117'
    },
    satellite: {
      url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
      opts: {maxZoom:18},
      bg: '#0a0a0a'
    },
    topo: {
      url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
      opts: {maxZoom:17},
      bg: '#1a1a2e'
    },
    osm: {
      url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
      opts: {maxZoom:19},
      bg: '#e8e8e8'
    }
  };

  var _prevLayer = null;
  var _prevMap = null;

  window._rjSetTheme = function(map, name) {
    if (!map) return;
    var theme = THEMES[name];
    if (!theme) { name = 'dark'; theme = THEMES[name]; }
    try {
      if (_prevLayer && _prevMap) _prevMap.removeLayer(_prevLayer);
    } catch(e) {}
    _prevLayer = L.tileLayer(theme.url, theme.opts);
    _prevLayer.addTo(map);
    _prevMap = map;
    try { map.getContainer().style.background = theme.bg; } catch(e) {}
    try { localStorage.setItem('rj-map-style', name); } catch(e) {}
    var sel = document.getElementById('themeSel');
    if (sel) sel.value = name;
  };

  window._rjInitMap = function(map) {
    var saved = 'dark';
    try { saved = localStorage.getItem('rj-map-style') || 'dark'; } catch(e) {}
    window._rjSetTheme(map, saved);
  };

  window._rjAddMapStyleControl = window._rjInitMap;
})();
