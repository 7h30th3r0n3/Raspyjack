(function(){
  var STYLES={
    'Dark':'/tiles/{z}/{x}/{y}.png',
    'Dark (online)':'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    'Light':'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
    'Satellite':'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    'Topo':'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    'OSM':'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png'
  };

  window._rjMapStyles=STYLES;

  window._rjAddMapStyleControl=function(map,position){
    var saved=localStorage.getItem('rj-map-style')||'Dark';
    var currentLayer=null;

    function setStyle(name){
      var url=STYLES[name]||STYLES['Dark'];
      if(currentLayer)map.removeLayer(currentLayer);
      currentLayer=L.tileLayer(url,{maxZoom:19,subdomains:'abcd'}).addTo(map);
      localStorage.setItem('rj-map-style',name);
      if(sel)sel.value=name;
    }

    var ctrl=L.control({position:position||'topright'});
    var sel;
    ctrl.onAdd=function(){
      var div=L.DomUtil.create('div','');
      div.style.cssText='background:rgba(8,12,20,.85);border:1px solid rgba(100,100,100,.3);border-radius:6px;padding:4px;backdrop-filter:blur(6px)';
      sel=L.DomUtil.create('select','',div);
      sel.style.cssText='background:transparent;color:#ccc;border:none;font-size:9px;font-family:Courier New,monospace;cursor:pointer;outline:none';
      for(var name in STYLES){
        var opt=L.DomUtil.create('option','',sel);
        opt.value=name;opt.textContent=name;
        opt.style.background='#0a0e1a';
        if(name===saved)opt.selected=true;
      }
      L.DomEvent.disableClickPropagation(div);
      sel.onchange=function(){setStyle(sel.value)};
      return div;
    };
    ctrl.addTo(map);
    setStyle(saved);
  };
})();
