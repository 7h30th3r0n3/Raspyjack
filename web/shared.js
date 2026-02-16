(function(){
  const RJShared = {
    getApiUrl(path, params = {}, loc){
      const locationRef = loc || window.location;
      const qs = new URLSearchParams(params).toString();
      return `${locationRef.origin}${path}${qs ? `?${qs}` : ''}`;
    },

    getWsUrl(loc){
      const locationRef = loc || window.location;
      if (locationRef.protocol === 'https:'){
        return `${locationRef.origin.replace(/^https:/, 'wss:')}/ws`;
      }
      const p = new URLSearchParams(locationRef.search || '');
      const host = locationRef.hostname || 'raspberrypi.local';
      const port = p.get('port') || '8765';
      return `ws://${host}:${port}/`.replace(/\/\/\//, '//');
    },

    saveToken(storageKey, token){
      const value = String(token || '').trim();
      try{
        if (value){
          sessionStorage.setItem(storageKey, value);
        } else {
          sessionStorage.removeItem(storageKey);
        }
      }catch{}
      return value;
    },

    loadToken(storageKey){
      try{
        return String(sessionStorage.getItem(storageKey) || '').trim();
      }catch{
        return '';
      }
    },

    migrateTokenFromUrl(storageKey, urlParam = 'token'){
      try{
        const u = new URL(window.location.href);
        const token = String(u.searchParams.get(urlParam) || '').trim();
        if (!token) return '';
        const saved = this.saveToken(storageKey, token);
        u.searchParams.delete(urlParam);
        window.history.replaceState({}, '', u.toString());
        return saved;
      }catch{
        return '';
      }
    },

    authHeaders(token, extra){
      const headers = Object.assign({}, extra || {});
      const authToken = String(token || '').trim();
      if (authToken){
        headers.Authorization = `Bearer ${authToken}`;
      }
      return headers;
    },

    async fetchJson(url, options = {}){
      const res = await fetch(url, options);
      let data = null;
      try { data = await res.json(); } catch {}
      return { res, data };
    },

    async fetchBootstrapStatus(getApiUrl){
      try{
        const { res, data } = await this.fetchJson(getApiUrl('/api/auth/bootstrap-status'), { cache: 'no-store' });
        return !!(res.ok && data && data.initialized);
      }catch{
        return true;
      }
    },

    async fetchAuthMe(getApiUrl, token){
      try{
        const { res, data } = await this.fetchJson(getApiUrl('/api/auth/me'), {
          cache: 'no-store',
          credentials: 'include',
          headers: this.authHeaders(token, {}),
        });
        if (!res.ok) return null;
        return data && data.authenticated ? data : null;
      }catch{
        return null;
      }
    },

    async refreshWsTicket(getApiUrl, token){
      if (token) return '';
      try{
        const { res, data } = await this.fetchJson(getApiUrl('/api/auth/ws-ticket'), {
          method: 'POST',
          credentials: 'include',
        });
        if (res.ok && data && data.ticket){
          return String(data.ticket);
        }
      }catch{}
      return '';
    },
  };

  window.RJShared = RJShared;
})();
