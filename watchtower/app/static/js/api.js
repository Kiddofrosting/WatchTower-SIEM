// FIX: Use sessionStorage (same-origin, not subject to Tracking Prevention).
// Falls back to an in-memory map if storage is blocked (e.g. private browsing).
const wtStorage = (() => {
  const mem = {};
  const ok = (() => { try { sessionStorage.setItem('_t','1'); sessionStorage.removeItem('_t'); return true; } catch(e){ return false; } })();
  return {
    getItem: k => ok ? sessionStorage.getItem(k) : (mem[k] ?? null),
    setItem: (k, v) => ok ? sessionStorage.setItem(k, v) : (mem[k] = v),
    removeItem: k => ok ? sessionStorage.removeItem(k) : delete mem[k],
  };
})();

/* WatchTower SIEM — API Helper */
'use strict';
const API = (() => {
  let _accessToken = wtStorage.getItem('wt_access_token');
  let _refreshToken = wtStorage.getItem('wt_refresh_token');
  let _refreshing = false;
  let _refreshQueue = [];

  function setTokens(access, refresh) {
    _accessToken = access;
    if (refresh) _refreshToken = refresh;
    wtStorage.setItem('wt_access_token', access);
    if (refresh) wtStorage.setItem('wt_refresh_token', refresh);
  }
  function clearTokens() {
    _accessToken = null; _refreshToken = null;
    wtStorage.removeItem('wt_access_token');
    wtStorage.removeItem('wt_refresh_token');
    wtStorage.removeItem('wt_user');
  }
  async function _doRefresh() {
    if (_refreshing) return new Promise((res, rej) => _refreshQueue.push({res, rej}));
    _refreshing = true;
    try {
      const r = await fetch('/api/v1/auth/refresh', {
        method: 'POST', headers: {'Authorization': `Bearer ${_refreshToken}`}
      });
      if (!r.ok) throw new Error('refresh_failed');
      const d = await r.json();
      setTokens(d.access_token, null);
      _refreshQueue.forEach(q => q.res(d.access_token));
      _refreshQueue = [];
      return d.access_token;
    } catch(e) {
      _refreshQueue.forEach(q => q.rej(e));
      _refreshQueue = [];
      clearTokens();
      window.location.href = '/login';
      throw e;
    } finally { _refreshing = false; }
  }

  async function request(method, path, body = null, opts = {}) {
    const headers = {'Content-Type': 'application/json'};
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;
    const fOpts = {method, headers};
    if (body && method !== 'GET') fOpts.body = JSON.stringify(body);

    let resp = await fetch('/api/v1' + path, fOpts);

    if (resp.status === 401 && !opts._retried && _refreshToken) {
      try {
        const tok = await _doRefresh();
        headers['Authorization'] = `Bearer ${tok}`;
        resp = await fetch('/api/v1' + path, {...fOpts, headers});
        opts._retried = true;
      } catch { return null; }
    }
    if (resp.status === 401) { clearTokens(); window.location.href = '/login'; return null; }
    if (resp.status === 204) return null;
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return resp.ok ? await resp.blob() : null;
    const data = await resp.json();
    if (!resp.ok) {
      const err = new Error(data.message || data.error || `HTTP ${resp.status}`);
      err.status = resp.status; err.data = data; throw err;
    }
    return data;
  }

  function qs(params) {
    if (!params) return '';
    const p = Object.fromEntries(Object.entries(params).filter(([,v]) => v != null && v !== ''));
    return Object.keys(p).length ? '?' + new URLSearchParams(p).toString() : '';
  }

  return {
    get:    (path, params) => request('GET', path + qs(params)),
    post:   (path, body)   => request('POST',   path, body),
    put:    (path, body)   => request('PUT',    path, body),
    patch:  (path, body)   => request('PATCH',  path, body),
    delete: (path)         => request('DELETE', path),
    setTokens, clearTokens,
    getUser: () => { try { return JSON.parse(wtStorage.getItem('wt_user') || 'null'); } catch { return null; } },
  };
})();
