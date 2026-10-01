const TOKEN_KEY = 'soc_token';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t) => {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
};

async function api(url, { method = 'GET', body, timeout = 30000, auth = true } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const headers = body !== undefined ? { 'Content-Type': 'application/json' } : {};
    if (auth && getToken()) headers.Authorization = 'Bearer ' + getToken();
    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    if (!res.ok) {
      if (res.status === 401 && auth) {
        setToken(null);
        window.dispatchEvent(new Event('soc:unauthorized'));
      }
      let detail = '';
      try {
        const j = await res.json();
        detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j);
      } catch { /* not json */ }
      throw new Error(`HTTP ${res.status}${detail ? ': ' + detail : ''}`);
    }
    return res.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`Timeout (${timeout}ms): ${url}`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

export default api;