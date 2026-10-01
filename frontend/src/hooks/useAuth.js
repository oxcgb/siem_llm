import { useState, useEffect } from 'react';
import api, {
  getToken, setToken
} from '../api';

export function useAuth() {
  const [authMode, setAuthMode] =
    useState('local');
  const [authUser, setAuthUser] =
    useState(null);
  const [ldapReady, setLdapReady] =
    useState(false);

  useEffect(() => {
    api('/api/auth/mode', {
      auth: false
    }).then(d => {
      setAuthMode(
        d.mode || 'local');
      setLdapReady(!!(
        d.ldap_enabled &&
        d.ldap_configured &&
        d.ldap_lib_ok
      ));
      if (d.mode === 'ad' &&
          getToken()) {
        api('/api/auth/me')
          .then(r => {
            if (r.user)
              setAuthUser(
                r.user);
          })
          .catch(() => {});
      }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    const h = () =>
      setAuthUser(null);
    window.addEventListener(
      'soc:unauthorized', h);
    return () =>
      window.removeEventListener(
        'soc:unauthorized', h);
  }, []);

  const login = (res) => {
    setAuthUser({
      username: res.username,
      display_name:
        res.display_name,
      is_admin: res.is_admin
    });
  };

  const logout = async () => {
    try {
      await api(
        '/api/auth/logout', {
        method: 'POST'
      });
    } catch {}
    setToken(null);
    setAuthUser(null);
  };

  return {
    authMode, authUser,
    ldapReady, login, logout
  };
}
