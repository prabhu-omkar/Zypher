/**
 * Admin session state.
 *
 * This used to live inside SettingsModal, so nothing outside that one panel
 * could know whether an admin was signed in. Signing in now puts the whole
 * application into admin mode: the tool behaves exactly as before, but the
 * estate — every asset in every stored scan — becomes reachable.
 *
 * The token is held in sessionStorage rather than localStorage so it dies with
 * the tab, and it is re-validated against the server on mount: a session the
 * server has expired must not leave a badge showing.
 */
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

const TOKEN_KEY = 'ecdat_admin_token';

const AdminContext = createContext(null);

function readToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function writeToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* a browser with storage disabled still works, just without persistence */
  }
}

export function AdminProvider({ children }) {
  const [token, setToken] = useState(readToken);
  const [status, setStatus] = useState(null);
  const [checking, setChecking] = useState(true);

  const refreshStatus = useCallback(async (candidate) => {
    const headers = candidate ? { Authorization: `Bearer ${candidate}` } : {};
    try {
      const res = await fetch('/api/admin/status', { headers });
      if (!res.ok) throw new Error('unreachable');
      const body = await res.json();
      setStatus(body);
      // The server is the authority on whether the session is still alive.
      if (candidate && !body.is_authenticated) {
        writeToken(null);
        setToken(null);
      }
      return body;
    } catch {
      setStatus(null);
      return null;
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    refreshStatus(readToken());
  }, [refreshStatus]);

  const signIn = useCallback(
    async (password, isSetup) => {
      const res = await fetch(isSetup ? '/api/admin/login' : '/api/admin/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || 'Could not sign in.');
      writeToken(body.token);
      setToken(body.token);
      await refreshStatus(body.token);
      return body;
    },
    [refreshStatus]
  );

  /**
   * Leave admin mode.
   *
   * The password is required to leave as well as to enter: dropping the estate
   * out of view is a change of state, and it should not be available to
   * somebody who walked up to an unlocked machine. The local token is only
   * cleared once the server confirms the session was revoked, so a wrong
   * password leaves the session exactly as it was rather than half-torn-down.
   */
  const signOut = useCallback(
    async (password) => {
      const current = readToken();
      if (!current) {
        await refreshStatus(null);
        return;
      }
      const res = await fetch('/api/admin/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${current}`,
        },
        body: JSON.stringify({ password: password || '' }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || 'Could not exit admin mode.');

      writeToken(null);
      setToken(null);
      await refreshStatus(null);
    },
    [refreshStatus]
  );

  /** fetch() with the admin token attached, that signs out on a 401. */
  const adminFetch = useCallback(
    async (url, options = {}) => {
      const current = readToken();
      const res = await fetch(url, {
        ...options,
        headers: {
          ...(options.headers || {}),
          ...(current ? { Authorization: `Bearer ${current}` } : {}),
        },
      });
      if (res.status === 401) {
        writeToken(null);
        setToken(null);
        setStatus((s) => (s ? { ...s, is_authenticated: false } : s));
        throw new Error('The admin session has expired. Sign in again.');
      }
      return res;
    },
    []
  );

  const value = useMemo(
    () => ({
      isAdmin: Boolean(token && status?.is_authenticated),
      isSetup: Boolean(status?.is_setup),
      checking,
      status,
      signIn,
      signOut,
      adminFetch,
      refreshStatus,
    }),
    [token, status, checking, signIn, signOut, adminFetch, refreshStatus]
  );

  return <AdminContext.Provider value={value}>{children}</AdminContext.Provider>;
}

export function useAdmin() {
  const ctx = useContext(AdminContext);
  if (!ctx) throw new Error('useAdmin must be used inside an AdminProvider');
  return ctx;
}
