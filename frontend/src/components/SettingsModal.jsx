/**
 * Settings: storage and the admin overview.
 *
 * Replaces the first-run StartupModal, the BYODatabaseModal and the Admin tab.
 * The old app greeted a first-time user with a mandatory-looking MongoDB Atlas
 * connection string prompt, and told them Git and CI/CD scanning were "locked"
 * without it. Storage is now what it always should have been: an optional
 * preference, reachable from Settings, that changes where results are written
 * and nothing else.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  Database,
  GitBranch,
  HardDrive,
  KeyRound,
  Loader2,
  LogOut,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Alert, MetricCard, Modal, Segmented } from './ui/Primitives';
import { useAdmin } from '../lib/admin';
import { formatNumber, readinessMeta } from '../lib/risk';

const PANES = [
  { value: 'storage', label: 'Storage', icon: Database },
  { value: 'analysis', label: 'Analysis depth', icon: GitBranch },
  { value: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { value: 'admin', label: 'Fleet overview', icon: ShieldCheck },
];

export default function SettingsModal({ open, onClose, dbStatus, onStatusChange }) {
  const [pane, setPane] = useState('storage');

  return (
    <Modal open={open} onClose={onClose} title="Settings" width="max-w-2xl">
      <div className="space-y-5">
        <Segmented options={PANES} value={pane} onChange={setPane} ariaLabel="Settings section" />
        {pane === 'storage' && <StoragePane dbStatus={dbStatus} onStatusChange={onStatusChange} />}
        {pane === 'analysis' && <DataflowPane />}
        {pane === 'vulnerabilities' && <VulnerabilityPane />}
        {pane === 'admin' && <AdminPane />}
      </div>
    </Modal>
  );
}

/* ----------------------------------------------------------------- Storage */

function StoragePane({ dbStatus, onStatusChange }) {
  const [uri, setUri] = useState('');
  const [dbName, setDbName] = useState('ecdat_enterprise_inventory');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const connected = dbStatus?.is_connected;

  const submit = async (mongoUri) => {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch('/api/config/db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mongo_uri: mongoUri, database_name: dbName }),
      });
      const data = await res.json();
      setMessage({
        tone: data.success ? 'success' : 'error',
        text: data.message || (data.success ? 'Saved.' : 'Could not connect.'),
      });
      const statusRes = await fetch('/api/config/db');
      if (statusRes.ok) onStatusChange(await statusRes.json());
      if (data.success) setUri('');
    } catch (e) {
      setMessage({ tone: 'error', text: e.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Alert tone="info" title="Storage is optional">
        Zypher works fully offline. Every scanner, the Mosca engine, Git and CI/CD scanning and all
        exports behave identically either way — this only decides where results are written.
      </Alert>

      <div className="panel-sunken flex items-center gap-3 p-3.5">
        {connected ? (
          <Database className="h-5 w-5 shrink-0" style={{ color: 'var(--low)' }} aria-hidden="true" />
        ) : (
          <HardDrive className="h-5 w-5 shrink-0 text-muted" aria-hidden="true" />
        )}
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">
            {connected ? 'MongoDB' : 'Local files'}
          </div>
          <div className="truncate text-xs text-muted">
            {connected
              ? `Database: ${dbStatus.database_name}`
              : 'Results are written to data_store/ next to the application'}
          </div>
        </div>
        {connected && (
          <button className="btn btn-secondary" onClick={() => submit('')} disabled={busy}>
            Switch to local
          </button>
        )}
      </div>

      {message && (
        <Alert tone={message.tone} onDismiss={() => setMessage(null)}>
          {message.text}
        </Alert>
      )}

      {!connected && (
        <div className="space-y-3">
          <div>
            <label className="label" htmlFor="mongo-uri">
              MongoDB connection string
            </label>
            <input
              id="mongo-uri"
              type="password"
              className="field field-mono"
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              placeholder="mongodb+srv://user:password@cluster.mongodb.net"
              autoComplete="off"
            />
            <p className="hint">
              Share an inventory across machines.
            </p>
          </div>
          <div>
            <label className="label" htmlFor="mongo-db">
              Database name
            </label>
            <input
              id="mongo-db"
              className="field"
              value={dbName}
              onChange={(e) => setDbName(e.target.value)}
            />
          </div>
          <button
            className="btn btn-primary"
            onClick={() => submit(uri)}
            disabled={busy || !uri.trim()}
          >
            {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {busy ? 'Validating…' : 'Connect'}
          </button>
        </div>
      )}
    </div>
  );
}

/* --------------------------------------------------------- Vulnerabilities */

/**
 * The one setting that changes whether a scan reaches the network.
 *
 * Off by default, because Zypher's premise is that it works fully offline. It is
 * presented as an explicit choice rather than buried, and the cache count makes
 * clear that a previously-checked package still resolves without connectivity.
 */
/* ------------------------------------------------------- Analysis depth */

/**
 * State of the Tier 4 dataflow pass.
 *
 * Shown rather than hidden because it decides whether a key size in the
 * inventory was measured or assumed, and that is the difference between
 * RSA-1024 — broken today — and an assumed RSA-2048, which is not.
 */
function DataflowPane() {
  const [state, setState] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/config/dataflow')
      .then((r) => (r.ok ? r.json() : null))
      .then(setState)
      .catch(() => setError('Could not read the current setting.'));
  }, []);

  const toggle = async (enabled) => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/config/dataflow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) throw new Error('Could not change the setting.');
      setState(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (!state) {
    return <p className="py-6 text-center text-[13px] text-faint">Loading…</p>;
  }

  const on = state.enabled && state.available;

  return (
    <div className="space-y-4">
      <Alert tone="info" title="Four tiers of detection, all offline">
        Text patterns, then syntax-aware parsing, then standard binary signatures,
        and finally dataflow analysis — which follows a value across function
        boundaries so a key size written in one place is attributed to the call
        that uses it. Nothing here touches the network.
      </Alert>

      <div className="panel-sunken flex items-center gap-3 p-3.5">
        <GitBranch
          className="h-5 w-5 shrink-0"
          style={{ color: on ? 'var(--low)' : 'var(--ink-muted)' }}
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">
            {on
              ? 'Resolving parameters across function boundaries'
              : state.enabled
                ? 'Unavailable'
                : 'Turned off'}
          </div>
          <div className="text-xs text-muted">
            {on
              ? 'Key sizes, curves and algorithm names are read from the value that actually reaches the call.'
              : state.enabled
                ? state.reason || 'The analysis engine could not be started.'
                : 'Parameters passed through helpers will be reported as assumed defaults.'}
          </div>
        </div>
        <button
          className={state.enabled ? 'btn btn-secondary' : 'btn btn-primary'}
          onClick={() => toggle(!state.enabled)}
          disabled={busy || (!state.enabled && !state.binary_present)}
        >
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          {state.enabled ? 'Turn off' : 'Turn on'}
        </button>
      </div>

      {state.available && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[13px]">
          <dt className="text-muted">Engine</dt>
          <dd className="mono">
            {state.engine} {state.version}
          </dd>
          <dt className="text-muted">Rules loaded</dt>
          <dd className="mono tabular">{state.rules}</dd>
          <dt className="text-muted">Network access</dt>
          <dd>None</dd>
        </dl>
      )}

      {error && <Alert tone="error">{error}</Alert>}
    </div>
  );
}

/* -------------------------------------------------------- Vulnerabilities */

function VulnerabilityPane() {
  const [state, setState] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/config/vulnerability-lookup')
      .then((r) => (r.ok ? r.json() : null))
      .then(setState)
      .catch(() => setError('Could not read the current setting.'));
  }, []);

  const toggle = async (enabled) => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/config/vulnerability-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) throw new Error('Could not change the setting.');
      const body = await res.json();
      setState((prev) => ({ ...prev, ...body }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (!state) {
    return <p className="py-6 text-center text-[13px] text-faint">Loading…</p>;
  }

  return (
    <div className="space-y-4">
      <Alert tone="info" title="This is the only feature that uses the network">
        Every scanner, the Mosca engine and all exports work fully offline. Turning
        this on additionally queries {state.source} for published advisories
        affecting the dependency versions found in a scan.
      </Alert>

      <div className="panel-sunken flex items-center gap-3 p-3.5">
        <ShieldAlert
          className="h-5 w-5 shrink-0"
          style={{ color: state.enabled ? 'var(--low)' : 'var(--ink-muted)' }}
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">
            {state.enabled ? 'Checking known vulnerabilities' : 'Not checking'}
          </div>
          <div className="text-xs text-muted">
            {state.enabled
              ? 'Scans query OSV for each dependency found.'
              : 'Scans stay entirely offline. Package identifiers are still recorded.'}
          </div>
        </div>
        <button
          className={state.enabled ? 'btn btn-secondary' : 'btn btn-primary'}
          onClick={() => toggle(!state.enabled)}
          disabled={busy}
        >
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {state.enabled ? 'Turn off' : 'Turn on'}
        </button>
      </div>

      {error && <Alert tone="error">{error}</Alert>}

      <div className="space-y-2 text-[12.5px] leading-relaxed text-muted">
        <p>
          Results are cached on disk, so a package checked once resolves again
          without connectivity —{' '}
          <strong style={{ color: 'var(--ink)' }}>
            {state.cached_packages} package
            {state.cached_packages === 1 ? '' : 's'}
          </strong>{' '}
          cached.
        </p>
        <p>
          Advisories are reported separately from the quantum assessment. A CVE
          is a defect in a released version; Mosca risk describes exposure to a
          future quantum adversary. A library can carry one without the other.
        </p>
        <p>
          Package identifiers are recorded either way.
        </p>
      </div>
    </div>
  );
}


/* ------------------------------------------------------------------- Admin */

function AdminPane() {
  // Session state is shared with the rest of the application rather than owned
  // here. It used to live in this component alone, so nothing outside this one
  // panel could tell whether an admin was signed in — which is why signing in
  // could not unlock anything.
  const { isAdmin, isSetup, checking, status, signIn, signOut, adminFetch } = useAdmin();

  const [data, setData] = useState(null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  // Leaving admin mode needs the password too, so it is a small confirm step
  // rather than a single click.
  const [exiting, setExiting] = useState(false);
  const [exitPassword, setExitPassword] = useState('');
  const [exitError, setExitError] = useState(null);

  const leaveAdminMode = async (e) => {
    e.preventDefault();
    setExitError(null);
    setBusy(true);
    try {
      await signOut(exitPassword);
      setExitPassword('');
      setExiting(false);
    } catch (err) {
      setExitError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const load = useCallback(async () => {
    setBusy(true);
    try {
      const res = await adminFetch('/api/admin/overview');
      if (res.ok) setData(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }, [adminFetch]);

  useEffect(() => {
    if (isAdmin) load();
    else setData(null);
  }, [isAdmin, load]);

  const authenticate = async (e) => {
    e.preventDefault();
    setError(null);

    if (!isSetup) {
      if (password.length < 8) return setError('Use at least 8 characters.');
      if (password !== confirm) return setError('The two passwords do not match.');
    }

    setBusy(true);
    try {
      await signIn(password, isSetup);
      setPassword('');
      setConfirm('');
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (checking && !status) {
    return <p className="py-6 text-center text-sm text-faint">Loading…</p>;
  }

  if (!isAdmin) {
    return (
      <form onSubmit={authenticate} className="space-y-4">
        <div className="panel-sunken flex items-start gap-3 p-3.5">
          <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden="true" />
          <p className="text-[13px] text-muted">
            Protected by a PBKDF2-HMAC-SHA256 password.
          </p>
        </div>

        <div>
          <label className="label" htmlFor="admin-pw">
            {isSetup ? 'Password' : 'Create a password'}
          </label>
          <input
            id="admin-pw"
            type="password"
            className="field"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isSetup ? 'current-password' : 'new-password'}
          />
          {!isSetup && <p className="hint">At least 8 characters.</p>}
        </div>

        {!isSetup && (
          <div>
            <label className="label" htmlFor="admin-pw2">
              Confirm password
            </label>
            <input
              id="admin-pw2"
              type="password"
              className="field"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </div>
        )}

        {error && <Alert tone="error">{error}</Alert>}

        <button className="btn btn-primary w-full" disabled={busy || !password}>
          {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {isSetup ? 'Unlock' : 'Create and unlock'}
        </button>
      </form>
    );
  }

  if (busy && !data) {
    return <p className="py-6 text-center text-sm text-faint">Aggregating scans…</p>;
  }

  if (!data) return <Alert tone="error">{error || 'No aggregate data available.'}</Alert>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px] text-muted">
          Across {formatNumber(data.total_systems_scanned)} stored{' '}
          {data.total_systems_scanned === 1 ? 'scan' : 'scans'} · {data.database_name}
        </p>
        <button className="btn btn-ghost" onClick={() => setExiting((v) => !v)}>
          <LogOut className="h-3.5 w-3.5" />
          Exit admin mode
        </button>
      </div>

      {exiting && (
        <form onSubmit={leaveAdminMode} className="panel-sunken space-y-2.5 p-3.5">
          <label className="label mb-0" htmlFor="exit-admin-pw">
            Confirm your password to exit
          </label>
          <p className="text-xs text-faint">
            Closing the application also ends the session.
          </p>
          <input
            id="exit-admin-pw"
            className="field"
            type="password"
            autoComplete="current-password"
            value={exitPassword}
            onChange={(e) => setExitPassword(e.target.value)}
          />
          {exitError && <Alert tone="error">{exitError}</Alert>}
          <div className="flex gap-2">
            <button className="btn btn-primary" disabled={busy || !exitPassword}>
              {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Exit admin mode
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                setExiting(false);
                setExitPassword('');
                setExitError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <MetricCard label="Systems" value={data.total_systems_scanned} />
        <MetricCard label="Assets" value={data.total_enterprise_assets} />
        <MetricCard
          label="Critical"
          value={data.total_critical_risks}
          accent={data.total_critical_risks > 0 ? 'var(--critical)' : undefined}
        />
        <MetricCard
          label="Avg readiness"
          value={data.average_quantum_readiness}
          accent={readinessMeta(data.average_quantum_readiness).color}
        />
      </div>

      {data.systems_summary?.length > 0 && (
        <div className="panel-sunken max-h-64 overflow-y-auto">
          <ul className="divide-rows">
            {data.systems_summary.map((s) => (
              <li key={s.scan_id} className="flex items-center gap-3 px-3 py-2">
                <span className="min-w-0 flex-1 truncate text-[13px]">{s.system_name}</span>
                <span className="shrink-0 text-[11px] text-faint tabular">
                  {formatNumber(s.total_assets)} assets
                </span>
                <span
                  className="w-8 shrink-0 text-right text-[12px] font-semibold tabular"
                  style={{ color: readinessMeta(s.readiness_score).color }}
                >
                  {s.readiness_score}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
