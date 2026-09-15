import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Shell from './components/Shell';
import Dashboard from './components/Dashboard';
import ScanView from './components/ScanView';
import InventoryView from './components/InventoryView';
import ReportsView from './components/ReportsView';
import EstateView from './components/EstateView';
import SettingsModal from './components/SettingsModal';
import { Alert } from './components/ui/Primitives';
import { MERGED_SCAN_ID } from './lib/constants';
import { useAdmin } from './lib/admin';

export const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'scan', label: 'Scan' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'reports', label: 'Reports' },
];

// Only reachable with an admin session. Signing in does not change how the tool
// works — it adds this one view, where every asset in every stored scan is
// queryable as a single estate.
const ADMIN_TAB = { id: 'estate', label: 'Estate', adminOnly: true };

const VALID_TABS = new Set([...TABS, ADMIN_TAB].map((t) => t.id));

function tabFromHash() {
  const id = window.location.hash.replace(/^#\/?/, '');
  return VALID_TABS.has(id) ? id : 'dashboard';
}

export default function App() {
  const { isAdmin } = useAdmin();

  // Tab state lives in the URL hash so the view is linkable and the browser's
  // (and the desktop window's) back button behaves predictably.
  const [activeTab, setActiveTabState] = useState(tabFromHash);
  const [scanResult, setScanResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [dbStatus, setDbStatus] = useState(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  // Errors used to go only to console.error, so a failure looked like nothing
  // happening. They are surfaced here instead.
  const [error, setError] = useState(null);

  const tabs = useMemo(() => (isAdmin ? [...TABS, ADMIN_TAB] : TABS), [isAdmin]);

  // Signing out while standing on the estate tab must not leave a blank screen
  // behind; fall back to the dashboard.
  useEffect(() => {
    if (!isAdmin && activeTab === ADMIN_TAB.id) setActiveTabState('dashboard');
  }, [isAdmin, activeTab]);

  const setActiveTab = useCallback((id) => {
    setActiveTabState(id);
    if (tabFromHash() !== id) window.location.hash = `#/${id}`;
  }, []);

  useEffect(() => {
    const onHashChange = () => setActiveTabState(tabFromHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/scans');
      if (res.ok) setScanHistory(await res.json());
    } catch {
      /* history is non-essential; the active scan still works */
    }
  }, []);

  /** Load a stored scan, or the merged view for the merged id. */
  const loadScan = useCallback(async (scanId) => {
    const url =
      scanId === MERGED_SCAN_ID ? '/api/scans/merged' : `/api/scans/${scanId}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('That scan could not be loaded.');
    return res.json();
  }, []);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const dbRes = await fetch('/api/config/db');
        if (dbRes.ok && !cancelled) setDbStatus(await dbRes.json());

        const scansRes = await fetch('/api/scans');
        if (!scansRes.ok) throw new Error('Could not reach the Zypher engine.');
        const scans = await scansRes.json();
        if (cancelled) return;
        setScanHistory(scans);

        // Open the combined view by default, so the estate is the starting
        // point rather than whichever scan happened to run last. It does NOT
        // run a scan on startup the way it used to.
        if (scans.length > 0) {
          const merged = await fetch('/api/scans/merged');
          if (merged.ok && !cancelled) setScanResult(await merged.json());
        }
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to start.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const handleScanComplete = useCallback(
    (result) => {
      setScanResult(result);
      setActiveTab('dashboard');
      refreshHistory();
    },
    [refreshHistory]
  );

  const handleSelectScan = useCallback(
    async (scanId) => {
      try {
        setScanResult(await loadScan(scanId));
        setActiveTab('dashboard');
      } catch (e) {
        setError(e.message);
      }
    },
    [loadScan, setActiveTab]
  );

  const handleDeleteScan = useCallback(
    async (scanId) => {
      try {
        await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
        await refreshHistory();
        // The combined view is derived, so it has to be rebuilt after a
        // deletion — and a deleted active scan falls back to it.
        const active = scanResult?.summary.scan_id;
        if (active === scanId || active === MERGED_SCAN_ID) {
          try {
            setScanResult(await loadScan(MERGED_SCAN_ID));
          } catch {
            setScanResult(null);
          }
        }
      } catch (e) {
        setError(e.message);
      }
    },
    [scanResult, refreshHistory, loadScan]
  );

  return (
    <Shell
      tabs={tabs}
      isAdmin={isAdmin}
      activeTab={activeTab}
      onTabChange={setActiveTab}
      scanResult={scanResult}
      scanHistory={scanHistory}
      dbStatus={dbStatus}
      onOpenSettings={() => setSettingsOpen(true)}
      onSelectScan={handleSelectScan}
    >
      {error && (
        <div className="mb-5">
          <Alert tone="error" title="Something went wrong" onDismiss={() => setError(null)}>
            {error}
          </Alert>
        </div>
      )}

      {loading ? (
        <LoadingState />
      ) : (
        <>
          {activeTab === 'dashboard' && (
            <Dashboard
              scanResult={scanResult}
              onNavigate={setActiveTab}
              onUpdateScanResult={setScanResult}
            />
          )}
          {activeTab === 'scan' && (
            <ScanView onScanComplete={handleScanComplete} onError={setError} />
          )}
          {activeTab === 'inventory' && <InventoryView scanResult={scanResult} onNavigate={setActiveTab} />}
          {activeTab === 'estate' && <EstateView />}
          {activeTab === 'reports' && (
            <ReportsView
              scanResult={scanResult}
              scanHistory={scanHistory}
              onNavigate={setActiveTab}
              onSelectScan={handleSelectScan}
              onDeleteScan={handleDeleteScan}
            />
          )}
        </>
      )}

      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        dbStatus={dbStatus}
        onStatusChange={setDbStatus}
      />
    </Shell>
  );
}

function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center py-28">
      <div
        className="h-8 w-8 animate-spin rounded-full border-2 border-line-strong"
        style={{ borderTopColor: 'var(--accent)' }}
      />
      <p className="mt-4 text-sm text-muted">Starting the analysis engine…</p>
    </div>
  );
}
