/**
 * Application shell.
 *
 * A fixed sidebar rather than a row of top tabs: this is a tool you sit inside
 * for a while, and a persistent rail gives the content area the full width for
 * data while keeping every destination and the active scan in view.
 */
import React, { useEffect, useRef, useState } from 'react';
import {
  ChevronsUpDown,
  Database,
  FileText,
  HardDrive,
  Building2,
  LayoutDashboard,
  Layers,
  Radar,
  Settings,
} from 'lucide-react';
import { ZypherWordmark } from './ui/Brand';
import { formatNumber, readinessMeta } from '../lib/risk';
import { MERGED_SCAN_ID } from '../lib/constants';

const ICONS = {
  dashboard: LayoutDashboard,
  scan: Radar,
  inventory: Layers,
  reports: FileText,
  // Added when the estate tab was introduced; without an entry here the nav
  // rendered it as a label with a hole where every other item has a mark.
  estate: Building2,
};

export default function Shell({
  tabs,
  isAdmin,
  activeTab,
  onTabChange,
  scanResult,
  scanHistory,
  dbStatus,
  onOpenSettings,
  onSelectScan,
  children,
}) {
  return (
    <div className="flex min-h-screen">
      {/* ------------------------------------------------------------ Sidebar */}
      <aside
        className="fixed inset-y-0 left-0 z-30 hidden flex-col border-r border-line bg-surface lg:flex"
        style={{ width: 'var(--sidebar-w)' }}
      >
        <div className="px-4 py-4">
          <ZypherWordmark
            badge={
              /* The badge is the only visible difference admin mode makes to
                 the chrome. Everything else behaves identically signed in. */
              isAdmin ? (
                <span
                  className="rounded-[4px] px-1.5 py-[1px] text-[9px] font-bold uppercase"
                  style={{
                    background: 'var(--accent)',
                    color: '#fff',
                    letterSpacing: '0.07em',
                  }}
                  title="Signed in as admin — the estate view is available"
                >
                  Admin
                </span>
              ) : null
            }
          />
        </div>

        <nav className="flex flex-col gap-0.5 px-2.5 pt-2" aria-label="Primary">
          {tabs.map((tab) => {
            const Icon = ICONS[tab.id];
            const active = tab.id === activeTab;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                aria-current={active ? 'page' : undefined}
                className="group flex items-center gap-2.5 rounded-[7px] px-2.5 text-[13px] transition-colors"
                style={{
                  minHeight: 34,
                  fontWeight: active ? 550 : 450,
                  color: active ? 'var(--accent)' : 'var(--ink-soft)',
                  background: active ? 'var(--accent-soft)' : 'transparent',
                }}
                onMouseEnter={(e) => {
                  if (!active) e.currentTarget.style.background = 'var(--surface-sunken)';
                }}
                onMouseLeave={(e) => {
                  if (!active) e.currentTarget.style.background = 'transparent';
                }}
              >
                {Icon && <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />}
                {tab.label}
              </button>
            );
          })}
        </nav>

        <div className="mt-auto space-y-1 p-2.5">
          <StorageRow dbStatus={dbStatus} />
          <button
            onClick={onOpenSettings}
            className="flex w-full items-center gap-2.5 rounded-[7px] px-2.5 text-[13px] text-soft transition-colors hover:bg-surface-sunken"
            style={{ minHeight: 34 }}
          >
            <Settings className="h-4 w-4 shrink-0" aria-hidden="true" />
            Settings
          </button>
        </div>
      </aside>

      {/* ------------------------------------------------------------ Content */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-[var(--sidebar-w)]">
        <header className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur-md">
          <div className="mx-auto flex h-[52px] max-w-[1360px] items-center gap-3 px-5 sm:px-7">
            {/* Compact nav for narrow windows, where the rail is hidden. */}
            <nav className="flex items-center gap-0.5 lg:hidden" aria-label="Primary">
              {tabs.map((tab) => {
                const active = tab.id === activeTab;
                return (
                  <button
                    key={tab.id}
                    onClick={() => onTabChange(tab.id)}
                    aria-current={active ? 'page' : undefined}
                    className="rounded-[6px] px-2.5 text-[13px] transition-colors"
                    style={{
                      minHeight: 32,
                      fontWeight: active ? 550 : 450,
                      color: active ? 'var(--accent)' : 'var(--ink-muted)',
                      background: active ? 'var(--accent-soft)' : 'transparent',
                    }}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </nav>

            <div className="ml-auto flex items-center gap-2">
              <ScanPicker
                scanResult={scanResult}
                scanHistory={scanHistory}
                onSelectScan={onSelectScan}
              />
              <button
                onClick={onOpenSettings}
                className="btn btn-ghost px-2 lg:hidden"
                aria-label="Settings"
              >
                <Settings className="h-4 w-4" />
              </button>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1360px] flex-1 px-5 py-7 sm:px-7">{children}</main>

        <footer className="mx-auto w-full max-w-[1360px] px-5 pb-6 sm:px-7">
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4 text-[11px] text-faint">
            <span>CycloneDX 1.6 · FIPS 203/204/205</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

/** Where results are written. Informational — no feature depends on it. */
function StorageRow({ dbStatus }) {
  const cloud = dbStatus?.is_connected;
  const Icon = cloud ? Database : HardDrive;
  return (
    <div
      className="flex items-center gap-2.5 rounded-[7px] px-2.5 py-1.5 text-[12px] text-muted"
      title={
        cloud
          ? `Results stored in MongoDB (${dbStatus.database_name})`
          : 'Results stored in local files'
      }
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate">{cloud ? 'MongoDB' : 'Local storage'}</span>
      <span
        className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full"
        style={{ background: cloud ? 'var(--low)' : 'var(--ink-faint)' }}
        aria-hidden="true"
      />
    </div>
  );
}

/** Switch between stored scans without leaving the current view. */
function ScanPicker({ scanResult, scanHistory, onSelectScan }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (!scanResult && (!scanHistory || scanHistory.length === 0)) return null;

  const current = scanResult?.summary;
  const isMerged = current?.scan_id === MERGED_SCAN_ID;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="btn btn-secondary max-w-[300px]"
        aria-expanded={open}
        aria-haspopup="listbox"
      >
        <span className="truncate">{current ? current.target_name : 'Select a scan'}</span>
        {current && (
          <span className="shrink-0 tabular text-faint">
            {formatNumber(current.total_artefacts)}
          </span>
        )}
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-faint" aria-hidden="true" />
      </button>

      {open && (
        <div
          role="listbox"
          className="animate-slide-up absolute right-0 z-50 mt-1.5 w-[360px] overflow-hidden rounded-lg bg-surface p-1"
          style={{ boxShadow: 'var(--shadow-pop)' }}
        >
          {/* The combined estate first: it is the default view, and the
              individual scans below are a way to narrow to one target. */}
          <button
            role="option"
            aria-selected={isMerged}
            onClick={() => {
              onSelectScan(MERGED_SCAN_ID);
              setOpen(false);
            }}
            className="flex w-full items-center gap-3 rounded-[7px] px-2.5 py-2 text-left transition-colors hover:bg-surface-sunken"
            style={{ background: isMerged ? 'var(--accent-soft)' : 'transparent' }}
          >
            <Layers className="h-4 w-4 shrink-0 text-muted" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-medium">All scans</div>
              <div className="mt-0.5 text-[11px] text-faint">
                Every stored scan, deduplicated
              </div>
            </div>
            {isMerged && current && (
              <span className="shrink-0 text-[13px] font-semibold tabular text-muted">
                {formatNumber(current.total_artefacts)}
              </span>
            )}
          </button>

          <div className="my-1 border-t border-line" />

          <div className="eyebrow px-2.5 py-1.5">Individual scans ({scanHistory.length})</div>
          <div className="max-h-[min(50vh,420px)] overflow-y-auto">
            {scanHistory.map((s) => {
              const active = s.scan_id === current?.scan_id;
              const meta = readinessMeta(s.quantum_readiness_score);
              return (
                <button
                  key={s.scan_id}
                  role="option"
                  aria-selected={active}
                  onClick={() => {
                    onSelectScan(s.scan_id);
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-3 rounded-[7px] px-2.5 py-2 text-left transition-colors hover:bg-surface-sunken"
                  style={{ background: active ? 'var(--accent-soft)' : 'transparent' }}
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-medium">{s.target_name}</div>
                    <div className="mt-0.5 text-[11px] tabular text-faint">
                      {formatNumber(s.total_artefacts)} assets ·{' '}
                      {new Date(s.created_at).toLocaleDateString(undefined, {
                        day: 'numeric',
                        month: 'short',
                      })}
                      {' · '}
                      {new Date(s.created_at).toLocaleTimeString(undefined, {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </div>
                  </div>
                  <span
                    className="shrink-0 text-[13px] font-semibold tabular"
                    style={{ color: meta.color }}
                  >
                    {s.quantum_readiness_score}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
