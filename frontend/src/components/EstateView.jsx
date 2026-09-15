/**
 * The estate: every cryptographic asset across every stored scan.
 *
 * Deliberately not the same thing as the merged view on the Inventory tab. That
 * one deduplicates, so the same library found in two systems counts once —
 * which is right for measuring an inventory and wrong for planning work, since
 * those are two things to fix in two places. This shows both rows, attributed
 * to their system.
 *
 * Filtering, sorting and paging all happen on the server, so opening this on a
 * large estate fetches one page rather than the whole database.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Building2,
  ChevronLeft,
  ChevronRight,
  Database,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { Alert, EmptyState } from './ui/Primitives';
import { useAdmin } from '../lib/admin';
import { RISK_ORDER, fileName, formatNumber, riskMeta, vulnMeta } from '../lib/risk';

const SORTS = [
  { value: 'risk', label: 'Risk, then deadline' },
  { value: 'deadline', label: 'Nearest deadline' },
  { value: 'system', label: 'System' },
  { value: 'name', label: 'Asset name' },
  { value: 'occurrences', label: 'Most occurrences' },
];

const PAGE_SIZE = 50;

export default function EstateView() {
  const { isAdmin, adminFetch } = useAdmin();

  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState('risk');
  const [risk, setRisk] = useState('');
  const [system, setSystem] = useState('');
  const [family, setFamily] = useState('');
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');

  const [data, setData] = useState(null);
  const [facets, setFacets] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // One request after typing settles, not one per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setDebounced(search.trim()), 250);
    return () => clearTimeout(id);
  }, [search]);

  // Any filter change returns to the first page; page 7 of a new filter is
  // rarely where the user meant to land.
  useEffect(() => {
    setPage(1);
  }, [risk, system, family, overdueOnly, debounced, sortBy]);

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setBusy(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
        sort_by: sortBy,
      });
      if (risk) params.set('risk_category', risk);
      if (system) params.set('system_name', system);
      if (family) params.set('algorithm_family', family);
      if (overdueOnly) params.set('overdue_only', 'true');
      if (debounced) params.set('search', debounced);

      const res = await adminFetch(`/api/admin/artefacts?${params}`);
      if (!res.ok) throw new Error((await res.json()).detail || 'Could not load the estate.');
      setData(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }, [isAdmin, adminFetch, page, sortBy, risk, system, family, overdueOnly, debounced]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!isAdmin) return;
    adminFetch('/api/admin/facets')
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => b && setFacets(b))
      .catch(() => {
        /* filters fall back to free text */
      });
  }, [isAdmin, adminFetch]);

  const rows = data?.artefacts || [];
  const totalPages = data?.total_pages || 1;

  const overdueCount = useMemo(
    () => rows.filter((r) => r.is_overdue).length,
    [rows]
  );

  if (!isAdmin) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Admin sign-in required"
        body="The estate view shows every asset across every stored scan. Sign in from Settings to open it."
      />
    );
  }

  return (
    <div className="animate-fade-in space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="t-title flex items-center gap-2.5">
            <span className="panel-icon h-7 w-7"><Building2 className="h-4 w-4" aria-hidden="true" /></span>
            Estate
          </h1>
          <p className="mt-1 text-[13px] text-muted">
            {data ? formatNumber(data.total) : '—'} assets across every stored scan.
            Assets are not deduplicated here: the same library in two systems is
            two things to fix.
          </p>
        </div>
        <div className="flex items-center gap-2 text-[12px] text-faint">
          <Database className="h-3.5 w-3.5" aria-hidden="true" />
          {busy ? 'Loading…' : `Page ${data?.page || 1} of ${totalPages}`}
        </div>
      </div>

      {error && <Alert tone="error">{error}</Alert>}

      {data?.results_capped && (
        <Alert tone="warn" title="Result set capped">
          More than {formatNumber(data.cap)} assets matched. Narrow the filters —
          this page is a slice of the matches, not the whole estate.
        </Alert>
      )}

      {/* ---------------------------------------------------------- filters */}
      <div className="panel space-y-3 p-4">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint"
            aria-hidden="true"
          />
          <input
            className="field pl-9"
            placeholder="Search name, algorithm, path, system or purl…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search the estate"
          />
        </div>

        <div className="flex flex-wrap gap-2">
          <select className="field max-w-[170px]" value={risk}
                  onChange={(e) => setRisk(e.target.value)} aria-label="Risk band">
            <option value="">All risk bands</option>
            {RISK_ORDER.map((b) => (
              <option key={b} value={b}>{b}</option>
            ))}
          </select>

          <select className="field max-w-[210px]" value={system}
                  onChange={(e) => setSystem(e.target.value)} aria-label="System">
            <option value="">All systems</option>
            {(facets?.systems || []).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <select className="field max-w-[190px]" value={family}
                  onChange={(e) => setFamily(e.target.value)} aria-label="Algorithm family">
            <option value="">All algorithms</option>
            {(facets?.algorithm_families || []).map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>

          <select className="field max-w-[190px]" value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)} aria-label="Sort order">
            {SORTS.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>

          <label className="field-check">
            <input
              type="checkbox"
              checked={overdueOnly}
              onChange={(e) => setOverdueOnly(e.target.checked)}
            />
            Past their start date
          </label>
        </div>
      </div>

      {/* ------------------------------------------------------------ table */}
      {rows.length === 0 && !busy ? (
        <EmptyState
          icon={Search}
          title="Nothing matches"
          body="No asset in the estate matches these filters."
        />
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full text-left text-[12.5px]">
            <thead>
              <tr className="border-b border-line text-[11px] uppercase tracking-wide text-faint">
                <th className="px-3 py-2 font-semibold">Asset</th>
                <th className="px-3 py-2 font-semibold">System</th>
                <th className="px-3 py-2 font-semibold">Location</th>
                <th className="px-3 py-2 font-semibold">Status</th>
                <th className="px-3 py-2 font-semibold">Risk</th>
                <th className="px-3 py-2 font-semibold">Start by</th>
                <th className="px-3 py-2 font-semibold">Migrate to</th>
              </tr>
            </thead>
            <tbody className="divide-rows">
              {rows.map((a) => {
                const v = vulnMeta(a.quantum_vulnerability);
                return (
                  <tr key={`${a.scan_id}-${a.artefact_id}`}>
                    <td className="px-3 py-2">
                      <div className="font-medium">{a.name}</div>
                      {a.occurrence_count > 1 && (
                        <div className="text-[11px] text-faint">
                          {formatNumber(a.occurrence_count)} occurrences
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted">{a.system_name}</td>
                    <td className="mono px-3 py-2 text-[11px] text-faint" title={a.location}>
                      {fileName(a.location)}
                      {a.line_number ? `:${a.line_number}` : ''}
                    </td>
                    <td className="px-3 py-2">
                      <span className="text-[11px]" style={{ color: v.color }}>
                        {v.label}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {a.risk_category && (
                        <span className={riskMeta(a.risk_category).badge}>
                          {a.risk_category}
                        </span>
                      )}
                    </td>
                    <td className="mono px-3 py-2 tabular">
                      {a.is_overdue ? (
                        <span
                          className="inline-flex items-center gap-1"
                          style={{ color: 'var(--critical)' }}
                        >
                          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                          {a.must_start_by}
                        </span>
                      ) : (
                        a.must_start_by || '—'
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted">{a.recommended_standard || '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ----------------------------------------------------------- paging */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-[12px] text-faint">
            {overdueCount > 0 && `${overdueCount} on this page are past their start date`}
          </span>
          <div className="flex items-center gap-2">
            <button
              className="btn btn-ghost"
              disabled={page <= 1 || busy}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </button>
            <span className="mono text-[12px] tabular text-muted">
              {page} / {totalPages}
            </span>
            <button
              className="btn btn-ghost"
              disabled={page >= totalPages || busy}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
