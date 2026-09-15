import React, { useState } from 'react';
import {
  ArrowRight,
  Check,
  Copy,
  Download,
  ExternalLink,
  FileJson,
  FileSpreadsheet,
  FileText,
  Loader2,
  Trash2,
  GitCompare,
  History,
} from 'lucide-react';
import { Alert, DataTable, EmptyState, Modal } from './ui/Primitives';
import { formatNumber, readinessMeta, riskMeta } from '../lib/risk';
import { isDesktop, openReport, saveReport } from '../lib/download';
import { MERGED_SCAN_ID } from '../lib/constants';

export default function ReportsView({ scanResult, scanHistory, onNavigate, onSelectScan, onDeleteScan }) {
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(null);
  const [notice, setNotice] = useState(null);

  if (!scanResult) {
    return (
      <EmptyState
        icon={FileText}
        title="Nothing to export"
        body="Run a scan to produce a CycloneDX CBOM, an audit report and a CSV inventory."
        action={
          <button className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Run a scan
            <ArrowRight className="h-4 w-4" />
          </button>
        }
      />
    );
  }

  const { summary } = scanResult;
  const readiness = readinessMeta(summary.quantum_readiness_score);
  const base = `/api/scans/${summary.scan_id}`;

  const copyScanId = async () => {
    try {
      await navigator.clipboard.writeText(summary.scan_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard may be unavailable in the WebView; the id is visible anyway */
    }
  };

  /**
   * Run an export. Every outcome is reported — a silent click was the original
   * bug, and "nothing happened" is indistinguishable from a failure.
   */
  const handleExport = async (item) => {
    setBusy(item.title);
    setNotice(null);
    try {
      const result = item.download
        ? await saveReport(item.path, item.filename)
        : await openReport(item.path);

      if (result.cancelled) return;
      if (!result.ok) {
        setNotice({ tone: 'error', text: `${item.title} failed: ${result.error}` });
        return;
      }
      setNotice({
        tone: 'success',
        text: item.download
          ? `${item.title} saved${result.path ? ` to ${result.path}` : ''}.`
          : `${item.title} opened${isDesktop() ? ' in your browser' : ' in a new tab'}.`,
      });
    } finally {
      setBusy(null);
    }
  };

  const exports = [
    {
      title: 'CycloneDX 1.6 CBOM',
      format: 'JSON',
      icon: FileJson,
      path: `${base}/cbom`,
      filename: `cyclonedx-cbom-${summary.scan_id}.json`,
      action: 'Download',
      download: true,
    },
    {
      title: 'Audit report',
      format: 'HTML',
      icon: FileText,
      path: `${base}/report/html`,
      filename: `ecdat-report-${summary.scan_id}.html`,
      action: 'Open',
      download: false,
    },
    {
      title: 'Inventory export',
      format: 'CSV',
      icon: FileSpreadsheet,
      path: `${base}/report/csv`,
      filename: `ecdat-inventory-${summary.scan_id}.csv`,
      action: 'Download',
      download: true,
    },
  ];

  return (
    <div className="animate-fade-in space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Reports and exports</h1>
        <p className="mt-1 text-[13px] text-muted">
          Audit-ready output for the currently loaded scan.
        </p>
      </div>

      {notice && (
        <Alert tone={notice.tone} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Alert>
      )}

      {/* Scan being exported */}
      <div className="panel flex flex-wrap items-center justify-between gap-4 p-4">
        <div className="min-w-0">
          <h2 className="truncate text-base font-semibold">{summary.target_name}</h2>
          <p className="mt-1 flex flex-wrap items-center gap-x-2 text-[13px] text-muted">
            <button
              onClick={copyScanId}
              className="mono inline-flex items-center gap-1 rounded px-1 text-[12px] transition-colors hover:text-ink"
              title="Copy scan id"
            >
              {summary.scan_id}
              {copied ? <Check className="h-3 w-3" style={{ color: 'var(--low)' }} /> : <Copy className="h-3 w-3 opacity-50" />}
            </button>
            <span>·</span>
            <span>{new Date(summary.created_at).toLocaleString()}</span>
            <span>·</span>
            <span>{formatNumber(summary.total_artefacts)} assets</span>
            <span>·</span>
            <span>Z = {summary.mosca_global_z}y</span>
          </p>
        </div>
        <div className="text-right">
          <div className="text-[11px] uppercase tracking-wide text-faint">Readiness</div>
          <div className="text-2xl font-bold tabular" style={{ color: readiness.color }}>
            {summary.quantum_readiness_score}
          </div>
        </div>
      </div>

      {/* Exports */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {exports.map((x) => (
          <div key={x.title} className="panel flex flex-col p-4">
            <div className="flex items-center justify-between">
              <x.icon className="h-5 w-5" style={{ color: 'var(--accent-hover)' }} aria-hidden="true" />
              <span className="mono text-[10px] font-semibold text-faint">{x.format}</span>
            </div>
            <h3 className="mt-2.5 flex-1 text-sm font-semibold">{x.title}</h3>
            <button
              onClick={() => handleExport(x)}
              disabled={busy === x.title}
              className="btn btn-secondary mt-4 w-full"
            >
              {busy === x.title ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : x.download ? (
                <Download className="h-3.5 w-3.5" />
              ) : (
                <ExternalLink className="h-3.5 w-3.5" />
              )}
              {busy === x.title ? 'Working…' : x.action}
            </button>
          </div>
        ))}
      </div>

      {/* What changed since another scan. A single scan says what the
          cryptography is; two say whether it is getting better or worse. */}
      {scanHistory.length > 1 && scanResult && (
        <ScanComparison scanResult={scanResult} scanHistory={scanHistory} />
      )}

      {/* History */}
      {scanHistory.length > 0 && (
        <div className="panel">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">
                <span className="panel-icon"><History className="h-[15px] w-[15px]" aria-hidden="true" /></span>
                Scan history
              </h2>
              <p className="panel-sub">Select one to load, or remove it.</p>
            </div>
          </div>
          <DataTable
            rows={scanHistory}
            rowKey={(s) => s.scan_id}
            pageSize={12}
            initialSort={{ key: 'created', dir: 'desc' }}
            columns={[
              {
                key: 'target',
                header: 'Target',
                sortValue: (s) => s.target_name,
                render: (s) => (
                  <div>
                    <div className="font-medium">{s.target_name}</div>
                    <div className="mono mt-0.5 text-[11px] text-faint">{s.scan_id}</div>
                  </div>
                ),
              },
              {
                key: 'created',
                header: 'Scanned',
                sortValue: (s) => s.created_at,
                render: (s) => (
                  <span className="text-[12px] text-muted">{new Date(s.created_at).toLocaleString()}</span>
                ),
              },
              {
                key: 'assets',
                header: 'Assets',
                sortValue: (s) => s.total_artefacts,
                className: 'text-right',
                render: (s) => <span className="tabular">{formatNumber(s.total_artefacts)}</span>,
              },
              {
                key: 'critical',
                header: 'Critical',
                sortValue: (s) => s.risk_distribution?.Critical || 0,
                className: 'text-right',
                render: (s) => {
                  const n = s.risk_distribution?.Critical || 0;
                  return (
                    <span
                      className="tabular"
                      style={{ color: n > 0 ? 'var(--critical)' : 'var(--ink-faint)' }}
                    >
                      {n}
                    </span>
                  );
                },
              },
              {
                key: 'score',
                header: 'Readiness',
                sortValue: (s) => s.quantum_readiness_score,
                className: 'text-right',
                render: (s) => (
                  <span
                    className="font-semibold tabular"
                    style={{ color: readinessMeta(s.quantum_readiness_score).color }}
                  >
                    {s.quantum_readiness_score}
                  </span>
                ),
              },
              {
                key: 'actions',
                header: '',
                render: (s) => (
                  <div className="flex justify-end gap-1">
                    <button
                      className="btn btn-ghost px-2"
                      style={{ minHeight: 30 }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectScan(s.scan_id);
                      }}
                    >
                      Load
                    </button>
                    <button
                      className="btn btn-ghost px-2"
                      style={{ minHeight: 30 }}
                      onClick={(e) => {
                        e.stopPropagation();
                        setConfirmDelete(s);
                      }}
                      aria-label={`Delete scan ${s.target_name}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ),
              },
            ]}
          />
        </div>
      )}

      <Modal
        open={Boolean(confirmDelete)}
        onClose={() => setConfirmDelete(null)}
        title="Delete this scan?"
        width="max-w-md"
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => setConfirmDelete(null)}>
              Cancel
            </button>
            <button
              className="btn btn-danger"
              onClick={() => {
                onDeleteScan(confirmDelete.scan_id);
                setConfirmDelete(null);
              }}
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </button>
          </>
        }
      >
        <p className="text-sm text-muted">
          <strong style={{ color: 'var(--ink)' }}>{confirmDelete?.target_name}</strong> and its
          stored inventory will be removed permanently. Exports you have already downloaded are
          unaffected.
        </p>
      </Modal>
    </div>
  );
}

/**
 * Compare the loaded scan against an earlier one.
 *
 * The earlier scan is the baseline and the loaded one is "now", so the report
 * reads in the direction time runs.
 */
function ScanComparison({ scanResult, scanHistory }) {
  const [baseline, setBaseline] = useState('');
  const [delta, setDelta] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const current = scanResult.summary.scan_id;
  const candidates = scanHistory.filter(
    (s) => s.scan_id !== current && s.scan_id !== MERGED_SCAN_ID
  );

  const run = async (baselineId) => {
    setBaseline(baselineId);
    setDelta(null);
    setError(null);
    if (!baselineId) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/scans/${baselineId}/compare/${current}`);
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || 'Could not compare these scans.');
      setDelta(body);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (candidates.length === 0) return null;

  const groups = delta
    ? [
        ['New', delta.added, 'var(--critical)'],
        ['Worse', delta.risk_worsened, 'var(--high)'],
        ['Changed', delta.parameters_changed, 'var(--medium)'],
        ['Improved', delta.risk_improved, 'var(--low)'],
        ['Removed', delta.removed, 'var(--ink-muted)'],
      ].filter(([, items]) => items?.length)
    : [];

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2 className="panel-title">
          <span className="panel-icon"><GitCompare className="h-[15px] w-[15px]" aria-hidden="true" /></span>
          What changed
        </h2>
          <p className="panel-sub">
            Against an earlier scan.
          </p>
        </div>
      </div>

      <div className="space-y-3 p-4">
        <select
          className="field"
          value={baseline}
          onChange={(e) => run(e.target.value)}
          aria-label="Baseline scan"
        >
          <option value="">Choose a scan to compare against…</option>
          {candidates.map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.target_name} · {new Date(s.created_at).toLocaleString()}
            </option>
          ))}
        </select>

        {busy && <p className="text-[13px] text-faint">Comparing…</p>}
        {error && <Alert tone="error">{error}</Alert>}

        {delta && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <GitCompare className="h-4 w-4 text-faint" aria-hidden="true" />
              <span className="text-[13px] font-semibold">{delta.verdict}</span>
            </div>

            {delta.notes?.length > 0 && (
              <Alert tone="warn" title="Not a like-for-like comparison">
                <ul className="list-inside list-disc space-y-0.5">
                  {delta.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </Alert>
            )}

            {groups.length === 0 ? (
              <p className="text-[13px] text-muted">
                No asset was added, removed or reclassified between these scans.
              </p>
            ) : (
              groups.map(([label, items, colour]) => (
                <div key={label}>
                  <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide"
                      style={{ color: colour }}>
                    {label} ({items.length})
                  </h4>
                  <ul className="divide-rows panel-sunken max-h-56 overflow-y-auto">
                    {items.slice(0, 40).map((e) => (
                      <li key={`${e.artefact_id}-${e.location}`}
                          className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[12px]">
                        <span className="min-w-0 flex-1 truncate font-medium">{e.name}</span>
                        {e.previous_risk_category && e.previous_risk_category !== e.risk_category && (
                          <span className="text-[11px] text-faint">
                            {e.previous_risk_category} → {e.risk_category}
                          </span>
                        )}
                        {e.parameter_changes &&
                          Object.entries(e.parameter_changes).map(([field, change]) => (
                            <span key={field} className="mono text-[11px] text-faint">
                              {field.replace(/_/g, ' ')}: {String(change.before)} →{' '}
                              {String(change.after)}
                            </span>
                          ))}
                        {e.risk_category && (
                          <span className={riskMeta(e.risk_category).badge}>
                            {e.risk_category}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            )}
          </>
        )}
      </div>
    </div>
  );
}
