/**
 * Cryptographic inventory.
 *
 * This merges three former tabs — CBOM Explorer, Mosca Sandbox and PQC Migration
 * Hub — because they were three views of one list. The Z slider now sits
 * directly above the table whose banding it changes, instead of on a separate
 * screen where you could not see the effect.
 *
 * Two defects from the old Mosca tab are fixed here:
 *  - useState was called after an early `return`, a conditional hook that
 *    crashed React as soon as a scan loaded while that tab was mounted.
 *  - Every slider tick fired a request that re-saved the whole scan. Requests
 *    are now debounced, and the projection does not mutate stored data.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowRight,
  ChevronRight,
  Cpu,
  FileSearch,
  Filter,
  Layers,
  RotateCcw,
  Save,
  Search,
  Sliders,
  CalendarClock,
  Gauge,
  Scale,
} from 'lucide-react';
import { Alert, DataTable, DefList, EmptyState, Modal, Segmented } from './ui/Primitives';
import { StackedShareBar } from './charts/Charts';
import { advisoryStyle, worstAdvisory } from '../lib/vulnerabilities';
import { MERGED_SCAN_ID } from '../lib/constants';
import {
  ARTEFACT_TYPE_LABELS,
  RISK_ORDER,
  PARAMETER_SOURCES,
  TARGET_LABELS,
  fileName,
  formatNumber,
  riskMeta,
  shortenPath,
  vulnMeta,
} from '../lib/risk';

const SECTIONS = [
  { value: 'assets', label: 'Assets', icon: Layers },
  { value: 'mosca', label: 'Mosca worksheet', icon: Sliders },
  { value: 'migration', label: 'Migration', icon: Cpu },
];

/**
 * Whether this asset is already broken without any quantum computer.
 *
 * The risk engine short-circuits these: Mosca's inequality is a claim about a
 * *future* adversary, and an asset broken by classical cryptanalysis today is
 * not waiting for one.
 */
function isAlreadyBroken(artefact) {
  return (
    artefact?.quantum_vulnerability === 'classically_broken' ||
    artefact?.algorithm_class === 'legacy_broken'
  );
}

/**
 * Whether a quantum adversary gains anything against this asset.
 *
 * Mirrors the engine: post-quantum by design, or safe at these parameters —
 * AES-256, SHA-384 — which is recorded as a vulnerability status rather than an
 * algorithm class.
 */
function isQuantumSafe(artefact) {
  return (
    artefact?.algorithm_class === 'post_quantum' ||
    artefact?.algorithm_class === 'hybrid' ||
    artefact?.quantum_vulnerability === 'quantum_safe' ||
    artefact?.quantum_vulnerability === 'hybrid_protected'
  );
}

/** Whether X + Y > Z describes this asset at all. */
function moscaApplies(artefact) {
  return !isAlreadyBroken(artefact) && !isQuantumSafe(artefact);
}

/**
 * The fourth tile of the Mosca worksheet.
 *
 * It used to render safety_margin_years unconditionally, in green whenever it
 * was positive — so an already-broken TLS 1.0 endpoint showed "Margin +2y" in
 * green directly beside "Critical risk" and "Already broken". The number was
 * arithmetically true and completely misleading: Z − (X + Y) says nothing about
 * an asset that no longer needs a quantum computer to break.
 *
 * It now shows the slack from whichever model actually binds, and says "n/a"
 * where the margin does not apply at all.
 */
function marginTile(artefact, risk) {
  if (isAlreadyBroken(artefact)) {
    return ['Margin', 'n/a', 'var(--critical)'];
  }
  // A quantum-safe asset has no slack to run out of. The raw Mosca margin is
  // still arithmetically computable and still negative for a long-lived
  // secret — showing it would put "-0.8y" in red beside a "Quantum-safe"
  // badge, which is the inequality being applied to an asset it says nothing
  // about.
  if (isQuantumSafe(artefact)) {
    return ['Margin', 'n/a', 'var(--low)'];
  }
  const slack = risk.slack_years != null ? risk.slack_years : risk.safety_margin_years;
  if (slack == null) return ['Margin', '—', 'var(--ink-muted)'];
  return [
    risk.slack_years != null ? 'Slack' : 'Margin',
    `${slack > 0 ? '+' : ''}${slack}y`,
    slack < 0 ? 'var(--critical)' : slack < 1 ? 'var(--high)' : 'var(--low)',
  ];
}

// Four models assess every asset and the one demanding the earliest start sets
// the schedule. These are their display names.
const BINDING_LABELS = {
  mosca: 'Mosca',
  probabilistic: 'Probabilistic',
  regulatory: 'Regulatory deadline',
  hndl: 'Harvest-now-decrypt-later',
};

export default function InventoryView({ scanResult, onNavigate }) {
  // Every hook runs unconditionally, before any early return.
  const [section, setSection] = useState('assets');
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [vulnFilter, setVulnFilter] = useState('ALL');
  const [active, setActive] = useState(null);

  const storedZ = scanResult?.summary.mosca_global_z ?? 8;
  const [sliderZ, setSliderZ] = useState(storedZ);
  const [projection, setProjection] = useState(null);
  const [recalculating, setRecalculating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState(null);
  const debounceRef = useRef(null);

  // Follow the loaded scan when the user switches scans.
  useEffect(() => {
    setSliderZ(storedZ);
    setProjection(null);
  }, [storedZ, scanResult?.summary.scan_id]);

  useEffect(() => () => clearTimeout(debounceRef.current), []);

  const scanId = scanResult?.summary.scan_id;

  const requestProjection = useCallback(
    (z) => {
      clearTimeout(debounceRef.current);
      if (z === storedZ) {
        setProjection(null);
        return;
      }
      // One request after the drag settles, not one per tick.
      debounceRef.current = setTimeout(async () => {
        setRecalculating(true);
        try {
          const res = await fetch(`/api/scans/${scanId}/recalculate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mosca_z: z, persist: false }),
          });
          if (!res.ok) throw new Error((await res.json()).detail || 'Could not recalculate.');
          setProjection(await res.json());
        } catch (e) {
          setNotice({ tone: 'error', text: e.message });
        } finally {
          setRecalculating(false);
        }
      }, 250);
    },
    [scanId, storedZ]
  );

  const commitZ = async () => {
    setSaving(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/recalculate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mosca_z: sliderZ, persist: true }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || 'Could not save.');
      setNotice({ tone: 'success', text: `Scan is now assessed at Z = ${sliderZ} years.` });
      setProjection(null);
      window.location.reload();
    } catch (e) {
      setNotice({ tone: 'error', text: e.message });
    } finally {
      setSaving(false);
    }
  };

  // The view renders the projection when one exists, otherwise the stored scan.
  const view = projection || scanResult;

  const artefacts = view?.artefacts || [];
  const risks = view?.risk_assessments || {};
  const recs = view?.recommendations || {};
  const plan = view?.migration_plan || null;

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return artefacts.filter((a) => {
      const risk = risks[a.id];
      if (riskFilter !== 'ALL' && risk?.risk_category !== riskFilter) return false;
      if (typeFilter !== 'ALL' && a.type !== typeFilter) return false;
      if (vulnFilter !== 'ALL' && a.quantum_vulnerability !== vulnFilter) return false;
      if (!q) return true;
      return (
        a.name.toLowerCase().includes(q) ||
        a.algorithm_family.toLowerCase().includes(q) ||
        a.location.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q)
      );
    });
  }, [artefacts, risks, search, riskFilter, typeFilter, vulnFilter]);

  if (!scanResult) {
    return (
      <EmptyState
        icon={FileSearch}
        title="No inventory yet"
        body="Run a scan to build a CycloneDX 1.6 cryptographic bill of materials."
        action={
          <button className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Run a scan
            <ArrowRight className="h-4 w-4" />
          </button>
        }
      />
    );
  }

  const summary = view.summary;
  const dirty = sliderZ !== storedZ;
  // The combined view is derived from the stored scans, so there is nothing to
  // save a horizon against — only individual scans carry an assessed Z.
  const isMerged = summary.scan_id === MERGED_SCAN_ID;

  const riskSegments = RISK_ORDER.map((name) => ({
    label: name,
    value: summary.risk_distribution[name] || 0,
    color: riskMeta(name).mark,
  }));

  return (
    <div className="animate-fade-in space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="t-title">Cryptographic inventory</h1>
          <p className="mt-1 text-[13px] text-muted">
            {formatNumber(summary.total_artefacts)} distinct assets
            {summary.total_occurrences > summary.total_artefacts && (
              <> across {formatNumber(summary.total_occurrences)} occurrences</>
            )}{' '}
            in <span style={{ color: 'var(--ink)' }}>{summary.target_name}</span>
          </p>
        </div>
        <Segmented options={SECTIONS} value={section} onChange={setSection} ariaLabel="Inventory section" />
      </div>

      {notice && (
        <Alert tone={notice.tone} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Alert>
      )}

      {/* Horizon control — always visible, because it governs every number below. */}
      <div className="panel p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-[260px] flex-1">
            <div className="flex items-center justify-between gap-3">
              <label className="label mb-0" htmlFor="inv-z">
                Quantum horizon (Z) — Mosca: at risk when X + Y &gt; Z
              </label>
              <span className="mono text-sm font-semibold tabular">
                {sliderZ}y
                {dirty && <span className="ml-1.5 text-[11px] font-normal text-faint">(saved: {storedZ}y)</span>}
              </span>
            </div>
            <input
              id="inv-z"
              type="range"
              min="2"
              max="20"
              step="0.5"
              value={sliderZ}
              onChange={(e) => {
                const z = parseFloat(e.target.value);
                setSliderZ(z);
                requestProjection(z);
              }}
              className="mt-2.5 w-full"
              style={{ accentColor: 'var(--accent)' }}
            />
            <p className="hint">
              {dirty && isMerged
                ? 'Showing a projection across every stored scan.'
                : dirty
                ? 'Showing a projection. The stored scan is unchanged until you save.'
                : 'Drag to test how the inventory re-bands against a different quantum timeline.'}
            </p>
          </div>

          <div className="flex items-center gap-2 pt-5">
            {recalculating && <span className="text-xs text-faint">Recalculating…</span>}
            {dirty && (
              <>
                <button
                  className="btn btn-ghost"
                  onClick={() => {
                    setSliderZ(storedZ);
                    setProjection(null);
                  }}
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Reset
                </button>
                {!isMerged && (
                  <button className="btn btn-secondary" onClick={commitZ} disabled={saving}>
                    <Save className="h-3.5 w-3.5" />
                    {saving ? 'Saving…' : 'Save as assessed'}
                  </button>
                )}
              </>
            )}
          </div>
        </div>

        <div className="mt-4 border-t border-line pt-4">
          <StackedShareBar segments={riskSegments} total={summary.total_artefacts} height={9} />
        </div>
      </div>

      {section === 'assets' && (
        <AssetsSection
          filtered={filtered}
          risks={risks}
          search={search}
          setSearch={setSearch}
          riskFilter={riskFilter}
          setRiskFilter={setRiskFilter}
          typeFilter={typeFilter}
          setTypeFilter={setTypeFilter}
          vulnFilter={vulnFilter}
          setVulnFilter={setVulnFilter}
          onInspect={setActive}
          total={artefacts.length}
        />
      )}

      {section === 'mosca' && <MoscaSection artefacts={filtered} risks={risks} z={sliderZ} />}

      {section === 'migration' && (
        <MigrationSection
          artefacts={filtered}
          risks={risks}
          recs={recs}
          plan={plan}
          allArtefacts={artefacts}
          onInspect={setActive}
        />
      )}

      <AssetDrawer
        artefact={active}
        risk={active ? risks[active.id] : null}
        rec={active ? recs[active.id] : null}
        onClose={() => setActive(null)}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ Assets */

function AssetsSection({
  filtered,
  risks,
  search,
  setSearch,
  riskFilter,
  setRiskFilter,
  typeFilter,
  setTypeFilter,
  vulnFilter,
  setVulnFilter,
  onInspect,
  total,
}) {
  return (
    <div className="panel">
      <div className="flex flex-wrap items-center gap-2.5 border-b border-line p-3">
        <div className="relative min-w-[200px] flex-1">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
            aria-hidden="true"
          />
          <input
            className="field pl-8"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search algorithm, path or asset id"
            aria-label="Search assets"
          />
        </div>

        <select
          className="field w-auto"
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          aria-label="Filter by risk"
        >
          <option value="ALL">All risk levels</option>
          {RISK_ORDER.map((r) => (
            <option key={r} value={r}>
              {r} risk
            </option>
          ))}
        </select>

        <select
          className="field w-auto"
          value={vulnFilter}
          onChange={(e) => setVulnFilter(e.target.value)}
          aria-label="Filter by quantum vulnerability"
        >
          <option value="ALL">All quantum statuses</option>
          <option value="fully_broken">Broken by Shor's</option>
          <option value="classically_broken">Already broken</option>
          <option value="degraded">Degraded by Grover's</option>
          <option value="quantum_safe">Quantum-safe</option>
          <option value="hybrid_protected">Hybrid protected</option>
          <option value="unknown">Undetermined</option>
        </select>

        <select
          className="field w-auto"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          aria-label="Filter by asset type"
        >
          <option value="ALL">All asset types</option>
          {Object.entries(ARTEFACT_TYPE_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>

        {/* Always rendered, only made visible when a filter narrows the set.
            Mounting it on demand changed the width of the row, so every filter
            change nudged the dropdowns sideways under the pointer — the control
            you had just used moved out from under you. */}
        <span
          className="ml-auto flex shrink-0 items-center gap-1.5 text-xs text-faint"
          style={{ visibility: filtered.length !== total ? 'visible' : 'hidden' }}
          aria-hidden={filtered.length === total}
        >
          <Filter className="h-3 w-3" aria-hidden="true" />
          {formatNumber(filtered.length)} of {formatNumber(total)}
        </span>
      </div>

      <DataTable
        rows={filtered}
        rowKey={(a) => a.id}
        onRowClick={onInspect}
        initialSort={null}
        columns={[
          {
            key: 'name',
            header: 'Asset',
            sortValue: (a) => a.name,
            render: (a) => (
              <div>
                <div className="font-medium">{a.name}</div>
                <div className="mt-0.5 text-[11px] text-faint">
                  {ARTEFACT_TYPE_LABELS[a.type] || a.type}
                  {a.mode_or_padding ? ` · ${a.mode_or_padding}` : ''}
                </div>
              </div>
            ),
          },
          {
            key: 'location',
            header: 'Location',
            sortValue: (a) => a.location,
            render: (a) => (
              <div className="mono max-w-[260px] text-[11px] text-muted" title={a.location}>
                <div className="truncate">
                  {shortenPath(a.location, 40)}
                  {a.line_number ? `:${a.line_number}` : ''}
                </div>
                {a.occurrence_count > 1 && (
                  <div className="text-faint">
                    {a.occurrence_count} occurrences
                  </div>
                )}
              </div>
            ),
          },
          {
            key: 'surface',
            header: 'Found in',
            sortValue: (a) => a.target_type,
            render: (a) => (
              <span className="text-[12px] text-muted">{TARGET_LABELS[a.target_type] || a.target_type}</span>
            ),
          },
          {
            key: 'quantum',
            header: 'Quantum status',
            sortValue: (a) => a.quantum_vulnerability,
            render: (a) => {
              const v = vulnMeta(a.quantum_vulnerability);
              return (
                <span className={v.badge}>
                  <span aria-hidden="true">{v.glyph}</span>
                  {v.short}
                </span>
              );
            },
          },
          {
            key: 'criticality',
            header: 'Business impact',
            sortValue: (a) => ({ Critical: 3, High: 2, Medium: 1, Low: 0 }[a.business_criticality] ?? 0),
            render: (a) => <span className="text-[12px] text-muted">{a.business_criticality}</span>,
          },
          ...(filtered.some((a) => a.known_vulnerabilities?.length)
            ? [
                {
                  key: 'advisories',
                  header: 'Advisories',
                  sortValue: (a) => a.known_vulnerabilities?.length || 0,
                  render: (a) => {
                    const worst = worstAdvisory(a);
                    if (!worst) return <span className="text-faint">—</span>;
                    const style = advisoryStyle(worst.severity);
                    return (
                      <span className={style.badge} title={worst.summary}>
                        {a.known_vulnerabilities.length} known
                      </span>
                    );
                  },
                },
              ]
            : []),
          {
            key: 'risk',
            header: 'Risk',
            sortValue: (a) =>
              ({ Critical: 3, High: 2, Medium: 1, Low: 0 }[risks[a.id]?.risk_category] ?? -1),
            render: (a) => {
              const risk = risks[a.id];
              if (!risk) return <span className="text-faint">—</span>;
              const m = riskMeta(risk.risk_category);
              return (
                <span className={m.badge}>
                  <span aria-hidden="true">{m.glyph}</span>
                  {risk.risk_category}
                </span>
              );
            },
          },
        ]}
        emptyMessage="No assets match these filters."
      />
    </div>
  );
}

/* ------------------------------------------------------------------ Mosca */

function MoscaSection({ artefacts, risks, z }) {

  return (
    <div className="space-y-4">

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2 className="panel-title">Mosca worksheet</h2>
            <p className="panel-sub">At Z = {z} years.</p>
          </div>
        </div>
        <DataTable
          rows={artefacts}
          rowKey={(a) => a.id}
          pageSize={30}
          columns={[
            {
              key: 'name',
              header: 'Asset',
              sortValue: (a) => a.name,
              render: (a) => (
                <div>
                  <div className="font-medium">{a.name}</div>
                  <div className="mono mt-0.5 text-[11px] text-faint">{fileName(a.location)}</div>
                </div>
              ),
            },
            {
              key: 'x',
              header: 'X · shelf life',
              sortValue: (a) => risks[a.id]?.shelf_life_x,
              className: 'text-right',
              render: (a) => <span className="mono tabular">{risks[a.id]?.shelf_life_x}y</span>,
            },
            {
              key: 'y',
              header: 'Y · migration',
              sortValue: (a) => risks[a.id]?.migration_time_y,
              className: 'text-right',
              render: (a) => <span className="mono tabular">{risks[a.id]?.migration_time_y}y</span>,
            },
            {
              key: 'sum',
              header: 'X + Y',
              sortValue: (a) => risks[a.id]?.x_plus_y,
              className: 'text-right',
              render: (a) => (
                <span className="mono font-semibold tabular">{risks[a.id]?.x_plus_y}y</span>
              ),
            },
            {
              key: 'verdict',
              header: 'X + Y > Z',
              sortValue: (a) => (risks[a.id]?.is_at_risk ? 1 : 0),
              render: (a) => {
                const r = risks[a.id];
                if (!r) return '—';
                // An asset broken by classical cryptanalysis is not "within
                // margin" — the inequality simply does not describe it. Showing
                // a green badge here put "Within margin" beside "Critical risk"
                // on the same row.
                if (isAlreadyBroken(a)) {
                  return (
                    <span className="badge badge-critical">
                      <span aria-hidden="true">▲</span> Already broken
                    </span>
                  );
                }
                if (isQuantumSafe(a)) {
                  return (
                    <span className="badge badge-low">
                      <span aria-hidden="true">●</span> Quantum-safe
                    </span>
                  );
                }
                return r.is_at_risk ? (
                  <span className="badge badge-critical">
                    <span aria-hidden="true">▲</span> At risk
                  </span>
                ) : (
                  <span className="badge badge-low">
                    <span aria-hidden="true">●</span> Within margin
                  </span>
                );
              },
            },
            {
              key: 'margin',
              header: 'Slack',
              sortValue: (a) =>
                risks[a.id]?.slack_years ?? risks[a.id]?.safety_margin_years,
              className: 'text-right',
              render: (a) => {
                const r = risks[a.id];
                if (!r) return '—';
                if (!moscaApplies(a)) {
                  return <span className="mono tabular text-faint">n/a</span>;
                }
                // The slack from whichever model binds, falling back to the raw
                // Mosca margin for scans stored before the schedule existed.
                const m = r.slack_years != null ? r.slack_years : r.safety_margin_years;
                if (m == null) return '—';
                return (
                  <span
                    className="mono tabular"
                    style={{ color: m < 0 ? 'var(--critical)' : m < 1 ? 'var(--high)' : m < 3 ? 'var(--medium)' : 'var(--low)' }}
                  >
                    {m > 0 ? `+${m}` : m}y
                  </span>
                );
              },
            },
            {
              key: 'risk',
              header: 'Band',
              sortValue: (a) =>
                ({ Critical: 3, High: 2, Medium: 1, Low: 0 }[risks[a.id]?.risk_category] ?? -1),
              render: (a) => {
                const r = risks[a.id];
                if (!r) return '—';
                const m = riskMeta(r.risk_category);
                return (
                  <span className={m.badge}>
                    <span aria-hidden="true">{m.glyph}</span>
                    {r.risk_category}
                  </span>
                );
              },
            },
          ]}
        />
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- Migration */

const STANDARDS = [
  {
    code: 'FIPS 203',
    name: 'ML-KEM',
    former: 'CRYSTALS-Kyber',
    role: 'Key establishment',
    replaces: 'RSA key transport, ECDH, Diffie-Hellman',
    params: ['ML-KEM-512', 'ML-KEM-768 (recommended)', 'ML-KEM-1024'],
  },
  {
    code: 'FIPS 204',
    name: 'ML-DSA',
    former: 'CRYSTALS-Dilithium',
    role: 'Digital signatures',
    replaces: 'RSA-PSS, ECDSA, Ed25519',
    params: ['ML-DSA-44', 'ML-DSA-65 (recommended)', 'ML-DSA-87'],
  },
  {
    code: 'FIPS 205',
    name: 'SLH-DSA',
    former: 'SPHINCS+',
    role: 'Hash-based signatures',
    replaces: 'Long-lived root and firmware signing keys',
    params: ['SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-256s'],
  },
];

function MigrationSection({ artefacts, risks, recs, plan, allArtefacts, onInspect }) {
  // Group assets by the standard they migrate to, so the output is a work plan
  // rather than one near-identical card per artefact.
  const groups = useMemo(() => {
    const map = new Map();
    for (const a of artefacts) {
      const rec = recs[a.id];
      const risk = risks[a.id];
      if (!rec || !risk) continue;
      const key = rec.recommended_standard;
      if (!map.has(key)) {
        map.set(key, { standard: key, rec, items: [], worst: 0 });
      }
      const g = map.get(key);
      g.items.push({ art: a, risk });
      g.worst = Math.max(g.worst, { Critical: 3, High: 2, Medium: 1, Low: 0 }[risk.risk_category] ?? 0);
    }
    return [...map.values()].sort((a, b) => b.worst - a.worst || b.items.length - a.items.length);
  }, [artefacts, risks, recs]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {STANDARDS.map((s) => (
          <div key={s.code} className="panel p-4">
            <div className="flex items-baseline justify-between">
              <span className="mono text-[11px] font-semibold" style={{ color: 'var(--accent-hover)' }}>
                NIST {s.code}
              </span>
              <span className="text-[11px] text-faint">{s.role}</span>
            </div>
            <h3 className="mt-1.5 text-sm font-semibold">{s.name}</h3>
            <p className="mt-0.5 text-[11px] text-faint">formerly {s.former}</p>
            <p className="mt-2 text-xs leading-snug text-muted">Replaces {s.replaces}.</p>
            <ul className="mono mt-2.5 space-y-0.5 text-[11px] text-faint">
              {s.params.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {plan && (
        <MigrationSchedule
          plan={plan}
          artefacts={allArtefacts || artefacts}
          risks={risks}
          onInspect={onInspect}
        />
      )}

      {groups.length === 0 ? (
        <EmptyState icon={Cpu} title="Nothing to migrate" body="No assets in the current filter need a migration path." />
      ) : (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold">
            Migration plan — {groups.length} {groups.length === 1 ? 'group' : 'groups'}
          </h2>
          {groups.map((g) => (
            <MigrationGroup key={g.standard} group={g} />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * The assets inside one wave.
 *
 * Ordered worst-first and then by nearest deadline, which is the order the
 * work is actually picked up in. Each row opens the same drawer the Assets
 * table does, so a wave is a way into the inventory rather than a dead end.
 */
function WaveAssets({ wave, byId, risks, onInspect }) {
  const rows = useMemo(() => {
    const rank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return (wave.artefact_ids || [])
      .map((id) => ({ art: byId.get(id), risk: risks?.[id] }))
      .filter((r) => r.art)
      .sort((a, b) => {
        const byBand =
          (rank[a.risk?.risk_category] ?? 9) - (rank[b.risk?.risk_category] ?? 9);
        if (byBand !== 0) return byBand;
        return (a.risk?.must_start_by || '9999').localeCompare(
          b.risk?.must_start_by || '9999'
        );
      });
  }, [wave, byId, risks]);

  if (rows.length === 0) {
    return (
      <p className="mt-2.5 text-xs text-faint">
        The assets in this wave are not in the loaded inventory — this can happen
        on the combined view, where the plan is rebuilt from every stored scan.
      </p>
    );
  }

  return (
    <ul className="divide-rows panel-sunken mt-2.5 max-h-72 overflow-y-auto">
      {rows.map(({ art, risk }) => (
        <li key={art.id}>
          <button
            type="button"
            className="flex w-full items-center gap-3 px-3 py-2 text-left text-[12px] hover:bg-[var(--surface)]"
            onClick={() => onInspect?.(art)}
          >
            <span className="min-w-0 flex-1 truncate font-medium">{art.name}</span>
            <span
              className="mono min-w-0 flex-1 truncate text-[11px] text-faint"
              title={art.location}
            >
              {fileName(art.location)}
              {art.line_number ? `:${art.line_number}` : ''}
            </span>
            {risk?.must_start_by && (
              <span
                className="mono shrink-0 text-[11px] tabular"
                style={{ color: risk.is_overdue ? 'var(--critical)' : 'var(--ink-muted)' }}
              >
                {risk.must_start_by}
              </span>
            )}
            {risk?.risk_category && (
              <span className={`${riskMeta(risk.risk_category).badge} shrink-0`}>
                {risk.risk_category}
              </span>
            )}
          </button>
        </li>
      ))}
    </ul>
  );
}

/**
 * The migration plan as a schedule.
 *
 * Grouping by target standard says what to install; this says when, and — more
 * usefully — where the plan does not work. A wave whose deadline has already
 * passed is shown as a breach rather than as a window, because rendering it as
 * one would read "2026 to 2023".
 */
function MigrationSchedule({ plan, artefacts, risks, onInspect }) {
  // Which wave is open. Only one at a time: these lists run to dozens of rows
  // and several open at once makes the schedule itself unreadable.
  const [openWave, setOpenWave] = useState(null);

  // Waves carry artefact ids, so they are resolved against the *unfiltered*
  // inventory. Resolving against the filtered list would make assets vanish
  // from a wave whenever a filter was active, which reads as the plan having
  // changed.
  const byId = useMemo(() => {
    const map = new Map();
    for (const a of artefacts || []) map.set(a.id, a);
    return map;
  }, [artefacts]);

  if (!plan?.waves?.length) return null;

  return (
    <div className="panel p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="panel-title">
          <span className="panel-icon"><CalendarClock className="h-[15px] w-[15px]" aria-hidden="true" /></span>
          Schedule
        </h2>
        <span className="text-[11px] text-faint">
          critical path {plan.critical_path_years} years · generated {plan.generated_on}
        </span>
      </div>

      <ol className="mt-3 space-y-2">
        {plan.waves.map((w) => {
          const tone = w.deadline_already_passed
            ? 'var(--critical)'
            : w.is_infeasible
              ? 'var(--high)'
              : 'var(--line-strong)';
          const open = openWave === w.sequence;
          return (
            <li
              key={w.sequence}
              className="rounded-[9px] p-3"
              style={{ border: `1px solid ${tone}`, background: 'var(--surface-sunken)' }}
            >
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <button
                  type="button"
                  className="flex items-center gap-1.5 text-[13px] font-semibold hover:underline"
                  aria-expanded={open}
                  onClick={() => setOpenWave(open ? null : w.sequence)}
                >
                  <ChevronRight
                    className="h-3.5 w-3.5 transition-transform"
                    style={{ transform: open ? 'rotate(90deg)' : 'none' }}
                    aria-hidden="true"
                  />
                  {w.label}
                </button>
                <span className="mono text-[11px] tabular text-muted">
                  {w.asset_count} asset{w.asset_count === 1 ? '' : 's'}
                  {' · '}
                  {w.deadline_already_passed ? (
                    <span style={{ color: 'var(--critical)' }}>
                      deadline passed {w.must_complete_by}
                    </span>
                  ) : (
                    <>
                      {w.starts_on} → {w.must_complete_by}
                    </>
                  )}
                </span>
              </div>

              <p className="mt-1 text-xs leading-relaxed text-muted">{w.rationale}</p>

              {w.deadline_already_passed ? (
                <p className="mt-1.5 text-xs font-semibold" style={{ color: 'var(--critical)' }}>
                  Already non-compliant.
                </p>
              ) : (
                w.is_infeasible && (
                  <p className="mt-1.5 text-xs font-semibold" style={{ color: 'var(--high)' }}>
                    Cannot be completed on time: the longest job here takes{' '}
                    {w.longest_migration_years} years, which overruns by {w.shortfall_years}.
                  </p>
                )
              )}

              <div className="mt-2 flex flex-wrap gap-1.5">
                {RISK_ORDER.filter((band) => w.risk_distribution?.[band]).map((band) => (
                  <span key={band} className={riskMeta(band).badge}>
                    {w.risk_distribution[band]} {band}
                  </span>
                ))}
              </div>

              {open && (
                <WaveAssets
                  wave={w}
                  byId={byId}
                  risks={risks}
                  onInspect={onInspect}
                />
              )}
            </li>
          );
        })}
      </ol>

    </div>
  );
}

function MigrationGroup({ group }) {
  const [open, setOpen] = useState(false);
  const { rec, items } = group;
  const worstBand = ['Low', 'Medium', 'High', 'Critical'][group.worst];
  const meta = riskMeta(worstBand);

  return (
    <div className="panel overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-surface-hover"
        aria-expanded={open}
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold" style={{ color: 'var(--low)' }}>
              {group.standard}
            </span>
            <span className={meta.badge}>
              <span aria-hidden="true">{meta.glyph}</span>
              {worstBand}
            </span>
          </div>
          <p className="mt-1 text-xs text-muted">
            {items.length} {items.length === 1 ? 'asset' : 'assets'} · {rec.migration_urgency} ·{' '}
            {rec.latency_impact}
          </p>
        </div>
        <ArrowRight
          className="h-4 w-4 shrink-0 text-faint transition-transform"
          style={{ transform: open ? 'rotate(90deg)' : 'none' }}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div className="space-y-4 border-t border-line p-4">
          {/* Shown for every asset. These used to be gated behind a hybrid
              recommendation, so cost, alternatives and size impact were hidden
              for symmetric ciphers, hashes, libraries and hardware modules —
              exactly the assets whose cost is hardest to guess. */}
          <DefList
            items={[
              rec.nist_category && {
                term: 'Standard',
                value: [
                  rec.standard_reference,
                  `Category ${rec.nist_category}`,
                  rec.replaces_classical_bits
                    ? `replaces ${rec.replaces_classical_bits}-bit`
                    : null,
                ]
                  .filter(Boolean)
                  .join(' · '),
              },
              rec.hybrid_recommendation && {
                term: 'Hybrid option',
                value: rec.hybrid_recommendation,
              },
              { term: 'Urgency', value: rec.migration_urgency },
              { term: 'Estimated cost', value: rec.estimated_migration_cost },
              rec.latency_impact && { term: 'Size impact', value: rec.latency_impact },
              rec.alternative_options?.length && {
                term: 'Alternatives',
                value: rec.alternative_options.join(' · '),
              },
            ].filter(Boolean)}
          />

          {rec.selection_rationale && (
            <p className="text-[13px] leading-relaxed text-muted">
              <strong className="font-semibold">Why this target: </strong>
              {rec.selection_rationale}
            </p>
          )}

          {rec.implementation_targets?.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
                Where to get it
              </h4>
              <ul className="space-y-1 text-[13px] text-muted">
                {rec.implementation_targets.map((impl) => (
                  <li key={impl}>{impl}</li>
                ))}
              </ul>
              {rec.not_a_migration_target && (
                <p className="mt-1.5 text-xs text-faint">{rec.not_a_migration_target}</p>
              )}
            </div>
          )}

          {rec.migration_steps?.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
                Steps
              </h4>
              <ol className="space-y-1 text-[13px] text-muted">
                {rec.migration_steps.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ol>
            </div>
          )}

          {rec.code_diff_example && (
            <div>
              <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
                Example change
              </h4>
              <pre className="panel-sunken overflow-x-auto p-3.5 text-[11.5px] leading-relaxed">
                <code>
                  {rec.code_diff_example.split('\n').map((line, i) => (
                    <div
                      key={i}
                      style={{
                        color: line.startsWith('+')
                          ? 'var(--low)'
                          : line.startsWith('-')
                          ? 'var(--critical)'
                          : 'var(--ink-muted)',
                      }}
                    >
                      {line || ' '}
                    </div>
                  ))}
                </code>
              </pre>
            </div>
          )}

          <div>
            <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
              Affected assets
            </h4>
            <ul className="divide-rows panel-sunken">
              {items.slice(0, 25).map(({ art, risk }) => (
                <li key={art.id} className="flex items-center gap-3 px-3 py-2 text-[12px]">
                  <span className="min-w-0 flex-1 truncate font-medium">{art.name}</span>
                  <span className="mono min-w-0 flex-1 truncate text-[11px] text-faint" title={art.location}>
                    {fileName(art.location)}
                    {art.line_number ? `:${art.line_number}` : ''}
                  </span>
                  <span className={riskMeta(risk.risk_category).badge}>{risk.risk_category}</span>
                </li>
              ))}
              {items.length > 25 && (
                <li className="px-3 py-2 text-[11px] text-faint">
                  and {items.length - 25} more — see the Assets table
                </li>
              )}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Drawer */

function AssetDrawer({ artefact, risk, rec, onClose }) {
  if (!artefact) return null;
  const v = vulnMeta(artefact.quantum_vulnerability);

  return (
    <Modal
      open
      onClose={onClose}
      title={artefact.name}
      subtitle={`${ARTEFACT_TYPE_LABELS[artefact.type] || artefact.type} · ${artefact.id}`}
      width="max-w-3xl"
      footer={
        <button className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      <div className="space-y-5">
        <DefList
          items={[
            { term: 'Algorithm family', value: artefact.algorithm_family },
            { term: 'Key length', value: artefact.key_size_bits ? `${artefact.key_size_bits} bits` : '—' },
            { term: 'Curve', value: artefact.curve },
            { term: 'Mode / padding', value: artefact.mode_or_padding },
            // The key length drives the Mosca band, so how it was obtained is
            // part of the evidence rather than a footnote. A measured 1024 and
            // an assumed 2048 must not read the same.
            ...(PARAMETER_SOURCES[artefact.parameter_source]
              ? [{
                  term: 'Parameters',
                  value: PARAMETER_SOURCES[artefact.parameter_source],
                }]
              : []),
            { term: 'Discovery surface', value: TARGET_LABELS[artefact.target_type] },
            { term: 'Business impact', value: artefact.business_criticality },
            { term: 'Asset lifetime', value: artefact.artefact_lifetime },
            { term: 'Location', value: artefact.location, mono: true },
            ...(artefact.purl
              ? [{ term: 'Package URL', value: artefact.purl, mono: true }]
              : []),
            ...(artefact.source_scans?.length
              ? [{ term: 'Found by', value: artefact.source_scans.join(', ') }]
              : []),
          ]}
        />

        {artefact.known_vulnerabilities?.length > 0 && (
          <div className="panel-sunken p-3.5">
            <div className="flex items-center justify-between gap-3">
              <h4 className="text-[13px] font-semibold">
                Known vulnerabilities ({artefact.known_vulnerabilities.length})
              </h4>
              <span className="text-[11px] text-faint">
                Published advisories, separate from quantum risk
              </span>
            </div>
            {artefact.version_is_range && (
              <p className="mt-1.5 text-[11.5px] text-muted">
                Range-pinned: matched against the lowest allowed version.
              </p>
            )}
            <ul className="divide-rows mt-2.5">
              {artefact.known_vulnerabilities.map((v) => {
                const style = advisoryStyle(v.severity);
                return (
                  <li key={v.id} className="py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="mono text-[12px] font-medium">{v.id}</span>
                      <span className={style.badge}>{v.severity}</span>
                      {v.aliases?.slice(0, 2).map((alias) => (
                        <span key={alias} className="mono text-[11px] text-faint">
                          {alias}
                        </span>
                      ))}
                    </div>
                    {v.summary && (
                      <p className="mt-1 text-[12px] leading-snug text-muted">{v.summary}</p>
                    )}
                    {v.fixed_version && (
                      <p className="mt-1 text-[11.5px]" style={{ color: 'var(--low)' }}>
                        Fixed in {v.fixed_version}
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        <div className="panel-sunken p-3.5">
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-[13px] font-semibold">Quantum exposure</h4>
            <span className={v.badge}>
              <span aria-hidden="true">{v.glyph}</span>
              {v.label}
            </span>
          </div>
          <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{v.detail}</p>
          {artefact.broken_by && (
            <p className="mt-1.5 text-xs text-faint">
              <strong>Broken by:</strong> {artefact.broken_by}
            </p>
          )}
        </div>

        {risk && (
          <div className="panel-sunken p-3.5">
            <div className="flex items-center justify-between gap-3">
              <h4 className="panel-title text-[13px]">
                <span className="panel-icon h-[22px] w-[22px]"><Scale className="h-[13px] w-[13px]" aria-hidden="true" /></span>
                Mosca assessment
              </h4>
              <span className={riskMeta(risk.risk_category).badge}>
                <span aria-hidden="true">{riskMeta(risk.risk_category).glyph}</span>
                {risk.risk_category} risk
              </span>
            </div>
            <div className="mt-3 grid grid-cols-4 gap-2 text-center">
              {[
                ['X · shelf life', `${risk.shelf_life_x}y`, 'var(--ink)'],
                ['Y · migration', `${risk.migration_time_y}y`, 'var(--ink)'],
                ['Z · horizon', `${risk.threat_timeline_z}y`, 'var(--accent)'],
                marginTile(artefact, risk),
              ].map(([label, value, color]) => (
                <div key={label} className="rounded border border-line px-2 py-1.5">
                  <div className="text-[10px] uppercase tracking-wide text-faint">{label}</div>
                  <div className="mono mt-0.5 text-sm font-semibold tabular" style={{ color }}>
                    {value}
                  </div>
                </div>
              ))}
            </div>

            {isQuantumSafe(artefact) && (
              <p className="mt-2 text-xs leading-relaxed" style={{ color: 'var(--low)' }}>
                Mosca's inequality measures exposure to a quantum adversary. No
                known quantum attack gains a useful advantage against this asset
                at these parameters, so there is no deadline and nothing to
                migrate.
              </p>
            )}

            {isAlreadyBroken(artefact) && (
              <p className="mt-2 text-xs leading-relaxed" style={{ color: 'var(--critical)' }}>
                Mosca's margin describes exposure to a future quantum adversary.
                This primitive is broken by a present-day one, so the margin does
                not apply and the horizon cannot make it acceptable.
              </p>
            )}
            <p className="mt-3 text-[13px] leading-relaxed text-muted">{risk.explanation}</p>

            {risk.must_start_by && (
              <div className="mt-3 rounded border border-line bg-surface p-2.5">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="text-[10px] uppercase tracking-wide text-faint">
                    Migration window
                  </span>
                  {risk.binding_model && (
                    <span className="text-[10px] text-faint">
                      set by the {BINDING_LABELS[risk.binding_model] || risk.binding_model} model
                    </span>
                  )}
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px]">
                  <span className="text-muted">Start by</span>
                  <span
                    className="mono font-semibold tabular"
                    style={{ color: risk.is_overdue ? 'var(--critical)' : 'var(--ink)' }}
                  >
                    {risk.must_start_by}
                  </span>
                  <span className="text-faint" aria-hidden="true">→</span>
                  <span className="text-muted">finish by</span>
                  <span className="mono font-semibold tabular">{risk.must_complete_by}</span>
                </div>
                {risk.is_overdue ? (
                  <p className="mt-1 text-xs font-semibold" style={{ color: 'var(--critical)' }}>
                    Overdue by {Math.abs(risk.slack_years)} years.
                  </p>
                ) : (
                  <p className="mt-1 text-xs text-faint">
                    {risk.slack_years} years before work must begin.
                  </p>
                )}
              </div>
            )}

            {risk.model_verdicts?.length > 0 && (
              <ul className="mt-2.5 space-y-1.5">
                {risk.model_verdicts.map((v) => (
                  <li key={v.model} className="text-xs leading-relaxed">
                    <span
                      className="font-semibold"
                      style={{ color: v.at_risk ? 'var(--critical)' : 'var(--muted)' }}
                    >
                      {BINDING_LABELS[v.model] || v.model}
                    </span>
                    <span className="text-muted"> — {v.detail}</span>
                    {v.source && <span className="text-faint"> ({v.source})</span>}
                  </li>
                ))}
              </ul>
            )}

            {(risk.shelf_life_rationale || risk.migration_time_explanation) && (
              <details className="mt-2.5">
                <summary className="cursor-pointer text-xs text-faint">
                  How X and Y were derived
                </summary>
                {risk.shelf_life_rationale && (
                  <p className="mt-1.5 text-xs leading-relaxed text-muted">
                    <strong>X</strong> — {risk.shelf_life_rationale}
                  </p>
                )}
                {risk.migration_time_explanation && (
                  <p className="mt-1 text-xs leading-relaxed text-muted">
                    <strong>Y</strong> — {risk.migration_time_explanation}
                  </p>
                )}
              </details>
            )}
          </div>
        )}

        {artefact.agility_score != null && (
          <div className="panel-sunken p-3.5">
            <div className="flex items-center justify-between gap-3">
              <h4 className="panel-title text-[13px]">
                <span className="panel-icon h-[22px] w-[22px]"><Gauge className="h-[13px] w-[13px]" aria-hidden="true" /></span>
                Crypto agility
              </h4>
              <span className="mono text-sm font-semibold tabular">
                {artefact.agility_score}
                <span className="text-[11px] font-normal text-faint">
                  {' '}/ 100 · {artefact.agility_band}
                </span>
              </span>
            </div>
            <p className="mt-1.5 text-[13px] leading-relaxed text-muted">
              {artefact.agility_summary}
            </p>
            {artefact.agility_factors && (
              <ul className="mt-2.5 space-y-1.5">
                {Object.entries(artefact.agility_factors).map(([name, f]) => (
                  <li key={name} className="text-xs leading-relaxed">
                    <span className="font-semibold capitalize">
                      {name.replace(/_/g, ' ')}
                    </span>
                    <span className="mono text-faint"> {f.score}/100</span>
                    <span className="text-muted"> — {f.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {artefact.occurrences?.length > 0 && (
          <div>
            <h4 className="mb-2 text-[13px] font-semibold">
              Occurrences ({artefact.occurrences.length})
            </h4>
            <ul className="divide-rows panel-sunken max-h-56 overflow-y-auto">
              {artefact.occurrences.map((o, i) => (
                <li key={`${o.location}-${o.line_number}-${i}`} className="px-3 py-2">
                  <div className="mono text-[11px] text-muted">
                    {o.location}
                    {o.line_number ? `:${o.line_number}` : ''}
                  </div>
                  {o.snippet && (
                    <pre className="mono mt-1.5 overflow-x-auto text-[11px]" style={{ color: 'var(--accent)' }}>
                      <code>{o.snippet}</code>
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {rec && (
          <div
            className="rounded-[9px] p-4"
            style={{ background: 'var(--low-fill)', border: '1px solid var(--low-line)' }}
          >
            <h4 className="text-[13px] font-semibold" style={{ color: 'var(--low)' }}>
              Recommended migration
            </h4>
            <p className="mt-1 text-sm font-semibold">{rec.recommended_standard}</p>
            {rec.hybrid_recommendation && (
              <p className="mt-1 text-xs text-muted">Hybrid: {rec.hybrid_recommendation}</p>
            )}
            <p className="mt-1.5 text-xs text-faint">
              {rec.migration_urgency} · {rec.latency_impact}
            </p>
          </div>
        )}
      </div>
    </Modal>
  );
}
