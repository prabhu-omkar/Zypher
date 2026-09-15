import React, { useMemo } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  FileSearch,
  Info,
  Layers,
  ShieldAlert,
  CalendarClock,
  Timer,
} from 'lucide-react';
import { HorizonChart, RankedBars, ReadinessDial, StackedShareBar } from './charts/Charts';
import { Alert, DataTable, EmptyState, MetricCard } from './ui/Primitives';
import { countAdvisories } from '../lib/vulnerabilities';
import {
  RISK_ORDER,
  TARGET_LABELS,
  fileName,
  formatNumber,
  readinessMeta,
  riskMeta,
  vulnMeta,
} from '../lib/risk';

// Display names for the data-sensitivity profile a scan was run under. The
// authoritative list and its retention figures live in the backend and are
// served from /api/config/sensitivity-profiles; these are labels only.
const PROFILE_LABELS = {
  session: 'Session / ephemeral',
  general_business: 'General business',
  financial: 'Financial records',
  personal_data: 'Personal data',
  health: 'Health records',
  government: 'Government / classified',
  national_security: 'National security',
};

export default function Dashboard({ scanResult, onNavigate }) {
  if (!scanResult) {
    return (
      <EmptyState
        icon={FileSearch}
        title="No scan loaded"
        body="Scan a directory, a Git repository or an uploaded archive to build a cryptographic inventory and assess its quantum risk."
        action={
          <button className="btn btn-primary btn-lg" onClick={() => onNavigate('scan')}>
            Run a scan
            <ArrowRight className="h-4 w-4" />
          </button>
        }
      />
    );
  }

  const { summary, artefacts, risk_assessments: risks, recommendations } = scanResult;
  const readiness = readinessMeta(summary.quantum_readiness_score);

  const riskSegments = RISK_ORDER.map((name) => ({
    label: name,
    value: summary.risk_distribution[name] || 0,
    color: riskMeta(name).mark,
  }));

  const vulnBars = useMemo(() => {
    const order = [
      'fully_broken',
      'classically_broken',
      'degraded',
      'unknown',
      'quantum_safe',
      'hybrid_protected',
    ];
    return order
      .map((key) => ({
        label: vulnMeta(key).label,
        value: summary.vulnerability_distribution[key] || 0,
        color: vulnMeta(key).mark,
      }))
      .filter((r) => r.value > 0);
  }, [summary.vulnerability_distribution]);

  const familyBars = useMemo(() => {
    const counts = new Map();
    for (const a of artefacts) {
      counts.set(a.algorithm_family, (counts.get(a.algorithm_family) || 0) + 1);
    }
    return [...counts.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }, [artefacts]);

  const surfaceBars = useMemo(() => {
    const counts = new Map();
    for (const a of artefacts) {
      counts.set(a.target_type, (counts.get(a.target_type) || 0) + 1);
    }
    return [...counts.entries()]
      .map(([key, value]) => ({ label: TARGET_LABELS[key] || key, value }))
      .sort((a, b) => b.value - a.value);
  }, [artefacts]);

  /**
   * Risk across candidate horizons, computed locally from each artefact's own
   * X and Y. Mosca's inequality is a claim about a timeline, but the UI could
   * only ever show one Z, so you could not see where the estate tips over.
   */
  const horizonData = useMemo(() => {
    const horizons = [2, 4, 6, 8, 10, 12, 15, 20];
    const bands = { Critical: [], High: [], Medium: [], Low: [] };

    for (const z of horizons) {
      const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      for (const art of artefacts) {
        const xPlusY = art.data_shelf_life_years + art.migration_time_years;
        const margin = z - xPlusY;
        const isLegacyBroken = art.algorithm_class === 'legacy_broken';
        const isQuantumSafe =
          art.algorithm_class === 'post_quantum' || art.algorithm_class === 'hybrid';

        // Mirrors the engine's banding: timing sets the base band, and
        // business consequence sharpens it by one step but never invents
        // urgency where there is slack. This is the Mosca model only — the
        // regulatory deadline can bind earlier for an individual asset, so the
        // curve is an approximation of where the estate tips, not a
        // replacement for the assessed bands in the table below.
        let band;
        if (isQuantumSafe) band = 'Low';
        else if (isLegacyBroken) band = 'Critical';
        else {
          if (margin < 1) band = 'High';
          else if (margin < 3) band = 'Medium';
          else band = 'Low';

          const consequential =
            art.business_criticality === 'Critical' || art.business_criticality === 'High';
          if (consequential && band !== 'Low') {
            band = { Medium: 'High', High: 'Critical' }[band] || band;
          }
        }
        counts[band] += 1;
      }
      for (const k of RISK_ORDER) bands[k].push(counts[k]);
    }

    return {
      horizons,
      series: RISK_ORDER.map((name) => ({
        label: name,
        color: riskMeta(name).mark,
        values: bands[name],
      })),
    };
  }, [artefacts]);

  const priorityRows = useMemo(
    () =>
      artefacts
        .map((a) => ({ art: a, risk: risks[a.id], rec: recommendations[a.id] }))
        .filter((r) => r.risk && (r.risk.risk_category === 'Critical' || r.risk.risk_category === 'High'))
        .sort((a, b) => {
          const rank = { Critical: 0, High: 1 };
          const byBand = rank[a.risk.risk_category] - rank[b.risk.risk_category];
          if (byBand !== 0) return byBand;
          return b.art.occurrence_count - a.art.occurrence_count;
        })
        .slice(0, 10),
    [artefacts, risks, recommendations]
  );

  // A note is worth showing only if it says something was missed. Anything
  // that merely restates a count the cards already carry is noise.
  const coverageWarnings = useMemo(
    () =>
      (summary.coverage_notes || []).filter(
        (n) => !/deduplicated|combined:|entries/i.test(n)
      ),
    [summary.coverage_notes]
  );

  const criticalCount = summary.risk_distribution.Critical || 0;
  const highCount = summary.risk_distribution.High || 0;

  return (
    <div className="animate-fade-in space-y-5">
      {/* Scan context */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="t-title truncate">{summary.target_name}</h1>
          <p className="mt-1 text-[13px] text-muted">
            <span className="mono">{summary.scan_id}</span>
            {' · '}
            {new Date(summary.created_at).toLocaleString()}
            {summary.files_scanned > 0 && <> · {formatNumber(summary.files_scanned)} files read</>}
            {' · assessed at '}
            <span className="font-semibold" style={{ color: 'var(--ink)' }}>
              Z = {summary.mosca_global_z} years
            </span>
            {summary.crqc_estimated_on && (
              <> (a CRQC by {summary.crqc_estimated_on})</>
            )}
            {summary.sensitivity_profile && (
              <> · {PROFILE_LABELS[summary.sensitivity_profile] || summary.sensitivity_profile}</>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-secondary" onClick={() => onNavigate('inventory')}>
            <Layers className="h-4 w-4" />
            Inventory
          </button>
          <button className="btn btn-primary" onClick={() => onNavigate('reports')}>
            Export CBOM
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Known-vulnerability status is always stated, so "none shown" is never
          mistaken for "checked and clean". */}
      {summary.vulnerability_lookup && (
        <VulnerabilityBanner
          record={summary.vulnerability_lookup}
          found={summary.total_known_vulnerabilities || countAdvisories(artefacts)}
          onNavigate={onNavigate}
        />
      )}

      {/* The schedule, not just the bands. A risk category tells you how bad
          something is; these tell you when you have to act on it.

          Rendered with the same MetricCard as every other figure on this page.
          They were hand-built rows of large monospace numerals, which read as
          terminal output sitting above a set of properly set cards — the
          inconsistency was more noticeable than either style on its own. */}
      {(summary.overdue_artefacts > 0 || summary.earliest_start_required) && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {summary.overdue_artefacts > 0 && (
            <MetricCard
              label="Past their start date"
              value={summary.overdue_artefacts}
              unit={summary.overdue_artefacts === 1 ? 'asset' : 'assets'}
              accent="var(--critical)"
              icon={AlertTriangle}
              hint="Start date already passed."
            />
          )}
          {summary.earliest_start_required && (
            <MetricCard
              label="Next migration must begin"
              value={summary.earliest_start_required}
              icon={CalendarClock}
              hint="Earliest remaining start date."
            />
          )}
          {summary.longest_migration_years > 0 && (
            <MetricCard
              label="Longest single migration"
              value={summary.longest_migration_years}
              unit="years"
              icon={Timer}
              hint="Critical path for the estate."
            />
          )}
        </div>
      )}

      {/* Crypto agility (NIST CSWP 39): how replaceable this estate's
          cryptography is, independent of which algorithm it happens to use. */}
      {summary.agility?.average_score != null && (
        <div className="panel p-4">
          <div className="flex flex-wrap items-start gap-x-8 gap-y-4">
            <div>
              <span className="eyebrow">Crypto agility</span>
              <div className="mt-2 flex items-baseline gap-1.5">
                <span className="display text-[26px] leading-none">
                  {summary.agility.average_score}
                </span>
                <span className="text-[12px] text-faint">/ 100</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 self-center">
              {['Agile', 'Moderate', 'Rigid'].map((band) => {
                const count = summary.agility.band_distribution?.[band];
                if (!count) return null;
                const colour =
                  band === 'Agile' ? 'var(--low-mark)'
                    : band === 'Rigid' ? 'var(--critical-mark)'
                      : 'var(--medium-mark)';
                return (
                  <span key={band} className="chip">
                    <span className="dot" style={{ background: colour }} aria-hidden="true" />
                    {count} {band}
                  </span>
                );
              })}
            </div>

            <p className="min-w-[240px] flex-1 self-center text-[12.5px] leading-relaxed text-muted">
              {summary.agility.rigid_count > 0 ? (
                <>
                  {summary.agility.rigid_count} asset
                  {summary.agility.rigid_count === 1 ? '' : 's'} cannot be changed
                  without a vendor or a hardware refresh. Those set the floor on any
                  migration, whatever algorithm it targets.
                </>
              ) : (
                <>
                  Nothing in this inventory is locked to a vendor or to hardware, so
                  an algorithm change here is an engineering task rather than a
                  procurement one.
                </>
              )}
            </p>
          </div>
        </div>
      )}

      {/* Coverage is stated when something was *not* covered — a detector that
          could not load, a traversal cap that was hit. Purely descriptive notes
          ("55 entries deduplicated to 40 assets") are dropped: the counts they
          restate are already on the cards below. Suppressing the warnings too
          would let a partial scan read as a clean one. */}
      {coverageWarnings.length > 0 && (
        <Alert tone="warn" title="Scan coverage">
          <ul className="list-inside list-disc space-y-0.5">
            {coverageWarnings.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </Alert>
      )}

      {/* Headline */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(320px,auto),1fr]">
        <div className="panel flex items-center gap-5 p-4">
          <ReadinessDial
            score={summary.quantum_readiness_score}
            label={readiness.label}
            color={readiness.mark}
            labelColor={readiness.color}
            size={112}
          />
          <div className="max-w-[220px]">
            <h2 className="text-sm font-semibold">Quantum readiness</h2>
          </div>
        </div>

        {/* 2×2 so the block matches the dial's height instead of stretching four
            short cards into tall ones with dead space at the bottom. */}
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          <MetricCard
            label="Distinct assets"
            value={summary.total_artefacts}
            hint={
              summary.total_occurrences > summary.total_artefacts
                ? `across ${formatNumber(summary.total_occurrences)} occurrences in code`
                : 'unique cryptographic decisions'
            }
            icon={Boxes}
          />
          <MetricCard
            label="Critical"
            value={criticalCount}
            accent={criticalCount > 0 ? 'var(--critical)' : undefined}
            hint="Broken cryptography, or exposed sensitive systems"
            icon={ShieldAlert}
          />
          <MetricCard
            label="High"
            value={highCount}
            accent={highCount > 0 ? 'var(--high)' : undefined}
            hint="X + Y exceeds the CRQC horizon"
            icon={AlertTriangle}
          />
          <MetricCard
            label="Quantum-safe"
            value={
              (summary.vulnerability_distribution.quantum_safe || 0) +
              (summary.vulnerability_distribution.hybrid_protected || 0)
            }
            accent="var(--low)"
            hint="No known quantum advantage"
          />
        </div>
      </div>

      {/* Risk split + horizon */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="panel xl:col-span-3">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Risk across the quantum horizon</h2>
              <p className="panel-sub">
                Click a horizon to explore it.
              </p>
            </div>
          </div>
          <div className="p-4">
            <HorizonChart
              series={horizonData.series}
              horizons={horizonData.horizons}
              currentZ={summary.mosca_global_z}
              onPickZ={() => onNavigate('inventory')}
            />
          </div>
        </div>

        <div className="panel xl:col-span-2">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">Risk distribution</h2>
              <p className="panel-sub">At Z = {summary.mosca_global_z} years</p>
            </div>
          </div>
          <div className="space-y-5 p-4">
            <StackedShareBar segments={riskSegments} total={summary.total_artefacts} />
            <div className="border-t border-line pt-4">
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">
                What breaks these
              </h3>
              <RankedBars items={vulnBars} />
            </div>
          </div>
        </div>
      </div>

      {/* Composition */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="panel">
          <div className="panel-head">
            <h2 className="panel-title">Algorithms in use</h2>
          </div>
          <div className="p-4">
            <RankedBars
              items={familyBars.map((f) => ({ ...f, color: 'var(--series-a)' }))}
              maxRows={7}
            />
          </div>
        </div>
        <div className="panel">
          <div className="panel-head">
            <h2 className="panel-title">Where they were found</h2>
            <span className="text-xs text-faint">Discovery surface</span>
          </div>
          <div className="p-4">
            <RankedBars
              items={surfaceBars.map((s) => ({ ...s, color: 'var(--series-b)' }))}
              maxRows={5}
            />
          </div>
        </div>
      </div>

      {/* Priorities */}
      <div className="panel">
        <div className="panel-head">
          <div>
            <h2 className="panel-title">Migration priorities</h2>
            <p className="panel-sub">
              Highest risk first.
            </p>
          </div>
          <button className="btn btn-ghost" onClick={() => onNavigate('inventory')}>
            View all {formatNumber(summary.total_artefacts)}
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>

        {priorityRows.length === 0 ? (
          <div className="flex items-center gap-2.5 px-5 py-8 text-sm text-muted">
            <Info className="h-4 w-4 shrink-0" style={{ color: 'var(--low)' }} />
            Nothing is Critical or High at Z = {summary.mosca_global_z} years. Shorten the horizon in
            the Inventory to stress-test that result.
          </div>
        ) : (
          <DataTable
            rows={priorityRows}
            rowKey={(r) => r.art.id}
            pageSize={10}
            maxHeight="none"
            columns={[
              {
                key: 'asset',
                header: 'Asset',
                render: (r) => (
                  <div>
                    <div className="font-medium">{r.art.name}</div>
                    <div className="mt-0.5 text-[11px] text-faint">
                      {vulnMeta(r.art.quantum_vulnerability).label}
                    </div>
                  </div>
                ),
              },
              {
                key: 'where',
                header: 'Location',
                render: (r) => (
                  <div className="mono max-w-[220px] truncate text-[11px] text-muted" title={r.art.location}>
                    {fileName(r.art.location)}
                    {r.art.line_number ? `:${r.art.line_number}` : ''}
                    {r.art.occurrence_count > 1 && (
                      <span className="text-faint"> +{r.art.occurrence_count - 1}</span>
                    )}
                  </div>
                ),
              },
              {
                key: 'mosca',
                header: 'X + Y vs Z',
                render: (r) => (
                  <span className="mono text-[11px] tabular">
                    <span style={{ color: r.risk.is_at_risk ? 'var(--critical)' : 'var(--low)' }}>
                      {r.risk.x_plus_y}y
                    </span>
                    <span className="text-faint"> {r.risk.is_at_risk ? '>' : '≤'} {r.risk.threat_timeline_z}y</span>
                  </span>
                ),
              },
              {
                key: 'risk',
                header: 'Risk',
                render: (r) => (
                  <span className={riskMeta(r.risk.risk_category).badge}>
                    <span aria-hidden="true">{riskMeta(r.risk.risk_category).glyph}</span>
                    {r.risk.risk_category}
                  </span>
                ),
              },
              {
                key: 'target',
                header: 'Migrate to',
                render: (r) => (
                  <span className="text-[12px]" style={{ color: 'var(--low)' }}>
                    {r.rec?.recommended_standard || '—'}
                  </span>
                ),
              },
            ]}
          />
        )}
      </div>
    </div>
  );
}


/**
 * Advisory status for the loaded scan.
 *
 * Rendered whether or not the lookup ran: an inventory that shows nothing
 * because the check was disabled looks identical to one that is genuinely
 * clean, and the difference matters.
 */
function VulnerabilityBanner({ record, found, onNavigate }) {
  if (!record.enabled) {
    return (
      <Alert tone="info" title="Known vulnerabilities were not checked">
        Dependency advisories are looked up from OSV, which needs an internet
        connection, so the check is off by default. Enable it in Settings to see
        published CVEs for the packages in this inventory.
      </Alert>
    );
  }

  if (!record.available) {
    return (
      <Alert tone="warn" title="Could not check known vulnerabilities">
        {record.error || 'The advisory service was unreachable.'} The
        cryptographic inventory below is unaffected.
      </Alert>
    );
  }

  if (found === 0) {
    return (
      <Alert tone="success" title="No known vulnerabilities">
        {record.packages_checked} package(s) checked against {record.source}. This
        covers published advisories only — it says nothing about quantum risk.
      </Alert>
    );
  }

  return (
    <Alert tone="error" title={`${found} known vulnerabilities in ${record.packages_checked} package(s)`}>
      Published advisories from {record.source}, separate from the quantum
      assessment below.{' '}
      <button
        className="underline"
        style={{ color: 'var(--accent)' }}
        onClick={() => onNavigate('inventory')}
      >
        Review them in the Inventory
      </button>
      .
    </Alert>
  );
}
