/**
 * Hand-rolled SVG charts.
 *
 * The app is packaged offline, so a charting library would add several hundred
 * kilobytes for four simple marks. Each chart carries a legend with values and
 * a hover readout, and none relies on colour alone to convey meaning.
 */
import React, { useId, useMemo, useState } from 'react';
import { formatNumber } from '../../lib/risk';

/**
 * Proportional stacked bar — the share of an inventory in each band.
 * Segments carry their own count when wide enough, so the reading does not
 * depend on matching colours to a legend.
 */
export function StackedShareBar({ segments, total, height = 10 }) {
  const [hovered, setHovered] = useState(null);
  const safeTotal = total || segments.reduce((s, x) => s + x.value, 0) || 1;
  const visible = segments.filter((s) => s.value > 0);

  return (
    <div>
      <div
        className="flex w-full gap-0.5 overflow-hidden"
        style={{ height }}
        role="img"
        aria-label={visible.map((s) => `${s.label}: ${s.value} of ${safeTotal}`).join('; ')}
      >
        {visible.map((seg, i) => {
          const pct = (seg.value / safeTotal) * 100;
          return (
            <div
              key={seg.label}
              className="transition-opacity duration-200"
              style={{
                width: `${pct}%`,
                background: seg.color,
                opacity: hovered && hovered !== seg.label ? 0.3 : 1,
                borderRadius:
                  visible.length === 1
                    ? 999
                    : i === 0
                    ? '999px 2px 2px 999px'
                    : i === visible.length - 1
                    ? '2px 999px 999px 2px'
                    : 2,
              }}
              onMouseEnter={() => setHovered(seg.label)}
              onMouseLeave={() => setHovered(null)}
              title={`${seg.label}: ${seg.value} (${pct.toFixed(1)}%)`}
            />
          );
        })}
      </div>

      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
        {segments.map((seg) => (
          <div
            key={seg.label}
            className="flex items-baseline gap-1.5 text-[12px] transition-opacity"
            style={{ opacity: hovered && hovered !== seg.label ? 0.45 : 1 }}
            onMouseEnter={() => setHovered(seg.label)}
            onMouseLeave={() => setHovered(null)}
          >
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 translate-y-px rounded-full"
              style={{ background: seg.color }}
            />
            <span className="text-muted">{seg.label}</span>
            <span className="font-semibold tabular">{seg.value}</span>
            <span className="tabular text-faint">
              {((seg.value / safeTotal) * 100).toFixed(0)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Horizontal bars for ranked categorical counts — the right mark for comparing
 * magnitudes across labelled categories, and it stays readable with long
 * algorithm names that a pie would crowd out.
 */
export function RankedBars({ items, valueLabel = 'assets', maxRows = 8 }) {
  const rows = items.slice(0, maxRows);
  const max = Math.max(...rows.map((r) => r.value), 1);

  if (rows.length === 0) {
    return <p className="py-6 text-center text-[13px] text-faint">No data to chart.</p>;
  }

  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.label} className="group">
          <div className="mb-1.5 flex items-baseline justify-between gap-3 text-[12.5px]">
            <span className="truncate text-soft" title={row.label}>
              {row.label}
            </span>
            <span className="shrink-0 tabular text-faint">
              {formatNumber(row.value)}{' '}
              {row.value === 1 && valueLabel.endsWith('s') ? valueLabel.slice(0, -1) : valueLabel}
            </span>
          </div>
          <div className="h-[5px] w-full overflow-hidden rounded-full bg-surface-sunken">
            <div
              className="h-full rounded-full transition-[width] duration-700 ease-out"
              style={{
                width: `${(row.value / max) * 100}%`,
                background: row.color || 'var(--accent)',
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Readiness dial. A single KPI with emphasis — the one case where a gauge beats
 * a bullet chart. The number is the reading; the arc reinforces it.
 */
export function ReadinessDial({ score, label, color, labelColor, size = 116 }) {
  const stroke = 7;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const sweep = 0.75; // three-quarter arc, opening at the bottom
  const dash = circumference * sweep;
  const filled = (dash * Math.max(0, Math.min(100, score))) / 100;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          style={{ transform: 'rotate(135deg)' }}
          role="img"
          aria-label={`Quantum readiness ${score} out of 100 — ${label}`}
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--surface-sunken)"
            strokeWidth={stroke}
            strokeDasharray={`${dash} ${circumference}`}
            strokeLinecap="round"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={`${filled} ${circumference}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 800ms cubic-bezier(0.16,1,0.3,1)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="display text-[30px] leading-none" style={{ color: 'var(--ink)' }}>
            {score}
          </span>
          <span className="mt-1 text-[10.5px] text-faint">out of 100</span>
        </div>
      </div>
      <span
        className="mt-1.5 text-center text-[12px] font-semibold"
        style={{ color: labelColor || color }}
      >
        {label}
      </span>
    </div>
  );
}

/**
 * Risk against the CRQC horizon.
 *
 * Mosca's inequality is a statement about a timeline, but the app can only show
 * one Z at a time — this is where you see the point at which the estate tips
 * over. Each series is the count of assets in a band at that horizon.
 */
export function HorizonChart({ series, horizons, currentZ, onPickZ }) {
  const gradId = useId().replace(/:/g, '');
  const [hoverIndex, setHoverIndex] = useState(null);

  const width = 660;
  const height = 210;
  const pad = { top: 14, right: 14, bottom: 30, left: 30 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const maxY = useMemo(() => Math.max(1, ...series.flatMap((s) => s.values)), [series]);

  const x = (i) =>
    pad.left + (horizons.length === 1 ? plotW / 2 : (i / (horizons.length - 1)) * plotW);
  const y = (v) => pad.top + plotH - (v / maxY) * plotH;

  // Monotone-ish smoothing: a gentle curve reads better than hard elbows and
  // does not misrepresent counts at the sampled horizons.
  const smooth = (values) => {
    const pts = values.map((v, i) => [x(i), y(v)]);
    if (pts.length < 2) return '';
    let d = `M${pts[0][0]},${pts[0][1]}`;
    for (let i = 0; i < pts.length - 1; i += 1) {
      const [x0, y0] = pts[i];
      const [x1, y1] = pts[i + 1];
      const cx = (x0 + x1) / 2;
      d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
    }
    return d;
  };

  const areaPath = (values) =>
    `${smooth(values)} L${x(values.length - 1)},${pad.top + plotH} L${x(0)},${pad.top + plotH} Z`;

  const zIndex = horizons.reduce(
    (best, h, i) => (Math.abs(h - currentZ) < Math.abs(horizons[best] - currentZ) ? i : best),
    0
  );

  const ticks = [0, Math.round(maxY / 2), maxY];

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ height: 'auto' }}
        role="img"
        aria-label="Asset counts by risk band across candidate CRQC horizons"
        onMouseLeave={() => setHoverIndex(null)}
      >
        <defs>
          {series.map((s, i) => (
            <linearGradient key={s.label} id={`${gradId}-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity="0.16" />
              <stop offset="100%" stopColor={s.color} stopOpacity="0.01" />
            </linearGradient>
          ))}
        </defs>

        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={pad.left}
              x2={width - pad.right}
              y1={y(t)}
              y2={y(t)}
              stroke="var(--line)"
              strokeDasharray={t === 0 ? undefined : '3 4'}
            />
            <text
              x={pad.left - 8}
              y={y(t) + 3.5}
              textAnchor="end"
              fontSize="10"
              fill="var(--ink-faint)"
            >
              {t}
            </text>
          </g>
        ))}

        {series.map((s, i) => (
          <g key={s.label}>
            <path d={areaPath(s.values)} fill={`url(#${gradId}-${i})`} />
            <path
              d={smooth(s.values)}
              fill="none"
              stroke={s.color}
              strokeWidth="1.75"
              strokeLinecap="round"
            />
          </g>
        ))}

        {/* The committed horizon */}
        <line
          x1={x(zIndex)}
          x2={x(zIndex)}
          y1={pad.top - 2}
          y2={pad.top + plotH}
          stroke="var(--ink-faint)"
          strokeWidth="1"
          strokeDasharray="3 3"
        />
        <text
          x={x(zIndex)}
          y={pad.top - 5}
          textAnchor="middle"
          fontSize="10"
          fontWeight="600"
          fill="var(--ink-muted)"
        >
          Z = {currentZ}
        </text>

        {horizons.map((h, i) => (
          <rect
            key={h}
            x={x(i) - plotW / horizons.length / 2}
            y={pad.top}
            width={plotW / horizons.length}
            height={plotH}
            fill="transparent"
            style={{ cursor: onPickZ ? 'pointer' : 'default' }}
            onMouseEnter={() => setHoverIndex(i)}
            onClick={() => onPickZ && onPickZ(h)}
          />
        ))}

        {hoverIndex !== null && (
          <g>
            <line
              x1={x(hoverIndex)}
              x2={x(hoverIndex)}
              y1={pad.top}
              y2={pad.top + plotH}
              stroke="var(--line-strong)"
            />
            {series.map((s) => (
              <circle
                key={s.label}
                cx={x(hoverIndex)}
                cy={y(s.values[hoverIndex])}
                r="3.5"
                fill="var(--surface)"
                stroke={s.color}
                strokeWidth="2"
              />
            ))}
          </g>
        )}

        {horizons.map((h, i) => (
          <text
            key={h}
            x={x(i)}
            y={height - 9}
            textAnchor="middle"
            fontSize="10"
            fill={i === hoverIndex ? 'var(--ink)' : 'var(--ink-faint)'}
            fontWeight={i === hoverIndex ? 600 : 400}
          >
            {h}y
          </text>
        ))}
      </svg>

      <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1.5">
        {series.map((s) => (
          <div key={s.label} className="flex items-baseline gap-1.5 text-[12px]">
            <span
              aria-hidden="true"
              className="h-[3px] w-3.5 translate-y-[-2px] rounded-full"
              style={{ background: s.color }}
            />
            <span className="text-muted">{s.label}</span>
            {hoverIndex !== null && (
              <span className="font-semibold tabular">{s.values[hoverIndex]}</span>
            )}
          </div>
        ))}
        <span className="ml-auto text-[11.5px] text-faint">
          {hoverIndex !== null
            ? `At Z = ${horizons[hoverIndex]} years`
            : 'Hover a horizon to read values'}
        </span>
      </div>
    </div>
  );
}
