/**
 * Shared UI primitives.
 *
 * Notably DataTable, which paginates. The inventory, the Mosca worksheet and
 * the migration list all used to render every artefact unconditionally — a real
 * scan produced thousands of rows and locked up the WebView.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Info,
  X,
} from 'lucide-react';
import { formatNumber } from '../../lib/risk';

/* ---------------------------------------------------------------- Metric card */

export function MetricCard({ label, value, unit, hint, accent, icon: Icon, onClick }) {
  const Wrapper = onClick ? 'button' : 'div';
  return (
    <Wrapper
      onClick={onClick}
      className={`panel flex flex-col p-4 text-left ${
        onClick ? 'panel-interactive text-left' : ''
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="eyebrow">{label}</span>
        {Icon && (
          <Icon
            className="h-3.5 w-3.5 shrink-0"
            style={{ color: accent || 'var(--ink-faint)' }}
            aria-hidden="true"
          />
        )}
      </div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <span
          className="display text-[26px] leading-none tabular"
          style={{ color: accent || 'var(--ink)' }}
        >
          {typeof value === 'number' ? formatNumber(value) : value}
        </span>
        {unit && <span className="text-[12px] text-muted">{unit}</span>}
      </div>
      {hint && <p className="mt-2 text-[11.5px] leading-snug text-faint">{hint}</p>}
    </Wrapper>
  );
}

/* ------------------------------------------------------------------- Empty state */

export function EmptyState({ icon: Icon, title, body, action }) {
  return (
    <div className="panel flex flex-col items-center px-6 py-16 text-center">
      {Icon && (
        // A ring rather than a filled square: an empty state is an absence, and
        // a heavy block in the middle of one reads as a thing that failed to
        // load rather than a thing that is not there yet.
        <div
          className="mb-5 flex h-14 w-14 items-center justify-center rounded-full"
          style={{
            background: 'var(--surface-sunken)',
            boxShadow: '0 0 0 6px var(--canvas)',
          }}
        >
          <Icon className="h-6 w-6" style={{ color: 'var(--ink-faint)' }} aria-hidden="true" />
        </div>
      )}
      <h3 className="t-head">{title}</h3>
      {body && <p className="mt-2 max-w-sm text-[13px] leading-relaxed text-muted">{body}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ Inline alert */

export function Alert({ tone = 'info', title, children, onDismiss }) {
  // Every tone carries a glyph. A status message with no mark reads as body
  // copy that happens to be tinted, and tone alone is not an accessible signal
  // — the icon is what carries the meaning to anyone who cannot separate the
  // fill colours.
  const tones = {
    info: { border: 'var(--line)', bg: 'var(--surface-sunken)', color: 'var(--ink-soft)', Icon: Info },
    warn: { border: 'var(--medium-line)', bg: 'var(--medium-fill)', color: 'var(--medium)', Icon: AlertTriangle },
    error: { border: 'var(--critical-line)', bg: 'var(--critical-fill)', color: 'var(--critical)', Icon: AlertOctagon },
    success: { border: 'var(--low-line)', bg: 'var(--low-fill)', color: 'var(--low)', Icon: CheckCircle2 },
  };
  const t = tones[tone] || tones.info;
  const ToneIcon = t.Icon;

  return (
    <div
      className="flex items-start gap-3 rounded-[9px] border p-3.5 text-[13px]"
      style={{ borderColor: t.border, background: t.bg }}
      role={tone === 'error' ? 'alert' : 'status'}
    >
      <ToneIcon
        className="mt-[1px] h-4 w-4 shrink-0"
        style={{ color: t.color }}
        aria-hidden="true"
      />
      <div className="min-w-0 flex-1">
        {title && (
          <p className="font-semibold" style={{ color: t.color }}>
            {title}
          </p>
        )}
        <div className={`${title ? 'mt-1' : ''} text-[12.5px] leading-relaxed text-soft`}>
          {children}
        </div>
      </div>
      {onDismiss && (
        <button onClick={onDismiss} className="btn-ghost -m-1 rounded p-1" aria-label="Dismiss">
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------------ Modal */

export function Modal({ open, onClose, title, subtitle, children, footer, width = 'max-w-2xl' }) {
  const panelRef = useRef(null);

  // Escape closes, focus moves into the dialog, and background scroll is locked
  // while it is open.
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    panelRef.current?.focus();
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="animate-fade-in fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      style={{ background: 'rgba(19, 24, 38, 0.32)', backdropFilter: 'blur(2px)' }}
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`animate-slide-up my-auto w-full ${width} rounded-lg bg-surface outline-none`}
        style={{ boxShadow: 'var(--shadow-pop)' }}
      >
        <div className="panel-head">
          <div className="min-w-0">
            <h2 className="panel-title truncate">{title}</h2>
            {subtitle && <p className="panel-sub">{subtitle}</p>}
          </div>
          <button onClick={onClose} className="btn btn-ghost -mr-2 -mt-1 px-2" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[min(70vh,640px)] overflow-y-auto p-5">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 rounded-b-lg border-t border-line bg-surface-sunken px-5 py-3">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------- DataTable */

/**
 * A sortable, paginated table.
 *
 * Pagination is not a nicety here: rendering a full inventory unconditionally is
 * what made the previous CBOM view unusable on any real codebase.
 */
export function DataTable({
  columns,
  rows,
  rowKey,
  onRowClick,
  pageSize = 25,
  initialSort,
  emptyMessage = 'Nothing matches the current filters.',
  maxHeight = '62vh',
}) {
  const [sort, setSort] = useState(initialSort || null);
  const [page, setPage] = useState(0);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const av = col.sortValue(a);
      const bv = col.sortValue(b);
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      return av > bv ? dir : -dir;
    });
  }, [rows, sort, columns]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const visible = sorted.slice(safePage * pageSize, safePage * pageSize + pageSize);

  // Filtering down to fewer pages must not leave the view stranded on an empty one.
  useEffect(() => {
    if (page > pageCount - 1) setPage(0);
  }, [pageCount, page]);

  const toggleSort = (key) => {
    setSort((prev) =>
      prev?.key === key
        ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: 'desc' }
    );
    setPage(0);
  };

  return (
    <div>
      <div className="table-scroll" style={{ maxHeight }}>
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((col) => (
                // The header takes the column's own alignment. Only the cells
                // carried col.className, so a right-aligned numeric column had
                // a left-aligned heading sitting over it — the label and the
                // figures it described were at opposite ends of the column.
                <th
                  key={col.key}
                  className={col.className}
                  style={col.width ? { width: col.width } : undefined}
                >
                  {col.sortValue ? (
                    <button
                      className={`th-sort${
                        col.className?.includes('text-right') ? ' th-sort-right' : ''
                      }`}
                      onClick={() => toggleSort(col.key)}
                      aria-label={`Sort by ${col.header}`}
                    >
                      {col.header}
                      {sort?.key === col.key &&
                        (sort.dir === 'asc' ? (
                          <ArrowUp className="h-3 w-3" />
                        ) : (
                          <ArrowDown className="h-3 w-3" />
                        ))}
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="py-12 text-center text-[13px] text-faint">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              visible.map((row) => (
                <tr
                  key={rowKey(row)}
                  className={onRowClick ? 'is-clickable' : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            onRowClick(row);
                          }
                        }
                      : undefined
                  }
                >
                  {columns.map((col) => (
                    <td key={col.key} className={col.className}>
                      {col.render(row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {sorted.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-2.5 text-[12px]">
          <span className="tabular text-faint">
            {safePage * pageSize + 1}–{Math.min(sorted.length, (safePage + 1) * pageSize)} of{' '}
            {formatNumber(sorted.length)}
          </span>
          {pageCount > 1 && (
            <div className="flex items-center gap-1">
              <button
                className="btn btn-ghost px-2"
                style={{ minHeight: 30 }}
                disabled={safePage === 0}
                onClick={() => setPage(safePage - 1)}
                aria-label="Previous page"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              <span className="px-1 tabular text-muted">
                {safePage + 1} / {pageCount}
              </span>
              <button
                className="btn btn-ghost px-2"
                style={{ minHeight: 30 }}
                disabled={safePage >= pageCount - 1}
                onClick={() => setPage(safePage + 1)}
                aria-label="Next page"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Segmented */

export function Segmented({ options, value, onChange, ariaLabel }) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className="inline-flex gap-0.5 rounded-[8px] bg-surface-sunken p-[3px]"
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(opt.value)}
            className="flex items-center gap-1.5 rounded-[6px] px-3 text-[12.5px] transition-all"
            style={{
              minHeight: 30,
              fontWeight: active ? 550 : 450,
              background: active ? 'var(--surface)' : 'transparent',
              color: active ? 'var(--ink)' : 'var(--ink-muted)',
              boxShadow: active ? 'var(--shadow-xs)' : 'none',
            }}
          >
            {opt.icon && <opt.icon className="h-3.5 w-3.5" aria-hidden="true" />}
            {opt.label}
            {opt.count !== undefined && <span className="tabular text-faint">{opt.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------ Definition list */

export function DefList({ items }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(({ term, value, mono }) => (
        <div key={term}>
          <dt className="eyebrow">{term}</dt>
          <dd className={`mt-1 text-[13px] text-soft ${mono ? 'mono break-all' : ''}`}>
            {value ?? '—'}
          </dd>
        </div>
      ))}
    </dl>
  );
}
