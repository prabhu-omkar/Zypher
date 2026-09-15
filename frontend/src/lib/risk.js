/**
 * The single source of truth for how risk and quantum status are named,
 * coloured and explained in the UI.
 *
 * These mappings used to be re-declared inline in every component, so the same
 * status was described differently on the dashboard, in the inventory table and
 * on the migration cards. Every entry pairs a colour with a label and a short
 * glyph, because colour must never be the only carrier of meaning.
 */

export const RISK_ORDER = ['Critical', 'High', 'Medium', 'Low'];

export const RISK = {
  Critical: {
    label: 'Critical',
    glyph: '▲',
    badge: 'badge badge-critical',
    color: 'var(--critical)',
    mark: 'var(--critical-mark)',
    fill: 'var(--critical-fill)',
    meaning: 'Act now — broken cryptography, or data outliving the quantum horizon in a sensitive system.',
  },
  High: {
    label: 'High',
    glyph: '▲',
    badge: 'badge badge-high',
    color: 'var(--high)',
    mark: 'var(--high-mark)',
    fill: 'var(--high-fill)',
    meaning: 'Data shelf life plus migration time exceeds the CRQC horizon. Plan migration this cycle.',
  },
  Medium: {
    label: 'Medium',
    glyph: '■',
    badge: 'badge badge-medium',
    color: 'var(--medium)',
    mark: 'var(--medium-mark)',
    fill: 'var(--medium-fill)',
    meaning: 'Safe today, but with under two years of margin. Schedule migration.',
  },
  Low: {
    label: 'Low',
    glyph: '●',
    badge: 'badge badge-low',
    color: 'var(--low)',
    mark: 'var(--low-mark)',
    fill: 'var(--low-fill)',
    meaning: 'Comfortable margin, or already quantum-resistant.',
  },
};

export function riskMeta(category) {
  return RISK[category] || RISK.Low;
}

/** Quantum vulnerability status: what breaks this, and how. */
export const VULN = {
  fully_broken: {
    label: "Broken by Shor's",
    short: "Shor's",
    glyph: '▲',
    badge: 'badge badge-critical',
    color: 'var(--critical)',
    mark: 'var(--critical-mark)',
    detail: "Shor's algorithm solves factoring and discrete logarithms in polynomial time, reducing RSA, ECC and Diffie-Hellman to zero security.",
  },
  classically_broken: {
    label: 'Already broken',
    short: 'Classical',
    glyph: '▲',
    badge: 'badge badge-critical',
    color: '#d64550',
    mark: '#ef6b6b',
    detail: 'Broken by conventional cryptanalysis today — no quantum computer required.',
  },
  degraded: {
    label: "Degraded by Grover's",
    short: "Grover's",
    glyph: '■',
    badge: 'badge badge-high',
    color: 'var(--high)',
    mark: 'var(--high-mark)',
    detail: "Grover's search halves effective key strength: a 128-bit key offers roughly 64 bits against a quantum adversary.",
  },
  quantum_safe: {
    label: 'Quantum-safe',
    short: 'Safe',
    glyph: '●',
    badge: 'badge badge-low',
    color: 'var(--low)',
    mark: 'var(--low-mark)',
    detail: 'No known quantum advantage at this parameter size.',
  },
  hybrid_protected: {
    label: 'Hybrid protected',
    short: 'Hybrid',
    glyph: '●',
    badge: 'badge badge-low',
    color: '#0d9488',
    mark: '#14b8a6',
    detail: 'Classical and post-quantum primitives combined, so a break in either alone is survivable.',
  },
  unknown: {
    label: 'Undetermined',
    short: 'Unknown',
    glyph: '?',
    badge: 'badge badge-neutral',
    // A mid neutral: visible as a chart bar on a light ground while staying
    // obviously neutral rather than implying a severity.
    color: '#9aa0ac',
    mark: 'var(--neutral-mark)',
    detail:
      'The underlying algorithm is not visible in the evidence — typically a key file, a certificate or a hardware module reference. Inspect it manually rather than assuming it is safe.',
  },
};

export function vulnMeta(status) {
  return (
    VULN[status] || {
      label: status || 'Unknown',
      short: 'Unknown',
      glyph: '·',
      badge: 'badge badge-neutral',
      color: 'var(--ink-muted)',
      mark: 'var(--neutral-mark)',
      detail: '',
    }
  );
}

export const TARGET_LABELS = {
  source_code: 'Source code',
  binary: 'Binary',
  dependency: 'Dependency',
  container: 'Container',
  multi_target: 'All targets',
};

// How an asset's key size, curve and mode were obtained. This is not a detail:
// the key size sets X in Mosca's inequality, and a value that was assumed
// because none could be read has to be distinguishable from one that was
// measured. RSA-1024 is broken today; RSA-2048 is not.
export const PARAMETER_SOURCES = {
  dataflow: 'Traced across function boundaries (dataflow analysis)',
  literal: 'Read directly from the call site',
  assumed: 'Not readable in the code — conventional default assumed',
};

export const ARTEFACT_TYPE_LABELS = {
  algorithm: 'Algorithm',
  key: 'Key',
  certificate: 'Certificate',
  protocol: 'Protocol',
  library: 'Library',
  hardware_module: 'Hardware module',
  cloud_service: 'Cloud KMS',
};

/** How to read a readiness score. Thresholds stated once. */
export function readinessMeta(score) {
  if (score >= 80) {
    return { label: 'Largely prepared', color: 'var(--low)', mark: 'var(--low-mark)', tone: 'low' };
  }
  if (score >= 50) {
    return { label: 'Migration required', color: 'var(--medium)', mark: 'var(--medium-mark)', tone: 'medium' };
  }
  if (score >= 25) {
    return { label: 'Substantially exposed', color: 'var(--high)', mark: 'var(--high-mark)', tone: 'high' };
  }
  return { label: 'Critically exposed', color: 'var(--critical)', mark: 'var(--critical-mark)', tone: 'critical' };
}

/** 1,234 rather than 1234 — long unformatted numbers are hard to compare. */
export function formatNumber(n) {
  if (n === null || n === undefined) return '—';
  return n.toLocaleString('en-US');
}

/** Keep the filename visible; elide the middle of a long path. */
export function shortenPath(path, maxLength = 48) {
  if (!path) return '—';
  const normalised = path.replace(/\\/g, '/');
  if (normalised.length <= maxLength) return normalised;
  const parts = normalised.split('/');
  const file = parts.pop();
  if (file.length >= maxLength - 4) return `…/${file}`;
  let prefix = '';
  for (const part of parts) {
    if (prefix.length + part.length + 1 > maxLength - file.length - 4) break;
    prefix += `${part}/`;
  }
  return `${prefix}…/${file}`;
}

export function fileName(path) {
  if (!path) return '—';
  return path.replace(/\\/g, '/').split('/').pop() || path;
}
