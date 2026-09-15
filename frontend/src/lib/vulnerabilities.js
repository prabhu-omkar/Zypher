/**
 * How published advisories are named and coloured.
 *
 * Deliberately separate from the risk ramp in risk.js. A CVE is a present-day
 * defect in a released version; the Mosca bands describe exposure to a future
 * quantum adversary. Showing them in the same colours would suggest they are
 * the same axis, and a library can easily be quantum-safe with a critical CVE,
 * or quantum-broken with a clean advisory record.
 */

const SEVERITY_ORDER = ['Critical', 'High', 'Moderate', 'Medium', 'Low'];

export function advisorySeverityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** The most severe advisory on an asset, or null. */
export function worstAdvisory(artefact) {
  const list = artefact?.known_vulnerabilities || [];
  if (list.length === 0) return null;
  return [...list].sort(
    (a, b) => advisorySeverityRank(a.severity) - advisorySeverityRank(b.severity)
  )[0];
}

export function advisoryStyle(severity) {
  switch (severity) {
    case 'Critical':
      return { color: 'var(--critical)', badge: 'badge badge-critical' };
    case 'High':
      return { color: 'var(--high)', badge: 'badge badge-high' };
    case 'Moderate':
    case 'Medium':
      return { color: 'var(--medium)', badge: 'badge badge-medium' };
    case 'Low':
      return { color: 'var(--ink-muted)', badge: 'badge badge-neutral' };
    default:
      return { color: 'var(--ink-muted)', badge: 'badge badge-neutral' };
  }
}

/** Total advisories across an inventory. */
export function countAdvisories(artefacts) {
  return (artefacts || []).reduce(
    (total, a) => total + (a.known_vulnerabilities?.length || 0),
    0
  );
}
