/**
 * Values shared across the app that do not belong to any one view.
 *
 * MERGED_SCAN_ID lives here rather than in App.jsx because Shell, Inventory and
 * Reports all need it, and importing it from App would make those components
 * circular dependencies of their own parent.
 */

/**
 * The id addressing the derived union of every stored scan. It is not a stored
 * scan: the backend builds it on request, it is never persisted, and it cannot
 * be deleted or have a horizon saved against it.
 */
export const MERGED_SCAN_ID = 'ALL';
