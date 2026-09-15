/**
 * Downloading a report from inside the desktop window.
 *
 * The app runs in WebView2 via pywebview, where a plain `<a download>` and a
 * same-origin `target="_blank"` both silently do nothing — the click produced
 * no file and no error. The launcher exposes a native bridge on
 * `window.pywebview.api`; when it is present we use a real Save dialog, and
 * when it is not (a dev browser) we fall back to normal anchor behaviour.
 */

/** True when running inside the packaged desktop window. */
export function isDesktop() {
  return typeof window !== 'undefined' && Boolean(window.pywebview?.api?.save_file);
}

/**
 * Save a report to disk.
 * Resolves to { ok, cancelled?, path?, error? }.
 */
export async function saveReport(apiPath, suggestedName) {
  if (isDesktop()) {
    try {
      return await window.pywebview.api.save_file(apiPath, suggestedName);
    } catch (e) {
      return { ok: false, error: e?.message || String(e) };
    }
  }

  // Browser fallback: fetch to a blob so the filename is honoured and a failing
  // request surfaces as an error instead of navigating away to an error page.
  try {
    const res = await fetch(apiPath);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = suggestedName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Revoke on the next tick; revoking immediately can cancel the download.
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    return { ok: true, path: suggestedName };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}

/**
 * Open a report for viewing — the system browser on desktop, a new tab
 * otherwise, so it can be read and printed to PDF.
 */
export async function openReport(apiPath) {
  if (typeof window !== 'undefined' && window.pywebview?.api?.open_external) {
    try {
      return await window.pywebview.api.open_external(apiPath);
    } catch (e) {
      return { ok: false, error: e?.message || String(e) };
    }
  }

  const opened = window.open(apiPath, '_blank', 'noopener');
  return opened
    ? { ok: true }
    : { ok: false, error: 'The browser blocked the new window. Allow pop-ups and try again.' };
}
