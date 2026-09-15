/**
 * Scan launcher.
 *
 * The previous version printed a fixed sequence of "[DISCOVERY] Scanning
 * targets..." lines on setTimeout and then waited a further hardcoded 2000ms
 * after the real result had already arrived. None of it described the backend.
 *
 * Everything shown here is polled from /api/scan/jobs/{id}: the phase the
 * pipeline is actually in, the file it is actually reading, and real counts.
 * Long scans are cancellable.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  FileArchive,
  FolderOpen,
  GitBranch,
  Loader2,
  Play,
  Upload,
  X,
} from 'lucide-react';
import { Alert, Segmented } from './ui/Primitives';
import { formatNumber } from '../lib/risk';

/**
 * Windows Explorer's "Copy as path" wraps the path in double quotes, and
 * pasting that verbatim used to fail with `Path not found: "C:\..."`. The
 * backend strips these too; doing it here as well means the field shows the
 * path that will actually be scanned.
 */
function cleanPath(value) {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    for (const q of ['"', "'"]) {
      if (trimmed.startsWith(q) && trimmed.endsWith(q)) return trimmed.slice(1, -1).trim();
    }
  }
  return trimmed;
}

const MODES = [
  { value: 'path', label: 'Local folder', icon: FolderOpen },
  { value: 'git', label: 'Git repository', icon: GitBranch },
  { value: 'upload', label: 'Upload archive', icon: Upload },
];


const TARGET_TYPES = [
  { value: 'multi_target', label: 'Everything (all four scanners)' },
  { value: 'source_code', label: 'Source code only' },
  { value: 'binary', label: 'Binaries and firmware only' },
  { value: 'dependency', label: 'Dependency manifests only' },
  { value: 'container', label: 'Container definitions only' },
];

export default function ScanView({ onScanComplete, onError }) {
  const [mode, setMode] = useState('path');
  const [targetName, setTargetName] = useState('');
  const [targetType, setTargetType] = useState('multi_target');
  const [path, setPath] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [gitToken, setGitToken] = useState('');
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [moscaZ, setMoscaZ] = useState(8);
  // X in Mosca's inequality is a property of the data, not of the algorithms
  // found in it, so it has to be stated rather than inferred. The list and its
  // retention figures come from the backend so there is one definition of them.
  const [profile, setProfile] = useState('financial');
  const [profiles, setProfiles] = useState([]);

  const [job, setJob] = useState(null);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState(null);
  const pollRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/config/sensitivity-profiles')
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => {
        if (cancelled || !body) return;
        setProfiles(body.profiles || []);
        if (body.default) setProfile(body.default);
      })
      .catch(() => {
        /* the scan still runs on the backend default if this cannot be read */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const pollJob = useCallback(
    (jobId) => {
      stopPolling();
      pollRef.current = setInterval(async () => {
        try {
          const res = await fetch(`/api/scan/jobs/${jobId}`);
          if (!res.ok) throw new Error('Lost contact with the scan job.');
          const snap = await res.json();
          setJob(snap);

          if (snap.state === 'completed') {
            stopPolling();
            const resultRes = await fetch(`/api/scan/jobs/${jobId}/result`);
            if (!resultRes.ok) throw new Error('Scan finished but the result could not be read.');
            const result = await resultRes.json();
            setBusy(false);
            onScanComplete(result);
          } else if (snap.state === 'failed') {
            stopPolling();
            setBusy(false);
            setLocalError(snap.error || 'The scan failed.');
          } else if (snap.state === 'cancelled') {
            stopPolling();
            setBusy(false);
          }
        } catch (e) {
          stopPolling();
          setBusy(false);
          setLocalError(e.message);
        }
      }, 350);
    },
    [onScanComplete, stopPolling]
  );

  const launch = async () => {
    setLocalError(null);
    setJob(null);
    setBusy(true);

    try {
      let res;
      if (mode === 'upload') {
        if (!file) throw new Error('Choose a file to scan.');
        const form = new FormData();
        form.append('file', file);
        form.append('target_name', targetName || file.name);
        form.append('target_type', targetType);
        form.append('mosca_z', String(moscaZ));
        form.append('sensitivity_profile', profile);
        res = await fetch('/api/scan/upload', { method: 'POST', body: form });
      } else if (mode === 'git') {
        if (!gitUrl.trim()) throw new Error('Enter a repository URL.');
        res = await fetch('/api/scan/git', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo_url: gitUrl.trim(),
            target_name: targetName || null,
            // Blank means "whatever the default branch is", rather than
            // guessing "main" and failing on repositories that use master.
            branch: gitBranch.trim() || null,
            auth_token: gitToken.trim() || null,
            mosca_z: moscaZ,
            sensitivity_profile: profile,
          }),
        });
      } else {
        if (!cleanPath(path)) throw new Error('Enter a folder or file path.');
        res = await fetch('/api/scan/path', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_name: targetName || cleanPath(path),
            target_type: targetType,
            path: cleanPath(path),
            mosca_z: moscaZ,
            sensitivity_profile: profile,
          }),
        });
      }

      if (!res.ok) throw new Error((await res.json()).detail || 'Scan could not be started.');
      const { job_id } = await res.json();
      setJob({ job_id, state: 'queued', phase: 'Starting', percent: 0, messages: [] });
      pollJob(job_id);
    } catch (e) {
      setBusy(false);
      setLocalError(e.message);
    }
  };

  const cancel = async () => {
    if (!job?.job_id) return;
    await fetch(`/api/scan/jobs/${job.job_id}/cancel`, { method: 'POST' });
  };

  const canLaunch =
    !busy &&
    ((mode === 'path' && path.trim()) ||
      (mode === 'git' && gitUrl.trim()) ||
      (mode === 'upload' && file));

  return (
    <div className="animate-fade-in mx-auto max-w-3xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Run a scan</h1>
        <p className="mt-1 text-[13px] text-muted">
          Source, binaries, dependencies and containers.
        </p>
      </div>

      <Segmented options={MODES} value={mode} onChange={setMode} ariaLabel="Scan source" />

      {localError && (
        <Alert tone="error" title="Scan failed" onDismiss={() => setLocalError(null)}>
          {localError}
        </Alert>
      )}

      {/* ---- Local folder ---- */}
      {mode === 'path' && (
        <div className="panel space-y-4 p-4">
          <div>
            <label className="label" htmlFor="scan-path">
              Folder or file path
            </label>
            <input
              id="scan-path"
              className="field field-mono"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onBlur={(e) => setPath(cleanPath(e.target.value))}
              onPaste={(e) => {
                e.preventDefault();
                setPath(cleanPath(e.clipboardData.getData('text')));
              }}
              placeholder="C:\projects\my-service"
              spellCheck={false}
            />
            <p className="hint">
              Dependency trees, build output and VCS directories are skipped.
            </p>
          </div>
          <NameAndScope
            targetName={targetName}
            setTargetName={setTargetName}
            targetType={targetType}
            setTargetType={setTargetType}
          />
        </div>
      )}

      {/* ---- Git ---- */}
      {mode === 'git' && (
        <div className="panel space-y-4 p-4">
          <div>
            <label className="label" htmlFor="git-url">
              Repository URL
            </label>
            <input
              id="git-url"
              className="field field-mono"
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              placeholder="https://github.com/organisation/repository.git"
              spellCheck={false}
            />
            <p className="hint">
              Cloned to a temporary directory and deleted after the scan.
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="git-branch">
                Branch <span className="font-normal text-faint">(optional)</span>
              </label>
              <input
                id="git-branch"
                className="field"
                value={gitBranch}
                onChange={(e) => setGitBranch(e.target.value)}
                placeholder="Repository default"
                spellCheck={false}
              />
            </div>
            <div>
              <label className="label" htmlFor="git-token">
                Access token <span className="font-normal text-faint">(private repos)</span>
              </label>
              <input
                id="git-token"
                type="password"
                className="field"
                value={gitToken}
                onChange={(e) => setGitToken(e.target.value)}
                placeholder="ghp_…"
                autoComplete="off"
              />
            </div>
          </div>
        </div>
      )}

      {/* ---- Upload ---- */}
      {mode === 'upload' && (
        <div className="panel space-y-4 p-4">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
            }}
            className="rounded-lg border-2 border-dashed p-8 text-center transition-colors"
            style={{
              borderColor: dragging ? 'var(--accent)' : 'var(--line-strong)',
              background: dragging ? 'rgba(5,150,105,0.06)' : 'transparent',
            }}
          >
            <input
              type="file"
              id="scan-file"
              className="sr-only"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            {file ? (
              <div className="flex items-center justify-center gap-3">
                <FileArchive className="h-5 w-5" style={{ color: 'var(--accent-hover)' }} />
                <div className="text-left">
                  <div className="text-[13px] font-medium">{file.name}</div>
                  <div className="text-xs text-faint tabular">
                    {(file.size / 1024).toFixed(0)} KB
                  </div>
                </div>
                <button className="btn btn-ghost px-2" onClick={() => setFile(null)} aria-label="Remove file">
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ) : (
              <label htmlFor="scan-file" className="cursor-pointer">
                <Upload className="mx-auto h-6 w-6 text-muted" aria-hidden="true" />
                <div className="mt-2.5 text-[13px] font-medium">
                  Drop a file here, or <span style={{ color: 'var(--accent-hover)' }}>browse</span>
                </div>
                <p className="mt-1 text-xs text-faint">
                  A .zip of a whole repository, or a single source file, binary or Dockerfile
                </p>
              </label>
            )}
          </div>
          <NameAndScope
            targetName={targetName}
            setTargetName={setTargetName}
            targetType={targetType}
            setTargetType={setTargetType}
            scopeHint="Ignored for .zip archives — those are always scanned with all four scanners."
          />
        </div>
      )}

      {/* ---- What the cryptography protects ---- */}
      <div className="panel p-4">
        <label className="label mb-0" htmlFor="sensitivity-profile">
          What does this cryptography protect?
        </label>
        <p className="text-xs text-faint">
          Sets X — how long the data must stay secret.
        </p>
        <select
          id="sensitivity-profile"
          className="field mt-3"
          value={profile}
          onChange={(e) => setProfile(e.target.value)}
        >
          {profiles.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label} — {p.retention_years} year{p.retention_years === 1 ? '' : 's'} retention
            </option>
          ))}
        </select>
        <p className="hint">
          Certificates and signing keys use their own validity window.
        </p>
      </div>

      {/* ---- Horizon ---- */}
      <div className="panel p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <label className="label mb-0" htmlFor="mosca-z">
              Quantum horizon (Z)
            </label>
            <p className="text-xs text-faint">
              Years until a cryptographically relevant quantum computer.
            </p>
          </div>
          <output
            className="mono rounded border border-line bg-surface-sunken px-2.5 py-1 text-sm font-semibold tabular"
            htmlFor="mosca-z"
          >
            {moscaZ} years
          </output>
        </div>
        <input
          id="mosca-z"
          type="range"
          min="2"
          max="20"
          step="0.5"
          value={moscaZ}
          onChange={(e) => setMoscaZ(parseFloat(e.target.value))}
          className="mt-3 w-full"
          style={{ accentColor: 'var(--accent)' }}
        />
        <div className="mt-1 flex justify-between text-[11px] text-faint">
          <span>2 — aggressive</span>
          <span>8 — common planning baseline</span>
          <span>20 — conservative</span>
        </div>
        <p className="hint">Adjustable later without rescanning.</p>
      </div>

      {/* ---- Launch / progress ---- */}
      {busy && job ? (
        <ScanProgress job={job} onCancel={cancel} />
      ) : (
        <button className="btn btn-primary btn-lg w-full" disabled={!canLaunch} onClick={launch}>
          <Play className="h-4 w-4" />
          Start scan
        </button>
      )}

      {!busy && job?.state === 'cancelled' && (
        <Alert tone="warn" title="Scan cancelled">
          No inventory was produced. Adjust the target and start again.
        </Alert>
      )}
    </div>
  );
}

function NameAndScope({ targetName, setTargetName, targetType, setTargetType, scopeHint }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <div>
        <label className="label" htmlFor="target-name">
          Name <span className="font-normal text-faint">(optional)</span>
        </label>
        <input
          id="target-name"
          className="field"
          value={targetName}
          onChange={(e) => setTargetName(e.target.value)}
          placeholder="How this should appear in reports"
        />
      </div>
      <div>
        <label className="label" htmlFor="target-type">
          Scanners to run
        </label>
        <select
          id="target-type"
          className="field"
          value={targetType}
          onChange={(e) => setTargetType(e.target.value)}
        >
          {TARGET_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
        {scopeHint && <p className="hint">{scopeHint}</p>}
      </div>
    </div>
  );
}

/** Progress built entirely from backend state. */
function ScanProgress({ job, onCancel }) {
  const pct = job.percent || 0;

  return (
    <div className="panel overflow-hidden">
      <div className="panel-head">
        <div className="min-w-0">
          <h2 className="panel-title flex items-center gap-2">
            <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color: 'var(--accent-hover)' }} />
            {job.phase}
          </h2>
          <p className="panel-sub">
            {job.files_total > 0
              ? `${formatNumber(job.files_done)} of ${formatNumber(job.files_total)} files read`
              : 'Preparing…'}
            {job.evidence_count > 0 && ` · ${formatNumber(job.evidence_count)} matches so far`}
          </p>
        </div>
        <button className="btn btn-danger" onClick={onCancel}>
          Cancel
        </button>
      </div>

      <div className="px-5 pt-4">
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-sunken">
          <div
            className="h-full rounded-full transition-[width] duration-300"
            style={{ width: `${pct}%`, background: 'var(--accent)' }}
          />
        </div>
        <div className="mt-1.5 flex justify-between text-[11px] text-faint tabular">
          <span>
            Step {(job.phase_index ?? 0) + 1} of {job.phase_total ?? 8}
          </span>
          <span>{pct.toFixed(0)}%</span>
        </div>
      </div>

      {job.current_file && (
        <p className="mono truncate px-5 pt-2.5 text-[11px] text-faint" title={job.current_file}>
          {job.current_file}
        </p>
      )}

      {job.messages?.length > 0 && (
        <div className="mt-4 max-h-40 overflow-y-auto border-t border-line bg-surface-sunken px-5 py-3">
          {job.messages.map((m, i) => (
            <div key={`${i}-${m}`} className="mono text-[11px] leading-relaxed text-muted">
              {m}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
