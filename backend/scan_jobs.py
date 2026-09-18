"""
Scan job registry.

Scans used to run synchronously inside the request handler. A directory scan of
a real project blocked for minutes with no way to observe or cancel it, so the
UI papered over the wait with a hardcoded sequence of setTimeout log lines that
described work the backend was not reporting.

Jobs run on a worker thread and publish genuine progress — the current phase,
the file being read, counts actually completed — which the UI polls. Nothing is
simulated, and a stuck scan is visible rather than indistinguishable from a
fast one.
"""
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# The pipeline phases a scan moves through, in order. The UI renders these as a
# checklist, so the names are user-facing.
PHASES: List[str] = [
    "Enumerating files",
    "Scanning source code",
    "Scanning binaries",
    "Scanning dependencies",
    "Scanning containers",
    "Resolving parameters",
    "Normalising artefacts",
    "Assessing quantum risk",
    "Building CBOM",
]


class ScanCancelled(Exception):
    """Raised inside a worker when the job has been cancelled."""


@dataclass
class ScanJob:
    job_id: str
    target_name: str
    state: JobState = JobState.QUEUED
    phase: str = PHASES[0]
    phase_index: int = 0
    files_total: int = 0
    files_done: int = 0
    current_file: Optional[str] = None
    evidence_count: int = 0
    artefact_count: int = 0
    messages: List[str] = field(default_factory=list)
    error: Optional[str] = None
    result: Optional[Any] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    warnings: List[str] = field(default_factory=list)
    _cancel: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # --- Worker-side API ---------------------------------------------------
    def check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()

    def set_phase(self, phase: str) -> None:
        self.check_cancelled()
        with self._lock:
            self.phase = phase
            if phase in PHASES:
                self.phase_index = PHASES.index(phase)
            self.messages.append(f"{_stamp()}  {phase}")

    def set_total(self, total: int) -> None:
        with self._lock:
            self.files_total = total

    def file_done(self, path: str) -> None:
        self.check_cancelled()
        with self._lock:
            self.files_done += 1
            self.current_file = path

    def log(self, message: str) -> None:
        with self._lock:
            self.messages.append(f"{_stamp()}  {message}")

    def warn(self, message: str) -> None:
        with self._lock:
            self.warnings.append(message)
            self.messages.append(f"{_stamp()}  Note: {message}")

    # --- Controller-side API -----------------------------------------------
    def cancel(self) -> None:
        self._cancel.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def snapshot(self) -> Dict[str, Any]:
        """A JSON-serialisable view for the progress endpoint."""
        with self._lock:
            pct = 0.0
            if self.state == JobState.COMPLETED:
                pct = 100.0
            elif self.files_total > 0:
                # File progress dominates; phase position fills the tail where
                # no files are being read (analysis, CBOM build).
                file_fraction = min(1.0, self.files_done / self.files_total)
                pct = round(file_fraction * 80.0 + (self.phase_index / len(PHASES)) * 20.0, 1)
            elif self.phase_index:
                pct = round((self.phase_index / len(PHASES)) * 100.0, 1)

            return {
                "job_id": self.job_id,
                "target_name": self.target_name,
                "state": self.state.value,
                "phase": self.phase,
                "phase_index": self.phase_index,
                "phase_total": len(PHASES),
                "percent": min(99.0, pct) if self.state == JobState.RUNNING else pct,
                "files_total": self.files_total,
                "files_done": self.files_done,
                "current_file": self.current_file,
                "evidence_count": self.evidence_count,
                "artefact_count": self.artefact_count,
                "messages": list(self.messages[-40:]),
                "warnings": list(self.warnings),
                "error": self.error,
                "scan_id": (
                    self.result.summary.scan_id
                    if self.state == JobState.COMPLETED and self.result is not None
                    else None
                ),
                "started_at": self.started_at.isoformat(),
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            }


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class ScanJobRegistry:
    """Holds running and recently finished jobs."""

    # Finished jobs are retained so the UI can read the terminal state even if
    # it polls after completion; older ones are pruned to bound memory.
    MAX_RETAINED = 20

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(self, target_name: str) -> ScanJob:
        job = ScanJob(job_id=f"JOB-{uuid.uuid4().hex[:10].upper()}", target_name=target_name)
        with self._lock:
            self._jobs[job.job_id] = job
            self._prune()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def run(self, job: ScanJob, work: Callable[[ScanJob], Any]) -> None:
        """Execute ``work`` on a daemon thread, recording the outcome on the job."""

        def runner() -> None:
            job.state = JobState.RUNNING
            try:
                result = work(job)
                if job.is_cancelled:
                    job.state = JobState.CANCELLED
                    job.log("Scan cancelled.")
                else:
                    job.result = result
                    job.artefact_count = result.summary.total_artefacts
                    job.state = JobState.COMPLETED
                    job.log(
                        f"Complete — {result.summary.total_artefacts} distinct "
                        f"cryptographic assets catalogued."
                    )
            except ScanCancelled:
                job.state = JobState.CANCELLED
                job.log("Scan cancelled.")
            except Exception as exc:  # surfaced to the UI verbatim
                job.state = JobState.FAILED
                job.error = str(exc) or exc.__class__.__name__
                job.log(f"Failed: {job.error}")
            finally:
                job.finished_at = datetime.now(timezone.utc)

        threading.Thread(target=runner, daemon=True, name=f"scan-{job.job_id}").start()

    def _prune(self) -> None:
        finished = [
            j for j in self._jobs.values()
            if j.state in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED)
        ]
        if len(finished) <= self.MAX_RETAINED:
            return
        finished.sort(key=lambda j: j.finished_at or j.started_at)
        for job in finished[: len(finished) - self.MAX_RETAINED]:
            self._jobs.pop(job.job_id, None)


registry = ScanJobRegistry()
