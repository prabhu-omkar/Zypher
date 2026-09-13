import os
import sys
import uuid
import shutil
import zipfile
import tempfile
import subprocess
import json
import secrets
from datetime import date, datetime, timezone
from typing import Optional, List, Dict, Any, Callable
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from backend.config import config
from backend.models import (
    TargetType, RawEvidence, CryptographicArtefact, KnownVulnerability,
    ScanResult, ScanSummary, RiskCategory, QuantumVulnerabilityStatus,
    DataSensitivityProfile
)
from backend.scanners.source_scanner import SourceCodeScanner
from backend.scanners.taint_scanner import TaintScanner
from backend.scanners.binary_scanner import BinaryScanner
from backend.scanners.dependency_scanner import DependencyScanner
from backend.scanners.container_scanner import ContainerScanner
from backend.scanners.certificate_scanner import CertificateScanner
from backend.scanners.walker import WalkLimits, WalkStats, count_candidate_files
from backend.cbom.artefact_extractor import ArtefactExtractor
from backend.cbom.aggregator import aggregate_artefacts, merge_artefact_sets
from backend.cbom.cbom_builder import CBOMBuilder
from backend.cbom.storage import EnterpriseStorageManager
from backend.analysis.classifier import Classifier
from backend.analysis import agility as agility_analysis
from backend.analysis.delta import compare_scans
from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.analysis.risk_inputs import (
    CRQC_CURVE_SOURCE, PROFILE_LABELS, PROFILE_RETENTION_YEARS,
    crqc_probability_within, years_from,
)
from backend.analysis.vulnerability_lookup import VulnerabilityLookup
from backend.recommendation.recommendation_engine import RecommendationEngine
from backend.recommendation.migration_planner import build_migration_plan
from backend.reporting.report_generator import ReportGenerator
from backend.scan_jobs import registry as job_registry, ScanJob, JobState
from backend.admin_session import AdminSessions, bearer_token

app = FastAPI(
    title="Zypher — Cryptographic Discovery & Analysis",
    description="SIH 26164 (NTRO) - Cryptographic Discovery, CBOM Generation, Mosca Quantum Risk & PQC Migration Engine",
    version="1.1.0"
)

# CORS is needed only for the Vite dev server on another port. In the packaged
# desktop app the SPA is served from this same origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Storage Manager
storage_manager = EnterpriseStorageManager(data_dir=config.storage_dir)

# Initialize Scanners
source_scanner = SourceCodeScanner()
taint_scanner = TaintScanner()
binary_scanner = BinaryScanner()
dependency_scanner = DependencyScanner()
container_scanner = ContainerScanner()
certificate_scanner = CertificateScanner()

# Admin sessions: tokens with a lifetime, and a throttle on failed logins.
# Previously a bare set() of strings that never expired and could be guessed at
# without cost — see backend/admin_session.py.
admin_sessions = AdminSessions()


def normalise_path(raw: str) -> str:
    r"""
    Clean a filesystem path typed or pasted by a user.

    Windows Explorer's "Copy as path" (Shift+Right-click) wraps the path in
    double quotes, and pasting that verbatim produced `Path not found:
    "C:\projects\..."` — the quotes were part of the string being looked up.
    Dragging a file into a terminal can add single quotes the same way.

    Also expands ~ and %VARS%, so those work as typed.
    """
    if raw is None:
        return ""
    cleaned = raw.strip()

    # Strip one balanced layer of surrounding quotes.
    for quote in ('"', "'"):
        if len(cleaned) >= 2 and cleaned.startswith(quote) and cleaned.endswith(quote):
            cleaned = cleaned[1:-1].strip()
            break

    if not cleaned:
        return ""

    return os.path.normpath(os.path.expanduser(os.path.expandvars(cleaned)))


# Request Models
class DBConfigRequest(BaseModel):
    mongo_uri: str
    database_name: Optional[str] = "ecdat_enterprise_inventory"


class ScanPathRequest(BaseModel):
    target_name: str
    target_type: TargetType
    path: str
    mosca_z: Optional[float] = 8.0
    # What class of data this target protects. X in Mosca's inequality is a
    # property of the data, so it has to be stated rather than guessed from the
    # algorithm names found in the code.
    sensitivity_profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL
    # An organisation that knows its own retention policy can state it directly
    # instead of taking the profile's default.
    retention_override_years: Optional[float] = None

    @field_validator("path")
    @classmethod
    def clean_path(cls, value: str) -> str:
        return normalise_path(value)


class GitScanRequest(BaseModel):
    repo_url: str
    target_name: Optional[str] = None
    branch: Optional[str] = None
    auth_token: Optional[str] = None # Optional personal access token for private repos
    mosca_z: Optional[float] = 8.0
    # What class of data this target protects. X in Mosca's inequality is a
    # property of the data, so it has to be stated rather than guessed from the
    # algorithm names found in the code.
    sensitivity_profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL
    # An organisation that knows its own retention policy can state it directly
    # instead of taking the profile's default.
    retention_override_years: Optional[float] = None


class RecalculateRequest(BaseModel):
    mosca_z: float
    # Changing the sensitivity profile re-derives X for every asset, so the
    # what-if sandbox can explore "what if this were health data" as well as
    # "what if a CRQC arrived sooner".
    sensitivity_profile: Optional[DataSensitivityProfile] = None
    retention_override_years: Optional[float] = None
    # The Mosca view is a what-if sandbox. By default a recalculation returns a
    # projection without altering the stored scan, so exploring timelines cannot
    # silently rewrite the audited record. Set true to commit the new Z.
    persist: bool = False


class AdminSetupRequest(BaseModel):
    password: str


class AdminLoginRequest(BaseModel):
    password: str


def read_scope(authorization: Optional[str] = Header(None)) -> str:
    """
    How much of the store this request may read.

    Everything the application shows normally is scoped to the scans this
    installation produced. Pointing two installations at one database must not
    make either one's work visible to the other. An unlocked admin session
    widens the scope to the whole estate, and nothing else does.
    """
    if admin_sessions.is_valid(bearer_token(authorization)):
        return storage_manager.SCOPE_ALL
    return storage_manager.SCOPE_OWN


# --- SCAN PIPELINE ---------------------------------------------------------

def run_all_scanners(
    root: str,
    target_type: TargetType,
    job: Optional[ScanJob] = None,
    limits: Optional[WalkLimits] = None,
) -> tuple:
    """
    Run the scanners selected by ``target_type`` over ``root``.

    Returns ``(raw_evidences, stats, dataflow_report)``, where the report is the
    outcome of the Tier 4 pass and is None for target types it does not apply to.
    Progress is reported through ``job`` as files are actually opened, so the UI
    reflects real work.
    """
    limits = limits or WalkLimits()
    stats = WalkStats()
    evidences: List[RawEvidence] = []
    is_dir = os.path.isdir(root)

    wants = {
        TargetType.SOURCE_CODE: [
            ("Scanning source code", source_scanner, "scan_file"),
            # Certificates sitting in a repository are part of its cryptography
            # and state their own algorithm, key size and expiry.
            ("Reading certificates", certificate_scanner, "scan_file"),
        ],
        TargetType.BINARY: [("Scanning binaries", binary_scanner, "scan_file")],
        TargetType.DEPENDENCY: [("Scanning dependencies", dependency_scanner, "scan_file")],
        TargetType.CONTAINER: [("Scanning containers", container_scanner, "scan_dockerfile")],
    }.get(
        target_type,
        [
            ("Scanning source code", source_scanner, "scan_file"),
            ("Reading certificates", certificate_scanner, "scan_file"),
            ("Scanning binaries", binary_scanner, "scan_file"),
            ("Scanning dependencies", dependency_scanner, "scan_file"),
            ("Scanning containers", container_scanner, "scan_dockerfile"),
        ],
    )

    if job is not None and is_dir:
        job.set_phase("Enumerating files")
        total = 0
        for _, scanner, _ in wants:
            total += count_candidate_files(root, accept=scanner.accepts, limits=limits)
        job.set_total(total)
        job.log(f"{total} candidate file(s) to read under {root}")
        if total == 0:
            job.warn(
                "No files matched any scanner. Check the path, or note that "
                "dependency trees, build output and version-control directories "
                "are excluded by design."
            )

    on_file = (lambda p: job.file_done(p)) if job is not None else None

    for phase, scanner, single_method in wants:
        if job is not None:
            job.set_phase(phase)
        if is_dir:
            evidences.extend(
                scanner.scan_directory(root, limits=limits, stats=stats, on_file=on_file)
            )
        else:
            if scanner.accepts(root):
                if on_file is not None:
                    on_file(root)
                evidences.extend(getattr(scanner, single_method)(root))
        if job is not None:
            job.evidence_count = len(evidences)

    # Tier 4. A whole-program analysis needs to see the tree at once to build a
    # call graph, so it runs once over the target rather than per file, and only
    # after the per-file scanners have produced the evidence it refines.
    dataflow = None
    if target_type in (TargetType.SOURCE_CODE, TargetType.MULTI_TARGET):
        if job is not None:
            job.set_phase("Resolving parameters")
        evidences, report = taint_scanner.enrich(evidences, [root])
        dataflow = report
        if job is not None:
            if not report.available:
                job.warn(
                    f"Dataflow analysis unavailable ({report.reason}). Key sizes and "
                    f"algorithms passed through variables will read as undetermined."
                )
            elif report.resolutions:
                job.log(
                    f"Dataflow resolved {report.resolutions} parameter(s) not visible "
                    f"at their call site"
                    + (f", correcting {report.defaults_corrected} assumed default(s)"
                       if report.defaults_corrected else "")
                )
            job.evidence_count = len(evidences)

    return evidences, stats, dataflow


def _walk_warnings(stats: WalkStats) -> List[str]:
    """Translate traversal caps into statements the user can act on."""
    notes: List[str] = []
    if stats.hit_file_limit:
        notes.append(
            f"Stopped after {stats.files_scanned} files (safety cap). Scan a "
            f"narrower subdirectory for full coverage."
        )
    if stats.hit_depth_limit:
        notes.append("Some directories were deeper than the traversal depth limit and were skipped.")
    if stats.files_skipped_size:
        notes.append(f"{stats.files_skipped_size} file(s) exceeded the 8 MB size limit and were skipped.")
    if stats.dirs_pruned:
        notes.append(
            f"{stats.dirs_pruned} directory(ies) excluded as dependency trees, "
            f"build output, or version-control metadata."
        )
    return notes


def execute_pipeline(
    target_name: str,
    target_type: TargetType,
    raw_evidences: List[RawEvidence],
    mosca_z: float = 8.0,
    job: Optional[ScanJob] = None,
    scan_stats: Optional[WalkStats] = None,
    dataflow: Optional[Any] = None,
    sensitivity_profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
    retention_override: Optional[float] = None,
) -> ScanResult:
    scan_id = f"SCAN-{str(uuid.uuid4())[:8].upper()}"

    # Step 1: Extract & normalise artefacts from raw evidence
    if job is not None:
        job.set_phase("Normalising artefacts")
    artefacts = ArtefactExtractor.extract_artefacts(raw_evidences)

    # Step 2: Collapse repeated matches of the same asset into one artefact
    # carrying all its occurrences. Without this, one md5() call repeated on
    # forty lines counted as forty distinct cryptographic assets.
    raw_artefact_count = len(artefacts)
    artefacts = aggregate_artefacts(artefacts)
    if job is not None and raw_artefact_count != len(artefacts):
        job.log(
            f"{raw_artefact_count} matches collapsed into {len(artefacts)} "
            f"distinct assets ({raw_artefact_count - len(artefacts)} duplicate occurrences)"
        )

    # Step 3: Classify artefacts (business criticality, lifetimes)
    classified_artefacts = Classifier.classify_all(artefacts)

    # Step 3b: Optional known-vulnerability enrichment for dependencies.
    vulnerability_record = enrich_with_known_vulnerabilities(classified_artefacts, job=job)

    # Step 3c: Derive the Mosca inputs.
    #
    # X comes from the scan's data-sensitivity profile by way of what each asset
    # is actually for; Y is computed from the evidence — who owns the code, how
    # many sites it touches, whether both ends have to negotiate the change.
    # This runs before assessment so the artefacts stored in the CBOM carry the
    # same numbers the risk engine used.
    if job is not None:
        job.set_phase("Deriving risk inputs")
    classified_artefacts = QuantumRiskEngine.prepare_all(
        classified_artefacts, sensitivity_profile, retention_override
    )

    # Step 3d: Crypto agility (NIST CSWP 39). Scored after the inputs are
    # derived so the reported score and the Y it influenced agree.
    agility_scores = agility_analysis.score_all(classified_artefacts)
    for art in classified_artefacts:
        entry = agility_scores.get(art.id)
        if entry:
            art.agility_score = entry["score"]
            art.agility_band = entry["band"]
            art.agility_factors = entry["factors"]
            art.agility_summary = entry["summary"]

    # Step 4: Quantum Risk Assessment (Mosca, probabilistic, regulatory, HNDL)
    if job is not None:
        job.set_phase("Assessing quantum risk")
    risk_assessments = QuantumRiskEngine.evaluate_all(
        classified_artefacts,
        global_z=mosca_z,
        profile=sensitivity_profile,
        retention_override=retention_override,
    )

    # Step 5: Recommendation Engine (PQC/Hybrid)
    #
    # The profile is passed through because it decides the target security
    # level: CNSA 2.0 requires the Category 5 parameter sets for national
    # security systems whatever the algorithm being replaced.
    recommendations = RecommendationEngine.generate_all(
        classified_artefacts, risk_assessments, profile=sensitivity_profile
    )

    # Step 5b: Turn the per-asset deadlines into a schedule.
    if job is not None:
        job.set_phase("Sequencing the migration")
    migration_plan = build_migration_plan(classified_artefacts, risk_assessments)

    if job is not None:
        job.set_phase("Building CBOM")

    summary = build_summary(
        scan_id=scan_id,
        target_name=target_name,
        target_type=target_type,
        artefacts=classified_artefacts,
        risk_assessments=risk_assessments,
        mosca_z=mosca_z,
        scan_stats=scan_stats,
        raw_match_count=raw_artefact_count,
        sensitivity_profile=sensitivity_profile,
        retention_override=retention_override,
    )
    summary.agility = agility_analysis.estate_summary(agility_scores)
    summary.vulnerability_lookup = vulnerability_record
    summary.total_known_vulnerabilities = sum(
        len(a.known_vulnerabilities) for a in classified_artefacts
    )

    if dataflow is not None:
        summary.dataflow_analysis = {
            "available": dataflow.available,
            "reason": dataflow.reason,
            "version": dataflow.version,
            "rules": dataflow.rules,
            "findings": dataflow.findings,
            "resolutions": dataflow.resolutions,
            "key_sizes_resolved": dataflow.key_sizes_resolved,
            "algorithms_resolved": dataflow.algorithms_resolved,
            "curves_resolved": dataflow.curves_resolved,
            "defaults_corrected": dataflow.defaults_corrected,
            "evidence_added": dataflow.evidence_added,
        }
        # Coverage is stated, never implied. A scan where Tier 4 could not run
        # reports undetermined parameters, and the reason for that belongs
        # alongside the traversal caps rather than being left to inference.
        summary.coverage_notes = list(summary.coverage_notes) + dataflow.notes()

    scan_result = ScanResult(
        summary=summary,
        artefacts=classified_artefacts,
        risk_assessments=risk_assessments,
        recommendations=recommendations,
        raw_evidences=raw_evidences,
        migration_plan=migration_plan,
    )

    storage_manager.save_scan_result(scan_result)
    return scan_result


def enrich_with_known_vulnerabilities(
    artefacts: List[CryptographicArtefact],
    job: Optional[ScanJob] = None,
) -> Dict[str, Any]:
    """
    Attach published advisories to dependency artefacts.

    Opt-in, because it is the only part of the pipeline that touches the
    network. The returned record always says what happened — enabled or not,
    reachable or not — so "no advisories found" is never mistaken for "never
    checked".

    Advisory severity is deliberately kept out of the Mosca risk bands. A CVE is
    a present-day defect in a release; the bands describe exposure to a future
    quantum adversary. Folding one into the other would make both unreadable.
    """
    record: Dict[str, Any] = {
        "enabled": config.vulnerability_lookup_enabled,
        "available": False,
        "packages_checked": 0,
        "advisories_found": 0,
        "from_cache": 0,
        "error": None,
        "source": "OSV (osv.dev)",
    }

    if not config.vulnerability_lookup_enabled:
        record["error"] = "Not enabled. Turn on vulnerability lookup in Settings."
        return record

    with_purl = [a for a in artefacts if a.purl]
    if not with_purl:
        record["available"] = True
        return record

    if job is not None:
        job.set_phase("Checking known vulnerabilities")
        job.log(f"Querying OSV for {len(with_purl)} package(s)...")

    lookup = VulnerabilityLookup(
        cache_path=os.path.join(config.storage_dir, "osv_cache.json")
    )
    result = lookup.lookup([a.purl for a in with_purl])

    record["available"] = result.available
    record["error"] = result.error
    record["packages_checked"] = len(with_purl)
    record["from_cache"] = result.from_cache

    if not result.available:
        if job is not None:
            job.warn(result.error or "Vulnerability lookup unavailable.")
        return record

    total = 0
    for artefact in with_purl:
        advisories = result.by_purl.get(artefact.purl) or []
        artefact.known_vulnerabilities = [
            KnownVulnerability(**a.as_dict()) for a in advisories
        ]
        total += len(advisories)

    record["advisories_found"] = total
    if job is not None:
        job.log(f"{total} advisory(ies) across {len(with_purl)} package(s).")
    return record


def compute_readiness_score(
    artefacts: List[CryptographicArtefact],
    risk_assessments: Dict[str, Any],
) -> float:
    """
    Quantum readiness as a 0-100 penalty score.

    Every finding deducts from a perfect 100 in proportion to its assessed risk,
    normalised by inventory size so that a large estate is not automatically
    scored worse than a small one for the same proportion of weak cryptography.
    An empty inventory scores 100 — there is nothing quantum-vulnerable in it.
    """
    if not artefacts:
        return 100.0

    weights = {
        RiskCategory.CRITICAL: 1.0,
        RiskCategory.HIGH: 0.6,
        RiskCategory.MEDIUM: 0.25,
        RiskCategory.LOW: 0.0,
    }

    penalty = 0.0
    for art in artefacts:
        risk = risk_assessments.get(art.id)
        if risk is None:
            continue
        penalty += weights.get(risk.risk_category, 0.0)

    score = 100.0 * (1.0 - penalty / len(artefacts))
    return round(min(100.0, max(0.0, score)), 1)


def build_summary(
    scan_id: str,
    target_name: str,
    target_type: TargetType,
    artefacts: List[CryptographicArtefact],
    risk_assessments: Dict[str, Any],
    mosca_z: float,
    scan_stats: Optional[WalkStats] = None,
    raw_match_count: Optional[int] = None,
    created_at: Optional[datetime] = None,
    sensitivity_profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
    retention_override: Optional[float] = None,
) -> ScanSummary:
    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    vuln_dist = {
        "fully_broken": 0, "degraded": 0, "classically_broken": 0,
        "quantum_safe": 0, "hybrid_protected": 0, "unknown": 0,
    }

    for art in artefacts:
        risk = risk_assessments.get(art.id)
        if risk:
            key = risk.risk_category.value
            risk_dist[key] = risk_dist.get(key, 0) + 1
        vkey = art.quantum_vulnerability.value
        vuln_dist[vkey] = vuln_dist.get(vkey, 0) + 1

    # Schedule roll-up. The estate's deadline is the earliest one in it, and an
    # asset whose start date has passed is counted separately — a plan that is
    # already late is a different conversation from one that is merely urgent.
    assessed_on = next(
        (r.assessed_on for r in risk_assessments.values()
         if getattr(r, "assessed_on", None)),
        date.today(),
    )
    overdue = sum(
        1 for r in risk_assessments.values() if getattr(r, "is_overdue", False)
    )
    # The next deadline, not the earliest arithmetic one. For an asset whose
    # shelf life already exceeds the horizon, "start by" lands decades in the
    # past — correct arithmetic, useless as a headline. Those are counted as
    # overdue instead, and this reports the next date anyone actually has to act
    # on.
    start_dates = [
        r.must_start_by for r in risk_assessments.values()
        if getattr(r, "must_start_by", None) is not None
        and r.must_start_by >= assessed_on
    ]

    return ScanSummary(
        installation_id=storage_manager.installation_id,
        sensitivity_profile=sensitivity_profile,
        retention_override_years=retention_override,
        assessed_on=assessed_on,
        crqc_estimated_on=years_from(assessed_on, mosca_z),
        earliest_start_required=min(start_dates) if start_dates else None,
        overdue_artefacts=overdue,
        longest_migration_years=round(
            max((a.migration_time_years for a in artefacts), default=0.0), 2
        ),
        total_known_vulnerabilities=sum(len(a.known_vulnerabilities) for a in artefacts),
        scan_id=scan_id,
        target_name=target_name,
        target_types=[target_type],
        created_at=created_at or datetime.now(timezone.utc),
        total_artefacts=len(artefacts),
        total_occurrences=sum(a.occurrence_count for a in artefacts),
        risk_distribution=risk_dist,
        vulnerability_distribution=vuln_dist,
        quantum_readiness_score=compute_readiness_score(artefacts, risk_assessments),
        mosca_global_z=mosca_z,
        files_scanned=scan_stats.files_scanned if scan_stats else 0,
        coverage_notes=_walk_warnings(scan_stats) if scan_stats else [],
    )


# --- MERGED "ALL SCANS" VIEW ------------------------------------------------

# The id the UI uses to address the union of every stored scan. It is not a real
# stored scan, so it is never written to storage.
MERGED_SCAN_ID = "ALL"


def build_merged_scan(
    mosca_z: Optional[float] = None,
    scope: str = "own",
) -> ScanResult:
    """
    Union every stored scan into a single inventory.

    Assets are deduplicated on the same identity used within a scan, so
    rescanning the same target does not double the estate, while the same
    algorithm in two different codebases remains two distinct things to fix.

    Risk is recomputed across the whole union at one horizon. When the stored
    scans disagree about Z, the *smallest* is used — merging must not quietly
    make anything look safer than the scan it came from — and the choice is
    stated in the coverage notes.
    """
    summaries = storage_manager.list_all_scans(scope=scope)

    sets: List[tuple] = []
    horizons: List[float] = []
    profiles: List[DataSensitivityProfile] = []
    files_scanned = 0
    notes: List[str] = []
    vulnerability_records: List[Optional[Dict[str, Any]]] = []
    dataflow_records: List[Optional[Dict[str, Any]]] = []

    for summary in summaries:
        scan_id = summary.get("scan_id")
        if not scan_id:
            continue
        raw = storage_manager.get_scan_result(scan_id, scope=scope)
        if not raw:
            continue
        try:
            scan = ScanResult.model_validate(raw)
        except Exception:
            # A corrupt stored scan must not take down the merged view; it is
            # reported rather than silently skipped.
            notes.append(f"Scan {scan_id} could not be read and was left out of this view.")
            continue
        sets.append((scan.summary.target_name, scan.artefacts))
        horizons.append(scan.summary.mosca_global_z)
        profiles.append(scan.summary.sensitivity_profile)
        files_scanned += scan.summary.files_scanned or 0
        vulnerability_records.append(scan.summary.vulnerability_lookup)
        dataflow_records.append(scan.summary.dataflow_analysis)

    artefacts = merge_artefact_sets(sets)

    if mosca_z is not None:
        effective_z = mosca_z
    elif horizons:
        effective_z = min(horizons)
        if len(set(horizons)) > 1:
            notes.append(
                f"Merged scans were assessed at different horizons "
                f"({', '.join(f'{h:g}y' for h in sorted(set(horizons)))}). "
                f"This view uses the most conservative, Z = {effective_z:g} years."
            )
    else:
        effective_z = config.default_mosca_z

    # Assets keep the X and Y they were audited with, but the merged view needs
    # one profile of its own to report. Take the most conservative — the longest
    # retention — for the same reason the horizon takes the shortest Z.
    effective_profile = max(
        profiles or [DataSensitivityProfile.FINANCIAL],
        key=lambda pr: PROFILE_RETENTION_YEARS[pr],
    )
    if len({p for p in profiles}) > 1:
        notes.append(
            f"Merged scans used different data-sensitivity profiles. This view "
            f"reports the most conservative, "
            f"'{effective_profile.value.replace('_', ' ')}'."
        )

    risks = QuantumRiskEngine.evaluate_all(
        artefacts, global_z=effective_z, profile=effective_profile
    )
    recs = RecommendationEngine.generate_all(
        artefacts, risks, profile=effective_profile
    )

    total_raw = sum(len(a) for _, a in sets)
    if total_raw > len(artefacts):
        notes.insert(
            0,
            f"{len(sets)} scans combined: {total_raw} entries deduplicated to "
            f"{len(artefacts)} distinct assets.",
        )

    summary = build_summary(
        scan_id=MERGED_SCAN_ID,
        target_name=f"All scans ({len(sets)})" if sets else "All scans",
        target_type=TargetType.MULTI_TARGET,
        artefacts=artefacts,
        risk_assessments=risks,
        mosca_z=effective_z,
        sensitivity_profile=effective_profile,
    )
    summary.files_scanned = files_scanned
    summary.coverage_notes = notes

    # Carry the advisory picture across the union. The merged view has no
    # lookup of its own — it inherits whatever its constituent scans recorded —
    # so this reports the combined position rather than leaving the panel blank
    # and looking like nothing was ever checked.
    checked = sum(
        (r or {}).get("packages_checked", 0) for r in vulnerability_records
    )
    any_enabled = any((r or {}).get("enabled") for r in vulnerability_records)
    any_available = any((r or {}).get("available") for r in vulnerability_records)
    first_error = next(
        ((r or {}).get("error") for r in vulnerability_records if (r or {}).get("error")),
        None,
    )
    summary.vulnerability_lookup = {
        "enabled": any_enabled,
        "available": any_available,
        "packages_checked": checked,
        "advisories_found": summary.total_known_vulnerabilities,
        "from_cache": 0,
        "error": None if any_available else first_error,
        "source": "OSV (osv.dev)",
    }

    # Same reasoning for the Tier 4 picture: the merged view runs no analysis of
    # its own, so it reports the combined position of the scans behind it. A
    # blank panel here would read as "dataflow analysis never ran".
    present = [r for r in dataflow_records if r]
    if present:
        summary.dataflow_analysis = {
            "available": any(r.get("available") for r in present),
            "reason": next(
                (r.get("reason") for r in present
                 if not r.get("available") and r.get("reason")), None
            ),
            "version": next((r.get("version") for r in present if r.get("version")), None),
            "rules": max((r.get("rules") or 0) for r in present),
            "findings": sum((r.get("findings") or 0) for r in present),
            "resolutions": sum((r.get("resolutions") or 0) for r in present),
            "key_sizes_resolved": sum((r.get("key_sizes_resolved") or 0) for r in present),
            "algorithms_resolved": sum((r.get("algorithms_resolved") or 0) for r in present),
            "curves_resolved": sum((r.get("curves_resolved") or 0) for r in present),
            "defaults_corrected": sum((r.get("defaults_corrected") or 0) for r in present),
            "evidence_added": sum((r.get("evidence_added") or 0) for r in present),
            "scans_with_dataflow": sum(1 for r in present if r.get("available")),
            "scans_total": len(sets),
        }

    return ScanResult(
        summary=summary,
        artefacts=artefacts,
        risk_assessments=risks,
        recommendations=recs,
        raw_evidences=[],
        migration_plan=build_migration_plan(artefacts, risks),
    )


def resolve_scan(
    scan_id: str,
    mosca_z: Optional[float] = None,
    scope: str = "own",
) -> ScanResult:
    """
    Load a stored scan, or build the merged view when given the merged id.

    Every scan-addressed route goes through this so exports, recalculation and
    detail all work identically for "All scans".
    """
    if scan_id == MERGED_SCAN_ID:
        return build_merged_scan(mosca_z=mosca_z, scope=scope)

    raw = storage_manager.get_scan_result(scan_id, scope=scope)
    if not raw:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult.model_validate(raw)


# --- SYSTEM & CONFIG ENDPOINTS ---
@app.get("/api/status")
def get_system_status():
    """Returns platform metadata, problem statement info, and database status."""
    return {
        "tool_name": config.app_name,
        "problem_statement_id": config.problem_statement_id,
        "organization": config.organization,
        "database_status": storage_manager.get_status().model_dump(),
        "storage_mode": "mongodb" if storage_manager.config.is_connected else "local",
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


class VulnerabilityLookupRequest(BaseModel):
    enabled: bool


@app.get("/api/config/vulnerability-lookup")
def get_vulnerability_lookup_setting():
    """Whether scans check published advisories. Off by default — it needs the network."""
    cache = os.path.join(config.storage_dir, "osv_cache.json")
    cached_packages = 0
    if os.path.exists(cache):
        try:
            with open(cache, "r", encoding="utf-8") as f:
                cached_packages = len(json.load(f))
        except Exception:
            cached_packages = 0
    return {
        "enabled": config.vulnerability_lookup_enabled,
        "source": "OSV (osv.dev)",
        "cached_packages": cached_packages,
    }


@app.post("/api/config/vulnerability-lookup")
def set_vulnerability_lookup_setting(req: VulnerabilityLookupRequest):
    """
    Enable or disable the lookup.

    Held in memory for this process: it changes whether a scan reaches the
    network, which should be a deliberate choice each session rather than a
    setting that silently persists.
    """
    config.vulnerability_lookup_enabled = req.enabled
    return {"enabled": config.vulnerability_lookup_enabled}


class DataflowRequest(BaseModel):
    enabled: bool


def _dataflow_status() -> Dict[str, Any]:
    from backend.scanners import opengrep_engine

    return {
        "enabled": config.dataflow_analysis_enabled,
        "available": opengrep_engine.is_available(),
        "reason": opengrep_engine.unavailable_reason(),
        "engine": "OpenGrep",
        "version": opengrep_engine.version(),
        "rules": opengrep_engine.rule_count(),
        "binary_present": opengrep_engine.binary_path() is not None,
        # Stated explicitly because it is the whole reason this engine was chosen
        # over CodeQL or a SonarQube plugin.
        "offline": True,
    }


@app.get("/api/config/sensitivity-profiles")
def get_sensitivity_profiles():
    """
    The data-sensitivity profiles a scan can be run under, and the retention
    period each one implies.

    Served rather than hardcoded in the UI so the retention figures have exactly
    one definition. X in Mosca's inequality is a property of the data, and this
    is where the tool states what it believes about each class of it.
    """
    lo, hi, provenance = crqc_probability_within(10.0)
    return {
        "default": DataSensitivityProfile.FINANCIAL.value,
        "profiles": [
            {
                "value": profile.value,
                "label": PROFILE_LABELS[profile],
                "retention_years": PROFILE_RETENTION_YEARS[profile],
            }
            for profile in DataSensitivityProfile
        ],
        "threat_horizon": {
            "default_z_years": config.default_mosca_z,
            "crqc_within_10_years": {"low": lo, "high": hi, "provenance": provenance},
            "source": CRQC_CURVE_SOURCE,
        },
    }


@app.get("/api/config/dataflow")
def get_dataflow_setting():
    """
    State of the Tier 4 dataflow pass.

    Reported even when it is working, because a reviewer needs to know whether the
    key sizes in a scan were measured or assumed, and that depends on whether this
    ran.
    """
    return _dataflow_status()


@app.post("/api/config/dataflow")
def set_dataflow_setting(req: DataflowRequest):
    """
    Enable or disable dataflow resolution for subsequent scans.

    Unlike the advisory lookup this reaches no network, so it is on by default.
    It is switchable only because it spawns a subprocess with a fixed start-up
    cost, which is worth avoiding when repeatedly scanning a very large tree.
    Turning it off means parameters passed through helpers revert to assumed
    defaults, which the scan then says in its coverage notes.
    """
    config.dataflow_analysis_enabled = req.enabled
    return _dataflow_status()


@app.post("/api/config/db")
def configure_enterprise_db(req: DBConfigRequest):
    """
    Attach an optional MongoDB instance for shared/cross-machine storage.

    This is purely a storage choice. No analysis feature depends on it.
    """
    return storage_manager.configure_mongo(
        req.mongo_uri, req.database_name or "ecdat_enterprise_inventory"
    )


@app.get("/api/config/db")
def get_enterprise_db_status():
    """Retrieve current DB connection state."""
    return storage_manager.get_status()


# --- GIT REPOSITORY CLONE & SCAN ---
@app.post("/api/scan/git")
def scan_git_repository(req: GitScanRequest):
    """
    Clone and scan a remote Git repository.

    Returns a job id immediately; poll /api/scan/jobs/{job_id} for progress.
    """
    if not shutil.which("git"):
        raise HTTPException(
            status_code=400,
            detail="Git is not installed or not on PATH. Install Git, or use "
                   "'Upload archive' to scan a .zip of the repository instead.",
        )

    repo_url = req.repo_url.strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required.")

    target_title = req.target_name or os.path.basename(repo_url.rstrip("/")).replace(".git", "")
    job = job_registry.create(f"Git: {target_title}")

    def work(j: ScanJob) -> ScanResult:
        # Clone into the OS temp area, not data_store. Keeping transient
        # working copies out of the persistent store means a scan of the
        # project directory can never pick up another scan's scratch files.
        temp_dir = tempfile.mkdtemp(prefix="ecdat_clone_")

        clone_url = repo_url
        if req.auth_token and clone_url.startswith("https://"):
            clone_url = f"https://{req.auth_token}@{clone_url[8:]}"

        def redact(text: str) -> str:
            """Never echo a personal access token back into the UI or logs."""
            return text.replace(req.auth_token, "***") if req.auth_token else text

        try:
            j.set_phase("Enumerating files")
            base_cmd = ["git", "clone", "--depth", "1", "--single-branch"]

            if req.branch:
                j.log(f"Cloning branch '{req.branch}'...")
                result = subprocess.run(
                    base_cmd + ["--branch", req.branch, clone_url, temp_dir],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode != 0:
                    # A wrong branch name used to fall back to the default branch
                    # silently, so the user scanned something they did not ask for.
                    raise Exception(
                        f"Could not clone branch '{req.branch}'. "
                        f"Check the branch name. Git reported: "
                        f"{redact(result.stderr.strip()) or 'unknown error'}"
                    )
            else:
                j.log("Cloning default branch...")
                result = subprocess.run(
                    base_cmd + [clone_url, temp_dir],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode != 0:
                    raise Exception(
                        f"Git clone failed: {redact(result.stderr.strip()) or 'unknown error'}"
                    )

            j.log("Clone complete. Starting discovery.")
            evidences, stats, dataflow = run_all_scanners(temp_dir, TargetType.MULTI_TARGET, job=j)

            # Report paths relative to the repository, not the scratch directory.
            prefix = temp_dir.replace("\\", "/").rstrip("/") + "/"
            for ev in evidences:
                if ev.file_path.startswith(prefix):
                    ev.file_path = ev.file_path[len(prefix):]

            return execute_pipeline(
                target_name=f"Git: {target_title}",
                target_type=TargetType.MULTI_TARGET,
                raw_evidences=evidences,
                mosca_z=req.mosca_z or 8.0,
                job=j,
                scan_stats=stats,
                dataflow=dataflow,
                sensitivity_profile=req.sensitivity_profile,
                retention_override=req.retention_override_years,
            )
        finally:
            # Cloned source is purged from disk as soon as the CBOM is built.
            shutil.rmtree(temp_dir, ignore_errors=True)

    job_registry.run(job, work)
    return {"job_id": job.job_id}


# --- CI/CD PIPELINE TRIGGER ---
@app.post("/api/scan/cicd")
def trigger_cicd_scan(req: ScanPathRequest):
    """
    Synchronous scan endpoint for CI/CD automation.

    Runs inline (no job polling) because pipeline runners want one blocking call,
    and returns a non-zero-worthy summary the caller can gate a build on.
    """
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail=f"Target path does not exist on runner: {req.path}")

    evidences, stats, dataflow = run_all_scanners(req.path, req.target_type)
    result = execute_pipeline(
        target_name=f"CI/CD: {req.target_name}",
        target_type=req.target_type,
        raw_evidences=evidences,
        mosca_z=req.mosca_z or 8.0,
        scan_stats=stats,
        dataflow=dataflow,
        sensitivity_profile=req.sensitivity_profile,
        retention_override=req.retention_override_years,
    )
    critical = result.summary.risk_distribution.get("Critical", 0)
    high = result.summary.risk_distribution.get("High", 0)
    return {
        "scan_id": result.summary.scan_id,
        "total_artefacts": result.summary.total_artefacts,
        "critical": critical,
        "high": high,
        "quantum_readiness_score": result.summary.quantum_readiness_score,
        "gate": "fail" if critical > 0 else ("warn" if high > 0 else "pass"),
    }


# --- LOCAL DIRECTORY / FILE SCAN ---
@app.post("/api/scan/path")
def scan_path(req: ScanPathRequest):
    """Scan a local directory or file. Returns a job id; poll for progress."""
    target = req.path  # already normalised by ScanPathRequest
    if not target:
        raise HTTPException(status_code=400, detail="Enter a folder or file path to scan.")
    if not os.path.exists(target):
        # Name the parent when it exists, so a typo in the last segment is
        # obvious rather than the whole path just being "not found".
        parent = os.path.dirname(target)
        hint = ""
        if parent and os.path.isdir(parent):
            hint = f" The folder {parent} exists, but it contains no entry named '{os.path.basename(target)}'."
        raise HTTPException(status_code=400, detail=f"Path not found: {target}.{hint}")

    job = job_registry.create(req.target_name or os.path.basename(target.rstrip("/\\")) or target)

    def work(j: ScanJob) -> ScanResult:
        evidences, stats, dataflow = run_all_scanners(target, req.target_type, job=j)
        return execute_pipeline(
            target_name=j.target_name,
            target_type=req.target_type,
            raw_evidences=evidences,
            mosca_z=req.mosca_z or 8.0,
            job=j,
            scan_stats=stats,
            dataflow=dataflow,
            sensitivity_profile=req.sensitivity_profile,
            retention_override=req.retention_override_years,
        )

    job_registry.run(job, work)
    return {"job_id": job.job_id}


# --- FILE & ZIP UPLOAD SCAN ---
@app.post("/api/scan/upload")
async def scan_uploaded_file(
    file: UploadFile = File(...),
    target_name: str = Form("Uploaded Asset"),
    target_type: TargetType = Form(TargetType.MULTI_TARGET),
    mosca_z: float = Form(8.0),
    sensitivity_profile: DataSensitivityProfile = Form(DataSensitivityProfile.FINANCIAL),
    retention_override_years: Optional[float] = Form(None),
):
    """Upload and scan a file, or a .zip archive of a whole repository."""
    upload_dir = tempfile.mkdtemp(prefix="ecdat_upload_")
    temp_file_path = os.path.join(upload_dir, os.path.basename(file.filename or "upload"))

    # The upload must be consumed before the request returns, so the bytes are
    # written here and the analysis continues on a worker.
    with open(temp_file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    filename = os.path.basename(file.filename or "upload")
    display_name = target_name or filename.replace(".zip", "")
    job = job_registry.create(display_name)

    def work(j: ScanJob) -> ScanResult:
        unzip_dir = None
        try:
            if filename.lower().endswith(".zip"):
                unzip_dir = os.path.join(upload_dir, "extracted")
                os.makedirs(unzip_dir, exist_ok=True)
                j.set_phase("Enumerating files")
                j.log(f"Extracting {filename}...")
                with zipfile.ZipFile(temp_file_path, "r") as zf:
                    _safe_extract(zf, unzip_dir)
                evidences, stats, dataflow = run_all_scanners(unzip_dir, TargetType.MULTI_TARGET, job=j)
                prefix = unzip_dir.replace("\\", "/").rstrip("/") + "/"
                for ev in evidences:
                    if ev.file_path.startswith(prefix):
                        ev.file_path = ev.file_path[len(prefix):]
                scan_type = TargetType.MULTI_TARGET
            else:
                evidences, stats, dataflow = run_all_scanners(temp_file_path, target_type, job=j)
                for ev in evidences:
                    ev.file_path = filename
                scan_type = target_type

            return execute_pipeline(
                target_name=display_name,
                target_type=scan_type,
                raw_evidences=evidences,
                mosca_z=mosca_z,
                job=j,
                scan_stats=stats,
                dataflow=dataflow,
                sensitivity_profile=sensitivity_profile,
                retention_override=retention_override_years,
            )
        finally:
            # Remove the whole scratch directory: the upload and anything
            # extracted from it.
            shutil.rmtree(upload_dir, ignore_errors=True)

    job_registry.run(job, work)
    return {"job_id": job.job_id}


def _safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    """
    Extract a zip, refusing entries that escape the destination directory.

    A plain extractall() honours '../' and absolute paths inside the archive,
    letting an uploaded file write anywhere the process can reach.
    """
    dest_abs = os.path.abspath(dest)
    for member in zf.infolist():
        target = os.path.abspath(os.path.join(dest, member.filename))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            raise Exception(f"Archive contains an unsafe path and was rejected: {member.filename}")
    zf.extractall(dest)


# --- JOB PROGRESS ---
@app.get("/api/scan/jobs/{job_id}")
def get_scan_job(job_id: str):
    """Progress for a running scan. Reflects files actually read."""
    job = job_registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found or expired.")
    return job.snapshot()


@app.get("/api/scan/jobs/{job_id}/result")
def get_scan_job_result(job_id: str):
    """The finished ScanResult for a completed job."""
    job = job_registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found or expired.")
    if job.state == JobState.FAILED:
        raise HTTPException(status_code=500, detail=job.error or "Scan failed.")
    if job.state != JobState.COMPLETED or job.result is None:
        raise HTTPException(status_code=409, detail=f"Scan is {job.state.value}, not complete.")
    return job.result


@app.post("/api/scan/jobs/{job_id}/cancel")
def cancel_scan_job(job_id: str):
    """Stop a running scan at the next file boundary."""
    job = job_registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found or expired.")
    job.cancel()
    return {"job_id": job_id, "state": "cancelling"}


# --- SCAN MANAGEMENT & EXPORTS ---
@app.get("/api/scans")
def list_scans(scope: str = Depends(read_scope)):
    return storage_manager.list_all_scans(scope=scope)


@app.get("/api/scans/merged")
def get_merged_scan(
    mosca_z: Optional[float] = Query(None, ge=0.5, le=30.0),
    scope: str = Depends(read_scope),
):
    """
    Every stored scan unioned into one inventory.

    Declared before /api/scans/{scan_id} so the literal path wins over the
    parameter.
    """
    return build_merged_scan(mosca_z=mosca_z, scope=scope)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, scope: str = Depends(read_scope)):
    if scan_id == MERGED_SCAN_ID:
        return build_merged_scan(scope=scope)
    result = storage_manager.get_scan_result(scan_id, scope=scope)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, scope: str = Depends(read_scope)):
    """Remove a stored scan."""
    if scan_id == MERGED_SCAN_ID:
        raise HTTPException(
            status_code=400,
            detail="The combined view is derived from the stored scans and cannot be deleted.",
        )
    if not storage_manager.delete_scan_result(scan_id, scope=scope):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


@app.post("/api/scans/{scan_id}/recalculate")
def recalculate_mosca(
    scan_id: str, req: RecalculateRequest, scope: str = Depends(read_scope)
):
    """
    Re-evaluate Mosca risk against a different CRQC horizon Z.

    Non-destructive by default: the response is a projection, and the stored
    scan keeps the Z it was audited at unless persist=true.
    """
    if not 0.5 <= req.mosca_z <= 30.0:
        raise HTTPException(status_code=400, detail="Z must be between 0.5 and 30 years.")

    # The merged view is derived, not stored: it recalculates freely and can
    # never be persisted.
    if scan_id == MERGED_SCAN_ID:
        return build_merged_scan(mosca_z=req.mosca_z, scope=scope)

    result_dict = storage_manager.get_scan_result(scan_id, scope=scope)
    if not result_dict:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_result = ScanResult.model_validate(result_dict)
    new_z = req.mosca_z

    # A profile change re-derives X for every asset, so the artefacts have to be
    # re-prepared rather than reassessed with their stored numbers.
    new_profile = req.sensitivity_profile or scan_result.summary.sensitivity_profile
    new_retention = (
        req.retention_override_years
        if req.retention_override_years is not None
        else scan_result.summary.retention_override_years
    )
    profile_changed = (
        new_profile != scan_result.summary.sensitivity_profile
        or new_retention != scan_result.summary.retention_override_years
    )
    if profile_changed:
        scan_result.artefacts = QuantumRiskEngine.prepare_all(
            scan_result.artefacts, new_profile, new_retention
        )

    new_risks = QuantumRiskEngine.evaluate_all(
        scan_result.artefacts, global_z=new_z,
        profile=new_profile, retention_override=new_retention,
    )
    new_recs = RecommendationEngine.generate_all(
        scan_result.artefacts, new_risks, profile=new_profile
    )
    scan_result.migration_plan = build_migration_plan(
        scan_result.artefacts, new_risks
    )

    scan_result.summary = build_summary(
        scan_id=scan_result.summary.scan_id,
        target_name=scan_result.summary.target_name,
        target_type=scan_result.summary.target_types[0] if scan_result.summary.target_types else TargetType.MULTI_TARGET,
        artefacts=scan_result.artefacts,
        risk_assessments=new_risks,
        mosca_z=new_z,
        created_at=scan_result.summary.created_at,
        sensitivity_profile=new_profile,
        retention_override=new_retention,
    )
    # Carry forward facts about the original traversal; they describe the scan,
    # not the risk model being re-applied.
    original = result_dict.get("summary", {})
    scan_result.summary.files_scanned = original.get("files_scanned", 0)
    scan_result.summary.coverage_notes = original.get("coverage_notes", [])
    scan_result.summary.total_occurrences = original.get(
        "total_occurrences", scan_result.summary.total_occurrences
    )
    scan_result.risk_assessments = new_risks
    scan_result.recommendations = new_recs

    if req.persist:
        storage_manager.save_scan_result(scan_result)

    return scan_result


@app.get("/api/scans/{scan_id}/compare/{other_scan_id}")
def compare_two_scans(
    scan_id: str,
    other_scan_id: str,
    scope: str = Depends(read_scope),
):
    """
    What changed between two scans.

    `scan_id` is the earlier one and `other_scan_id` the later, so the URL reads
    in the direction the comparison runs. Both are resolved through the ordinary
    scope, so a scan this caller cannot see cannot be compared against either.
    """
    if MERGED_SCAN_ID in (scan_id, other_scan_id):
        raise HTTPException(
            status_code=400,
            detail="The combined view is derived from the stored scans and "
                   "changes whenever any of them does, so comparing it says "
                   "nothing about a single system.",
        )
    if scan_id == other_scan_id:
        raise HTTPException(
            status_code=400, detail="A scan compared with itself has no changes."
        )

    before = resolve_scan(scan_id, scope=scope)
    after = resolve_scan(other_scan_id, scope=scope)
    return compare_scans(before, after)


@app.get("/api/scans/{scan_id}/migration-plan")
def get_migration_plan(
    scan_id: str,
    capacity: Optional[int] = Query(
        None, ge=1, le=10000,
        description="How many migrations the organisation can run at once. "
                    "Omitted means wave sizes are not checked against capacity, "
                    "and the plan says so rather than assuming a number.",
    ),
):
    """
    The per-asset deadlines grouped into schedulable waves.

    Rebuilt on request rather than served from the stored copy, so that stating
    a concurrency capacity re-evaluates the plan without rewriting the scan.
    """
    scan = resolve_scan(scan_id)
    return build_migration_plan(
        scan.artefacts, scan.risk_assessments, parallel_capacity=capacity
    )


@app.get("/api/scans/{scan_id}/cbom")
def export_cbom(scan_id: str):
    scan_result = resolve_scan(scan_id)
    cbom_json = ReportGenerator.generate_cyclonedx_json(scan_result)
    return Response(
        content=cbom_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cyclonedx_cbom_{scan_id}.json"},
    )


@app.get("/api/scans/{scan_id}/report/html")
def export_html_report(scan_id: str):
    scan_result = resolve_scan(scan_id)
    html_content = ReportGenerator.generate_html_report(scan_result)
    return HTMLResponse(content=html_content)


@app.get("/api/scans/{scan_id}/report/csv")
def export_csv_report(scan_id: str):
    scan_result = resolve_scan(scan_id)
    csv_content = ReportGenerator.generate_csv_report(scan_result)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ecdat_report_{scan_id}.csv"},
    )


# --- ADMIN PANEL & AUTHENTICATION ---
#
# Signing in does not change what the tool does. It changes what it can see:
# every asset in every stored scan becomes queryable as one estate, instead of
# one scan at a time. Everything else behaves exactly as it does signed out.

def require_admin(authorization: Optional[str] = Header(None)) -> str:
    """Gate a route behind a live admin session."""
    token = bearer_token(authorization)
    if not admin_sessions.is_valid(token):
        raise HTTPException(
            status_code=401,
            detail="Admin session required, or the session has expired.",
        )
    return token


@app.get("/api/admin/status")
def get_admin_status(authorization: Optional[str] = Header(None)):
    """
    Whether an admin password exists, and whether this caller holds a session.

    The second half lets the UI restore an admin session after a reload without
    asking for the password again, and lets it drop the badge the moment the
    session has actually lapsed rather than when a later request happens to fail.
    """
    return {
        "is_setup": storage_manager.is_admin_setup(),
        "is_authenticated": admin_sessions.is_valid(bearer_token(authorization)),
        "is_cloud_connected": storage_manager.config.is_connected,
        "database_name": (
            storage_manager.config.database_name
            if storage_manager.config.is_connected
            else "Local file storage"
        ),
        "lockout_seconds_remaining": admin_sessions.lockout_remaining(),
    }


@app.post("/api/admin/setup")
def setup_admin_account(req: AdminSetupRequest):
    """First-time setup: stores a salted PBKDF2 hash."""
    if storage_manager.is_admin_setup():
        raise HTTPException(status_code=400, detail="Admin password has already been established.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    if not storage_manager.setup_admin_password(req.password):
        raise HTTPException(status_code=500, detail="Failed to store admin password.")

    token, ttl = admin_sessions.issue()
    return {
        "success": True, "token": token, "expires_in": ttl,
        "message": "Admin password created.",
    }


@app.post("/api/admin/login")
def login_admin(req: AdminLoginRequest):
    """Verify the password, with a growing delay after repeated failures."""
    if not storage_manager.is_admin_setup():
        raise HTTPException(status_code=400, detail="Admin account is not yet configured.")

    locked = admin_sessions.lockout_remaining()
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {locked} seconds.",
        )

    if not storage_manager.verify_admin_password(req.password):
        delay = admin_sessions.record_failure()
        detail = "Invalid admin password."
        if delay:
            detail += f" Further attempts are locked for {delay} seconds."
        raise HTTPException(status_code=401, detail=detail)

    admin_sessions.record_success()
    token, ttl = admin_sessions.issue()
    return {"success": True, "token": token, "expires_in": ttl}


@app.post("/api/admin/logout")
def logout_admin(req: AdminLoginRequest, authorization: Optional[str] = Header(None)):
    """
    Leave admin mode.

    The password is required to leave as well as to enter, so that an unlocked
    session cannot be closed by someone who does not hold the credential —
    dropping the estate out of view is itself a change of state. Restarting the
    application also ends every session, which is the way out if the password
    is genuinely unavailable.
    """
    token = bearer_token(authorization)
    if not admin_sessions.is_valid(token):
        # Already out. Saying so is not an information leak and avoids leaving
        # a stale client wedged.
        return {"success": True, "already_signed_out": True}

    locked = admin_sessions.lockout_remaining()
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {locked} seconds.",
        )

    if not storage_manager.verify_admin_password(req.password):
        delay = admin_sessions.record_failure()
        detail = "Incorrect password. Admin mode has not been exited."
        if delay:
            detail += f" Further attempts are locked for {delay} seconds."
        raise HTTPException(status_code=401, detail=detail)

    admin_sessions.record_success()
    return {"success": admin_sessions.revoke(token)}


@app.get("/api/admin/overview")
def get_admin_overview(_: str = Depends(require_admin)):
    """Aggregated metrics across every stored scan."""
    return storage_manager.get_enterprise_aggregated_metrics(
        scope=storage_manager.SCOPE_ALL
    )


# The previous name for the same thing. Kept so a client that has not been
# rebuilt still works.
@app.get("/api/admin/dashboard")
def get_admin_dashboard(_: str = Depends(require_admin)):
    return storage_manager.get_enterprise_aggregated_metrics(
        scope=storage_manager.SCOPE_ALL
    )


@app.get("/api/admin/artefacts")
def get_admin_artefacts(
    _: str = Depends(require_admin),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("risk"),
    risk_category: Optional[str] = Query(None),
    system_name: Optional[str] = Query(None),
    algorithm_family: Optional[str] = Query(None),
    quantum_vulnerability: Optional[str] = Query(None),
    overdue_only: bool = Query(False),
    search: Optional[str] = Query(None),
):
    """
    One page of every cryptographic asset across every stored scan.

    Distinct from the merged view at /api/scans/ALL, which deduplicates assets
    so the same library in two systems counts once. This does not: an estate
    register has to show both rows, because they are two things to fix.
    """
    return storage_manager.query_artefacts(
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        risk_category=risk_category,
        system_name=system_name,
        algorithm_family=algorithm_family,
        quantum_vulnerability=quantum_vulnerability,
        overdue_only=overdue_only,
        search=search,
        scope=storage_manager.SCOPE_ALL,
    )


@app.get("/api/admin/facets")
def get_admin_facets(_: str = Depends(require_admin)):
    """The filter values that actually occur in the estate."""
    return storage_manager.artefact_facets(scope=storage_manager.SCOPE_ALL)


@app.post("/api/admin/reindex")
def rebuild_admin_register(_: str = Depends(require_admin)):
    """
    Re-project every stored scan into the artefact register.

    Needed once after attaching a database that already holds scans written
    before the register existed. Without a database the register is derived on
    read, so there is nothing to rebuild and the response says so.
    """
    if not storage_manager.config.is_connected:
        return {
            "indexed": 0,
            "message": "No database attached. The estate view reads the local "
                       "scan files directly, so there is no index to rebuild.",
        }
    indexed = storage_manager.rebuild_artefact_register()
    return {"indexed": indexed, "message": f"{indexed} asset rows reindexed."}


# --- SERVE COMPILED FRONTEND ---
if getattr(sys, "frozen", False):
    _base = sys._MEIPASS
else:
    _base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

dist_path = os.path.join(_base, "frontend", "dist")

if os.path.exists(dist_path):
    assets_path = os.path.join(dist_path, "assets")
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API endpoint not found")
        # Resolve inside dist only; a crafted path must not escape it.
        candidate = os.path.abspath(os.path.join(dist_path, full_path))
        if candidate.startswith(os.path.abspath(dist_path)) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(dist_path, "index.html"))
