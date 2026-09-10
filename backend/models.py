from typing import List, Dict, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field
from datetime import date, datetime


class TargetType(str, Enum):
    SOURCE_CODE = "source_code"
    BINARY = "binary"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    MULTI_TARGET = "multi_target"


class ArtefactType(str, Enum):
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    HARDWARE_MODULE = "hardware_module"
    CLOUD_SERVICE = "cloud_service"


class AlgorithmClass(str, Enum):
    ASYMMETRIC_FACTORING = "asymmetric_factoring"       # RSA, DSA
    ASYMMETRIC_DISCRETE_LOG = "asymmetric_discrete_log" # DH, ECDH, ECDSA
    SYMMETRIC = "symmetric"                             # AES, ChaCha20, 3DES, DES
    HASH = "hash"                                       # SHA-2, SHA-3, SHA-1, MD5
    POST_QUANTUM = "post_quantum"                       # ML-KEM, ML-DSA, SLH-DSA
    HYBRID = "hybrid"                                   # X25519+ML-KEM-768, etc.
    LEGACY_BROKEN = "legacy_broken"                     # MD5, SHA-1, DES, RC4
    # The primitive could not be identified from the evidence — a bare key file,
    # a certificate, an HSM reference. Defaulting these to SYMMETRIC made the
    # recommendation engine propose "migrate to AES-256-GCM" for a private key.
    UNKNOWN = "unknown"


class QuantumVulnerabilityStatus(str, Enum):
    FULLY_BROKEN = "fully_broken"         # Shor's (RSA, ECC, DH)
    DEGRADED = "degraded"                 # Grover's (AES-128, SHA-256)
    CLASSICALLY_BROKEN = "classically_broken" # MD5, SHA-1, DES, RSA-1024
    QUANTUM_SAFE = "quantum_safe"         # FIPS 203/204/205, AES-256
    HYBRID_PROTECTED = "hybrid_protected" # Hybrid classical + PQC
    # The algorithm behind this asset could not be determined — a key file, a
    # certificate or an HSM reference whose underlying primitive is not visible
    # in the evidence. Previously these silently defaulted to QUANTUM_SAFE, so
    # the inventory asserted that an unidentified private key was safe.
    UNKNOWN = "unknown"


class BusinessCriticality(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class RiskCategory(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class DataSensitivityProfile(str, Enum):
    """
    What class of data this scan's cryptography protects.

    X in Mosca's inequality is a property of the data, not of the algorithm, so
    it has to be stated rather than inferred from a primitive name. The scan
    carries one profile; individual assets can still be overridden.
    """
    SESSION = "session"
    GENERAL_BUSINESS = "general_business"
    FINANCIAL = "financial"
    PERSONAL_DATA = "personal_data"
    HEALTH = "health"
    GOVERNMENT = "government"
    NATIONAL_SECURITY = "national_security"


class CryptoUsage(str, Enum):
    """
    What an asset is for. Decides which definition of X applies to it.

    Confidentiality and key transport are exposed to harvest-now-decrypt-later
    and inherit the retention period of the data. Authenticity and integrity are
    not: a forged signature is only useful while the credential behind it is
    still trusted, so X is a validity window instead.
    """
    CONFIDENTIALITY = "confidentiality"
    KEY_TRANSPORT = "key_transport"
    AUTHENTICITY = "authenticity"
    INTEGRITY = "integrity"
    UNKNOWN = "unknown"


class RiskModel(str, Enum):
    """Which of the four models produced a given verdict."""
    MOSCA = "mosca"                    # X + Y > Z, deterministic
    PROBABILISTIC = "probabilistic"    # P(CRQC before migration completes)
    REGULATORY = "regulatory"          # fixed standards deadline, no estimation
    HNDL = "hndl"                      # harvest-now-decrypt-later exposure window


class RegulatoryDeadline(BaseModel):
    """A fixed date on which a primitive stops being permitted."""
    authority: str
    deprecated_on: Optional[date] = None
    disallowed_on: Optional[date] = None
    requirement: str
    # CNSA 2.0 binds national security systems only. A deadline that does not
    # apply to the organisation being scanned must not be reported as if it did.
    applies_only_to_nss: bool = False


class LatencyRequirement(str, Enum):
    ULTRA_LOW = "ultra_low"   # < 1ms
    LOW = "low"               # < 10ms
    STANDARD = "standard"     # Standard networking


class CostConsideration(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RawEvidence(BaseModel):
    id: str
    target_type: TargetType
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    snippet: Optional[str] = None
    matched_pattern: str
    raw_type: str
    detected_name: str
    version_or_mode: Optional[str] = None
    key_length: Optional[int] = None
    curve_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnownVulnerability(BaseModel):
    """
    A published advisory affecting a dependency version.

    Distinct from quantum risk: this is a present-day defect in a specific
    release, whereas the Mosca bands describe exposure to a future quantum
    adversary. The two are reported side by side and never merged — a library
    can be perfectly quantum-safe and still have a critical CVE, or vice versa.
    """
    id: str
    summary: str = ""
    severity: str = "Unknown"
    aliases: List[str] = Field(default_factory=list)
    fixed_version: Optional[str] = None
    reference_url: Optional[str] = None


class ArtefactOccurrence(BaseModel):
    """One place a cryptographic asset was observed."""
    location: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None


class CryptographicArtefact(BaseModel):
    id: str
    name: str
    type: ArtefactType
    algorithm_family: str
    mode_or_padding: Optional[str] = None
    key_size_bits: Optional[int] = None
    curve: Optional[str] = None
    version: Optional[str] = None
    location: str
    line_number: Optional[int] = None
    target_type: TargetType
    algorithm_class: AlgorithmClass
    quantum_vulnerability: QuantumVulnerabilityStatus
    broken_by: Optional[str] = None # e.g., "Shor's Algorithm", "Grover's Algorithm"
    
    # Classification Attributes
    business_criticality: BusinessCriticality = BusinessCriticality.MEDIUM
    data_shelf_life_years: float = 7.0 # X input for Mosca
    migration_time_years: float = 2.0  # Y input for Mosca
    artefact_lifetime: str = "Standard (3-5 years)"

    # What this asset is for, and how X and Y above were arrived at.
    #
    # X and Y are no longer constants looked up from the algorithm name. X comes
    # from the scan's data-sensitivity profile via the usage below; Y is computed
    # from the evidence — who owns the code, how many sites, what has to be
    # negotiated. Both record their working so a reviewer can take the number
    # apart instead of having to trust it.
    crypto_usage: CryptoUsage = CryptoUsage.UNKNOWN
    shelf_life_rationale: Optional[str] = None
    migration_time_breakdown: Optional[Dict[str, Any]] = None
    # Set when an operator has overridden X for this specific asset, so a manual
    # judgement is never silently recomputed away.
    shelf_life_override_years: Optional[float] = None
    # The validity window actually read off the artefact — currently only
    # certificates, which state it. For an authenticity asset X *is* that
    # window, so a measured figure replaces the conventional default. Distinct
    # from an operator override: this is observed, not decided.
    measured_validity_years: Optional[float] = None

    # How replaceable this asset is, in the sense NIST CSWP 39 uses: can the
    # algorithm be swapped without disrupting what depends on it? Reported with
    # every factor so the number can be argued with rather than trusted.
    agility_score: Optional[float] = None
    agility_band: Optional[str] = None
    agility_factors: Optional[Dict[str, Any]] = None
    agility_summary: Optional[str] = None
    
    # Hardware / Cloud references
    hardware_module_ref: Optional[str] = None # e.g. "PKCS#11 HSM Slot 1"
    cloud_service_ref: Optional[str] = None   # e.g. "AWS KMS alias/prod-key"
    
    # Code snippet / evidence
    code_snippet: Optional[str] = None
    confidence_score: float = 0.95

    # How the parameters above — key size, curve, mode — were arrived at:
    #
    #   "dataflow"  the literal reaching the argument was traced across function
    #               boundaries and read directly (Tier 4)
    #   "literal"   read from the call site itself by the AST scanner (Tier 1)
    #   "assumed"   no value was readable, so a conventional default was used
    #
    # Recorded because the key size drives the X in Mosca's inequality and the
    # risk band that follows from it. A reviewer has to be able to tell a measured
    # 1024 from an assumed 2048 without re-reading the source.
    parameter_source: Optional[str] = None

    # Every place this same asset was observed. Populated by the aggregator, so
    # one RSA-2048 finding reported on eight lines is one artefact with eight
    # occurrences rather than eight artefacts.
    occurrences: List[ArtefactOccurrence] = Field(default_factory=list)
    occurrence_count: int = 1

    # Which scans this asset came from. Only populated in the merged "all scans"
    # view, where knowing an asset appears across several systems is the point.
    source_scans: List[str] = Field(default_factory=list)

    # Package URL — the canonical identifier for a dependency, and a first-class
    # CycloneDX field. Without it a CBOM names packages but cannot be consumed
    # by any vulnerability service.
    purl: Optional[str] = None
    # True when the manifest pinned a range rather than an exact version, so a
    # range-derived advisory match is never reported as certain.
    version_is_range: bool = False
    # Published advisories affecting this exact version, when the optional
    # lookup is enabled.
    known_vulnerabilities: List[KnownVulnerability] = Field(default_factory=list)


class ModelVerdict(BaseModel):
    """One risk model's opinion of one asset."""
    model: RiskModel
    at_risk: bool
    # Years of slack before work must begin. Negative means already overdue.
    slack_years: Optional[float] = None
    # The date migration must start, and the date it must be finished, for this
    # model's constraint to be met.
    must_start_by: Optional[date] = None
    must_complete_by: Optional[date] = None
    # Probability band, for the probabilistic model only.
    probability_low: Optional[float] = None
    probability_high: Optional[float] = None
    detail: str = ""
    source: Optional[str] = None


class MoscaRiskAssessment(BaseModel):
    artefact_id: str
    shelf_life_x: float
    migration_time_y: float
    threat_timeline_z: float
    x_plus_y: float
    is_at_risk: bool # X + Y > Z
    safety_margin_years: float # Z - (X + Y)
    risk_category: RiskCategory
    explanation: str
    affected_data_type: str
    system_exposure: str

    # ---------------------------------------------------------------- added
    # Mosca stays the headline above. These fields carry the other three models
    # and the schedule that falls out of them. All optional, so scans stored
    # before this existed still load.

    # Every model's verdict, and which one binds hardest.
    model_verdicts: List[ModelVerdict] = Field(default_factory=list)
    binding_model: Optional[RiskModel] = None

    # The schedule, from whichever model binds. This is the answer to "when do
    # we actually have to do this" — previously the tool only produced a band.
    must_start_by: Optional[date] = None
    must_complete_by: Optional[date] = None
    slack_years: Optional[float] = None
    is_overdue: bool = False

    # What the horizon means on a calendar, rather than "8 years from a run
    # whose date nobody recorded".
    assessed_on: Optional[date] = None
    crqc_estimated_on: Optional[date] = None

    # Probability that a CRQC exists before this asset's migration could finish.
    breach_probability_low: Optional[float] = None
    breach_probability_high: Optional[float] = None
    probability_source: Optional[str] = None

    # Years of harvest-now-decrypt-later exposure: how long data encrypted today
    # would still be sensitive after a CRQC arrives. Zero when not exposed.
    hndl_exposure_years: float = 0.0

    # How X and Y were derived, carried through for reporting.
    crypto_usage: CryptoUsage = CryptoUsage.UNKNOWN
    shelf_life_rationale: Optional[str] = None
    migration_time_explanation: Optional[str] = None


class PQCRecommendation(BaseModel):
    artefact_id: str
    current_algorithm: str
    recommended_standard: str # e.g. "NIST FIPS 203 (ML-KEM-768)"
    alternative_options: List[str] = Field(default_factory=list)
    is_hybrid_available: bool = True
    hybrid_recommendation: Optional[str] = None # e.g. "X25519 + ML-KEM-768"
    migration_urgency: str
    latency_impact: str
    estimated_migration_cost: CostConsideration
    migration_steps: List[str] = Field(default_factory=list)
    code_diff_example: Optional[str] = None

    # Why this target and not another. The parameter set follows from the
    # security level being replaced, so both the level and the reasoning are
    # carried rather than left implicit in a lookup table.
    # The standard the target comes from, kept apart from the target itself so
    # the inventory column can be the algorithm alone. "NIST FIPS 203
    # (ML-KEM-768)" in a table cell is a citation wearing a label's clothes.
    standard_reference: Optional[str] = None
    nist_category: Optional[int] = None
    replaces_classical_bits: Optional[int] = None
    selection_rationale: Optional[str] = None
    # Named releases that actually ship the algorithm today, chosen for the
    # language this asset was found in.
    implementation_targets: List[str] = Field(default_factory=list)
    # Stated explicitly because it is the most common wrong answer: liboqs is
    # an experimentation library, not a migration destination.
    not_a_migration_target: Optional[str] = None


class MigrationWave(BaseModel):
    """
    One band of work in the migration plan.

    Assets are grouped by when they have to start, not by what they are, so a
    wave is something a team can actually schedule: a window, a set of assets,
    and a deadline that the window either fits inside or does not.
    """
    sequence: int
    label: str
    rationale: str
    starts_on: Optional[date] = None
    must_complete_by: Optional[date] = None
    artefact_ids: List[str] = Field(default_factory=list)
    asset_count: int = 0
    # The longest single migration in this wave. Because work inside a wave
    # runs in parallel, this is the wave's own duration.
    longest_migration_years: float = 0.0

    # True when the longest job in the wave cannot finish by the wave's earliest
    # deadline even if it started on the wave's first day. Reported rather than
    # hidden: a plan that cannot be met is the most important thing to say.
    is_infeasible: bool = False
    shortfall_years: float = 0.0
    # Distinct from merely infeasible: the deadline itself is in the past, so
    # this is not a schedule to plan against but a breach to report. Rendering
    # it as a window would read as "2026 to 2023".
    deadline_already_passed: bool = False
    risk_distribution: Dict[str, int] = Field(default_factory=dict)


class MigrationPlan(BaseModel):
    generated_on: date
    waves: List[MigrationWave] = Field(default_factory=list)
    # The longest single migration anywhere in the inventory. Even with
    # unlimited parallelism the estate cannot be migrated faster than this.
    critical_path_years: float = 0.0
    # Assets whose own duration makes them the schedule's constraint — vendor
    # firmware, hardware procurement, upstream dependency releases. They have to
    # start first regardless of which wave their deadline puts them in.
    long_lead_artefact_ids: List[str] = Field(default_factory=list)
    # How many migrations the organisation can run at once. None means it was
    # not stated, and therefore not assessed — never silently assumed.
    parallel_capacity: Optional[int] = None
    notes: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    scan_id: str
    target_name: str
    target_types: List[TargetType]
    created_at: datetime
    total_artefacts: int
    risk_distribution: Dict[str, int]
    vulnerability_distribution: Dict[str, int]
    quantum_readiness_score: float # 0 - 100
    mosca_global_z: float = 8.0

    # Which installation produced this scan. A shared database is shared: this
    # is what lets an ordinary read return only this installation's own work,
    # and an unlocked admin session return everything.
    installation_id: Optional[str] = None

    # What class of data this estate protects, and therefore what X means here.
    # Defaults to the financial profile, whose 7-year retention is the value the
    # tool used as a blanket constant before X was derived from anything.
    sensitivity_profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL
    retention_override_years: Optional[float] = None

    # The horizon on a calendar. Z alone is meaningless without the date it was
    # counted from.
    assessed_on: Optional[date] = None
    crqc_estimated_on: Optional[date] = None

    # Schedule roll-up across the estate: the earliest date any asset must be
    # started, and how many are already past their start date.
    earliest_start_required: Optional[date] = None
    overdue_artefacts: int = 0
    # Longest single-asset migration in the inventory — the critical path if
    # everything else were done in parallel.
    longest_migration_years: float = 0.0
    # Estate-level crypto agility: the average score, how the bands are spread,
    # and how many assets are rigid enough to dominate any future migration
    # whatever the algorithm turns out to be.
    agility: Optional[Dict[str, Any]] = None

    # Total raw occurrences behind the distinct artefact count, so the UI can
    # say "42 assets across 318 occurrences" rather than conflating the two.
    total_occurrences: int = 0
    # How much ground the scan actually covered, and anything it had to skip.
    # Reported so coverage is never left implicit.
    files_scanned: int = 0
    coverage_notes: List[str] = Field(default_factory=list)

    # Outcome of the optional known-vulnerability lookup. Present whether it ran
    # or not, so "no advisories" is never confused with "not checked".
    vulnerability_lookup: Optional[Dict[str, Any]] = None
    total_known_vulnerabilities: int = 0

    # Outcome of the Tier 4 dataflow pass: how many parameters it resolved that
    # were not readable at their call site, and how many assumed defaults it
    # replaced. Present whether it ran or not — a scan with no dataflow analysis
    # reports key sizes as undetermined, and that has to be visible rather than
    # inferred from their absence.
    dataflow_analysis: Optional[Dict[str, Any]] = None


class ScanResult(BaseModel):
    summary: ScanSummary
    artefacts: List[CryptographicArtefact]
    risk_assessments: Dict[str, MoscaRiskAssessment] # Keyed by artefact_id
    recommendations: Dict[str, PQCRecommendation]   # Keyed by artefact_id
    raw_evidences: List[RawEvidence] = Field(default_factory=list)
    # The per-asset deadlines grouped into schedulable waves. Optional so scans
    # stored before the planner existed still load.
    migration_plan: Optional[MigrationPlan] = None


class DatabaseConfig(BaseModel):
    mongo_uri: str
    database_name: str = "ecdat_enterprise_inventory"
    is_connected: bool = False
    is_standalone_fallback: bool = False
    last_validated_at: Optional[datetime] = None
