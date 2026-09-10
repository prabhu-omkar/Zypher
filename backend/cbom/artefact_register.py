"""
The estate-wide artefact register.

Artefacts live inside their scan document, which is the right shape for "show me
this scan" and the wrong shape for "show me every RSA key across every system".
The previous answer to the second question was to load every scan document into
memory, flatten it, and return the whole estate in one response — which is why
the admin view could only ever be a page of counts.

This projects each artefact into a flat row that can be filtered, sorted and
paged. Under MongoDB the rows are a real indexed collection. Without MongoDB
they are derived from the stored scans on each query rather than kept in a
second local index: an index that can drift out of step with the truth it
summarises is worse than a slightly slower read, and an offline desktop install
holds tens of scans rather than millions.
"""
from typing import Any, Dict, List, Optional

# No query materialises more than this many matching rows. Reaching it is
# reported, so a truncated estate is never mistaken for a complete one.
MAX_MATCHED_ROWS = 20000

MAX_PAGE_SIZE = 500

_RISK_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Fields a free-text search looks through.
_SEARCH_FIELDS = (
    "name", "algorithm_family", "location", "system_name", "purl", "artefact_id",
)


def artefact_row(
    scan_summary: Dict[str, Any],
    artefact: Dict[str, Any],
    risk: Optional[Dict[str, Any]],
    rec: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Flatten one artefact and its assessment into a single queryable row."""
    risk = risk or {}
    rec = rec or {}
    scan_id = scan_summary.get("scan_id", "")
    return {
        "_id": f"{scan_id}:{artefact.get('id')}",
        "scan_id": scan_id,
        # Carried onto the row so the register can be scoped without joining
        # back to the scan document on every query.
        "installation_id": scan_summary.get("installation_id"),
        "system_name": scan_summary.get("target_name") or "Unknown system",
        "scanned_at": scan_summary.get("created_at"),
        "sensitivity_profile": scan_summary.get("sensitivity_profile"),

        "artefact_id": artefact.get("id"),
        "name": artefact.get("name"),
        "type": artefact.get("type"),
        "algorithm_family": artefact.get("algorithm_family"),
        "algorithm_class": artefact.get("algorithm_class"),
        "key_size_bits": artefact.get("key_size_bits"),
        "curve": artefact.get("curve"),
        "location": artefact.get("location"),
        "line_number": artefact.get("line_number"),
        "target_type": artefact.get("target_type"),
        "quantum_vulnerability": artefact.get("quantum_vulnerability"),
        "business_criticality": artefact.get("business_criticality"),
        "occurrence_count": artefact.get("occurrence_count", 1),
        "purl": artefact.get("purl"),
        "crypto_usage": artefact.get("crypto_usage"),
        "known_vulnerability_count": len(artefact.get("known_vulnerabilities") or []),

        "risk_category": risk.get("risk_category"),
        "shelf_life_x": risk.get("shelf_life_x"),
        "migration_time_y": risk.get("migration_time_y"),
        "threat_timeline_z": risk.get("threat_timeline_z"),
        "must_start_by": risk.get("must_start_by"),
        "must_complete_by": risk.get("must_complete_by"),
        "is_overdue": bool(risk.get("is_overdue")),
        "binding_model": risk.get("binding_model"),

        "recommended_standard": rec.get("recommended_standard"),
        "nist_category": rec.get("nist_category"),
        "migration_urgency": rec.get("migration_urgency"),
    }


def rows_for_scan(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every artefact in one stored scan, as register rows."""
    summary = data.get("summary", {})
    risks = data.get("risk_assessments") or {}
    recs = data.get("recommendations") or {}
    return [
        artefact_row(summary, art, risks.get(art.get("id")), recs.get(art.get("id")))
        for art in (data.get("artefacts") or [])
    ]


class ArtefactFilter:
    """The filters an estate query can carry, and how a row is tested."""

    def __init__(
        self,
        risk_category: Optional[str] = None,
        system_name: Optional[str] = None,
        algorithm_family: Optional[str] = None,
        quantum_vulnerability: Optional[str] = None,
        overdue_only: bool = False,
        search: Optional[str] = None,
    ):
        self.risk_category = risk_category
        self.system_name = system_name
        self.algorithm_family = algorithm_family
        self.quantum_vulnerability = quantum_vulnerability
        self.overdue_only = overdue_only
        self.search = (search or "").strip().lower()

    def as_mongo_query(self) -> Dict[str, Any]:
        """
        The part of this filter the database can do.

        Free-text search is deliberately left out and applied in `matches`, so
        that the two backends agree on what a search means rather than one using
        a regex and the other a substring.
        """
        query: Dict[str, Any] = {}
        for field, value in (
            ("risk_category", self.risk_category),
            ("system_name", self.system_name),
            ("algorithm_family", self.algorithm_family),
            ("quantum_vulnerability", self.quantum_vulnerability),
        ):
            if value:
                query[field] = value
        if self.overdue_only:
            query["is_overdue"] = True
        return query

    def matches(self, row: Dict[str, Any]) -> bool:
        if self.risk_category and row.get("risk_category") != self.risk_category:
            return False
        if self.system_name and row.get("system_name") != self.system_name:
            return False
        if self.algorithm_family and row.get("algorithm_family") != self.algorithm_family:
            return False
        if (self.quantum_vulnerability
                and row.get("quantum_vulnerability") != self.quantum_vulnerability):
            return False
        if self.overdue_only and not row.get("is_overdue"):
            return False
        if self.search:
            haystack = " ".join(
                str(row.get(f) or "") for f in _SEARCH_FIELDS
            ).lower()
            if self.search not in haystack:
                return False
        return True


def sort_key(sort_by: str):
    """
    How to order the estate.

    The default is risk first and then the nearest deadline — the order somebody
    triaging an estate actually works in.
    """
    sorts = {
        "risk": lambda r: (
            _RISK_RANK.get(r.get("risk_category"), 9),
            r.get("must_start_by") or "9999-12-31",
            r.get("name") or "",
        ),
        "deadline": lambda r: (
            r.get("must_start_by") or "9999-12-31",
            _RISK_RANK.get(r.get("risk_category"), 9),
        ),
        "system": lambda r: (r.get("system_name") or "", r.get("name") or ""),
        "name": lambda r: (r.get("name") or "",),
        "occurrences": lambda r: (-(r.get("occurrence_count") or 0),),
    }
    return sorts.get(sort_by, sorts["risk"])


def paginate(
    matched: List[Dict[str, Any]],
    page: int,
    page_size: int,
    sort_by: str,
    capped: bool,
) -> Dict[str, Any]:
    matched.sort(key=sort_key(sort_by))
    total = len(matched)
    skip = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "sort_by": sort_by,
        # Stated rather than implied: a capped result set must never be mistaken
        # for a complete one.
        "results_capped": capped,
        "cap": MAX_MATCHED_ROWS if capped else None,
        "artefacts": matched[skip: skip + page_size],
    }


def clamp_paging(page: int, page_size: int) -> tuple:
    return max(1, page), max(1, min(MAX_PAGE_SIZE, page_size))
