"""
Tests for the merged "All scans" view.

The picker defaults to a union of every stored scan, so the union has to be a
real deduplication rather than a concatenation: rescanning one target must not
double the estate, and merging must never make anything look safer than the
scan it came from.
"""
import time

import pytest

from backend.cbom.aggregator import merge_artefact_sets
from backend.models import (
    ArtefactOccurrence, CryptographicArtefact, ArtefactType, AlgorithmClass,
    QuantumVulnerabilityStatus, BusinessCriticality, TargetType,
)


def _art(**kw):
    defaults = dict(
        id=kw.pop("id", "ART-1"),
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        key_size_bits=2048,
        location="auth.py",
        line_number=10,
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.MEDIUM,
        data_shelf_life_years=10.0,
        migration_time_years=2.0,
        occurrences=[ArtefactOccurrence(location="auth.py", line_number=10)],
        occurrence_count=1,
    )
    defaults.update(kw)
    return CryptographicArtefact(**defaults)


def _await_job(client, job_id, timeout=90.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = client.get(f"/api/scan/jobs/{job_id}").json()
        if snap["state"] in ("completed", "failed", "cancelled"):
            return snap
        time.sleep(0.1)
    pytest.fail("scan did not finish")


def _scan(client, path, name, z=8.0):
    res = client.post("/api/scan/path", json={
        "target_name": name, "target_type": "multi_target", "path": str(path), "mosca_z": z,
    })
    assert res.status_code == 200, res.text
    snap = _await_job(client, res.json()["job_id"])
    assert snap["state"] == "completed", snap["error"]
    return client.get(f"/api/scan/jobs/{res.json()['job_id']}/result").json()


# --------------------------------------------------------------- unit level

def test_the_same_asset_in_two_scans_collapses_to_one():
    merged = merge_artefact_sets([("Scan A", [_art(id="A")]), ("Scan B", [_art(id="B")])])
    assert len(merged) == 1
    assert merged[0].source_scans == ["Scan A", "Scan B"]


def test_the_same_algorithm_in_different_files_stays_separate():
    """Two codebases using RSA are two things to fix, not one."""
    merged = merge_artefact_sets([
        ("Scan A", [_art(id="A", location="a/auth.py")]),
        ("Scan B", [_art(id="B", location="b/tokens.py")]),
    ])
    assert len(merged) == 2


def test_occurrences_from_both_scans_are_preserved():
    """
    The reason this cannot reuse aggregate_artefacts: that function rebuilds the
    occurrence list from scratch and would discard what each scan accumulated.
    """
    a = _art(id="A", occurrences=[
        ArtefactOccurrence(location="auth.py", line_number=10),
        ArtefactOccurrence(location="auth.py", line_number=22),
    ], occurrence_count=2)
    b = _art(id="B", occurrences=[
        ArtefactOccurrence(location="auth.py", line_number=22),   # overlaps
        ArtefactOccurrence(location="auth.py", line_number=41),   # new
    ], occurrence_count=2)

    merged = merge_artefact_sets([("A", [a]), ("B", [b])])[0]

    assert merged.occurrence_count == 3
    assert sorted(o.line_number for o in merged.occurrences) == [10, 22, 41]


def test_merging_never_softens_the_assessment():
    merged = merge_artefact_sets([
        ("A", [_art(id="A", business_criticality=BusinessCriticality.LOW,
                    data_shelf_life_years=3.0, migration_time_years=1.0)]),
        ("B", [_art(id="B", business_criticality=BusinessCriticality.CRITICAL,
                    data_shelf_life_years=15.0, migration_time_years=5.0)]),
    ])[0]

    assert merged.business_criticality == BusinessCriticality.CRITICAL
    assert merged.data_shelf_life_years == 15.0
    assert merged.migration_time_years == 5.0


def test_merging_does_not_mutate_the_stored_artefacts():
    """The inputs come from stored scans and must survive building the view."""
    a = _art(id="A")
    original_occurrences = len(a.occurrences)

    merge_artefact_sets([("A", [a]), ("B", [_art(id="B", line_number=99)])])

    assert a.occurrence_count == 1
    assert len(a.occurrences) == original_occurrences
    assert a.source_scans == []


def test_empty_input_merges_to_nothing():
    assert merge_artefact_sets([]) == []


# ---------------------------------------------------------------- API level

def test_merged_endpoint_deduplicates_a_rescan(client, sample_tree):
    """Scanning one target three times must not triple the inventory."""
    single = _scan(client, sample_tree, "Run 1")["summary"]["total_artefacts"]
    _scan(client, sample_tree, "Run 2")
    _scan(client, sample_tree, "Run 3")

    merged = client.get("/api/scans/merged").json()["summary"]

    assert merged["total_artefacts"] == single, "a rescan must not inflate the estate"
    assert merged["scan_id"] == "ALL"
    assert "3 scans combined" in " ".join(merged["coverage_notes"])


def test_merged_endpoint_unions_distinct_targets(client, sample_tree, tmp_path):
    other = tmp_path / "other"
    (other / "src").mkdir(parents=True)
    (other / "src" / "legacy.py").write_text(
        "import hashlib\nd = hashlib.sha1(b'x').hexdigest()\n", encoding="utf-8"
    )

    a = _scan(client, sample_tree, "A")["summary"]["total_artefacts"]
    b = _scan(client, other, "B")["summary"]["total_artefacts"]

    merged = client.get("/api/scans/merged").json()["summary"]

    assert merged["total_artefacts"] == a + b, "different targets are distinct assets"


def test_merged_view_uses_the_most_conservative_horizon(client, sample_tree, tmp_path):
    """
    Merging must not make anything look safer than the scan it came from, so
    the smallest Z wins and the choice is stated.
    """
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text("import rsa\nk = rsa.generate_private_key(key_size=2048)\n", encoding="utf-8")

    _scan(client, sample_tree, "Long horizon", z=20.0)
    _scan(client, other, "Short horizon", z=4.0)

    merged = client.get("/api/scans/merged").json()["summary"]

    assert merged["mosca_global_z"] == 4.0
    assert any("most conservative" in n for n in merged["coverage_notes"])


def test_merged_view_can_be_recalculated_but_never_persisted(client, sample_tree):
    _scan(client, sample_tree, "A", z=8.0)

    projected = client.post("/api/scans/ALL/recalculate", json={"mosca_z": 18.0, "persist": True}).json()
    assert projected["summary"]["mosca_global_z"] == 18.0

    # persist:true is ignored — the merged view is derived, and the stored scan
    # keeps the horizon it was assessed at.
    assert client.get("/api/scans/merged").json()["summary"]["mosca_global_z"] == 8.0
    stored = client.get("/api/scans").json()
    assert all(s["mosca_global_z"] == 8.0 for s in stored)


def test_merged_view_is_exportable(client, sample_tree):
    """Reports must work while the combined view is selected."""
    _scan(client, sample_tree, "A")

    assert client.get("/api/scans/ALL/cbom").status_code == 200
    assert client.get("/api/scans/ALL/report/csv").status_code == 200
    assert client.get("/api/scans/ALL/report/html").status_code == 200

    cbom = client.get("/api/scans/ALL/cbom").json()
    assert cbom["bomFormat"] == "CycloneDX"
    assert len(cbom["components"]) > 0


def test_the_merged_view_cannot_be_deleted(client, sample_tree):
    _scan(client, sample_tree, "A")
    res = client.delete("/api/scans/ALL")
    assert res.status_code == 400
    assert "cannot be deleted" in res.json()["detail"]
    # The real scan is untouched.
    assert len(client.get("/api/scans").json()) == 1


def test_merged_view_with_no_scans_is_empty_not_an_error(client):
    body = client.get("/api/scans/merged").json()
    assert body["summary"]["total_artefacts"] == 0
    assert body["artefacts"] == []


def test_merged_assets_record_which_scans_found_them(client, sample_tree):
    _scan(client, sample_tree, "First")
    _scan(client, sample_tree, "Second")

    artefacts = client.get("/api/scans/merged").json()["artefacts"]

    assert artefacts
    assert all(set(a["source_scans"]) == {"First", "Second"} for a in artefacts)
