"""
Isolation between installations sharing one database.

A shared MongoDB is shared: before this, pointing two installations at the same
database made every scan visible to both through the ordinary scan list and the
merged view, with no password involved anywhere. The admin login gated a *view*,
not the data.

Every stored scan now carries the installation that produced it, and an ordinary
read returns only this installation's own work. Unlocking admin is the only
thing that widens the scope.

This is application-level scoping, not encryption — anyone holding the
connection string can still read the collection with a Mongo client. That is a
database-credentials problem and these tests do not pretend otherwise.
"""
import json

import pytest
from fastapi.testclient import TestClient

from backend.cbom.storage import EnterpriseStorageManager

PASSWORD = "a-sufficiently-long-password"
OTHER_INSTALL = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _scan(scan_id, name, installation_id):
    return {
        "summary": {
            "scan_id": scan_id,
            "target_name": name,
            "target_types": ["source_code"],
            "created_at": "2026-01-01T00:00:00Z",
            "total_artefacts": 1,
            "risk_distribution": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0},
            "vulnerability_distribution": {},
            "quantum_readiness_score": 10.0,
            "installation_id": installation_id,
        },
        "artefacts": [{
            "id": f"ART-{scan_id}", "name": f"RSA-2048 ({name})", "type": "algorithm",
            "algorithm_family": "RSA", "algorithm_class": "asymmetric_factoring",
            "key_size_bits": 2048, "location": "app.py", "target_type": "source_code",
            "quantum_vulnerability": "fully_broken", "business_criticality": "High",
            "occurrence_count": 1, "known_vulnerabilities": [],
        }],
        "risk_assessments": {},
        "recommendations": {},
    }


# =========================================================== installation id

def test_the_installation_id_is_generated_once_and_persists(tmp_path):
    first = EnterpriseStorageManager(data_dir=str(tmp_path))
    generated = first.installation_id
    assert generated and len(generated) == 32

    # A second manager over the same directory is the same installation.
    second = EnterpriseStorageManager(data_dir=str(tmp_path))
    assert second.installation_id == generated

    # A different directory is a different installation.
    other = EnterpriseStorageManager(data_dir=str(tmp_path / "elsewhere"))
    assert other.installation_id != generated


def test_ownership_resolves_ambiguity_towards_showing_less(tmp_path):
    """
    A scan with no installation id predates the field. On local disk it is this
    installation's; in a shared database its origin is unknown, so it stays
    hidden until an admin unlocks the estate.
    """
    manager = EnterpriseStorageManager(data_dir=str(tmp_path))
    unstamped = {"scan_id": "S1"}

    assert manager._owns(unstamped, from_database=False) is True
    assert manager._owns(unstamped, from_database=True) is False

    mine = {"installation_id": manager.installation_id}
    theirs = {"installation_id": OTHER_INSTALL}
    assert manager._owns(mine, from_database=True) is True
    assert manager._owns(theirs, from_database=False) is False


def test_the_scope_filter_is_empty_only_when_unlocked(tmp_path):
    manager = EnterpriseStorageManager(data_dir=str(tmp_path))
    assert manager._scope_query(manager.SCOPE_ALL) == {}
    assert manager._scope_query(manager.SCOPE_OWN) == {
        "summary.installation_id": manager.installation_id
    }


# ====================================================== end-to-end isolation

@pytest.fixture
def two_installations(tmp_path, monkeypatch):
    """
    One local store holding this installation's scan and another's, as a shared
    database would present them.
    """
    from backend import main

    monkeypatch.setattr(main.storage_manager, "data_dir", str(tmp_path))
    monkeypatch.setattr(main.storage_manager, "_installation_id", None)
    main.admin_sessions.revoke_all()
    main.admin_sessions.record_success()

    mine = main.storage_manager.installation_id
    for scan_id, name, owner in (
        ("SCAN-MINE01", "My Service", mine),
        ("SCAN-THEIR1", "Their Service", OTHER_INSTALL),
    ):
        with open(tmp_path / f"scan_{scan_id}.json", "w", encoding="utf-8") as f:
            json.dump(_scan(scan_id, name, owner), f)

    return TestClient(main.app), mine


def _sign_in(client):
    body = client.post("/api/admin/setup", json={"password": PASSWORD}).json()
    return {"Authorization": f"Bearer {body['token']}"}


def test_the_scan_list_shows_only_this_installations_work(two_installations):
    client, _ = two_installations
    names = [s["target_name"] for s in client.get("/api/scans").json()]
    assert names == ["My Service"]


def test_another_installations_scan_reads_as_absent_not_forbidden(two_installations):
    """404 rather than 403: the caller is not entitled to know it exists."""
    client, _ = two_installations
    assert client.get("/api/scans/SCAN-THEIR1").status_code == 404
    assert client.get("/api/scans/SCAN-MINE01").status_code == 200


def test_the_merged_view_does_not_leak_another_installation(two_installations):
    """
    The merged view was the real hole: it unioned every stored scan with no
    password anywhere, so a shared database exposed everything by default.
    """
    client, _ = two_installations
    merged = client.get("/api/scans/merged").json()
    names = [a["name"] for a in merged["artefacts"]]
    assert any("My Service" in n for n in names)
    assert not any("Their Service" in n for n in names)


def test_another_installations_scan_cannot_be_deleted(two_installations):
    client, _ = two_installations
    assert client.delete("/api/scans/SCAN-THEIR1").status_code == 404
    # And it is still there afterwards for an admin to see.
    headers = _sign_in(client)
    estate = client.get("/api/admin/artefacts", headers=headers).json()
    assert any(a["system_name"] == "Their Service" for a in estate["artefacts"])


def test_unlocking_admin_reveals_the_whole_estate(two_installations):
    client, _ = two_installations

    before = client.get("/api/admin/artefacts")
    assert before.status_code == 401

    headers = _sign_in(client)
    estate = client.get("/api/admin/artefacts", headers=headers).json()
    systems = {a["system_name"] for a in estate["artefacts"]}
    assert systems == {"My Service", "Their Service"}


def test_facets_do_not_name_other_installations_systems_when_locked(two_installations):
    """A filter dropdown must not be a side channel for what else is stored."""
    client, _ = two_installations
    from backend import main

    locked = main.storage_manager.artefact_facets(scope=main.storage_manager.SCOPE_OWN)
    assert locked["systems"] == ["My Service"]

    unlocked = main.storage_manager.artefact_facets(scope=main.storage_manager.SCOPE_ALL)
    assert set(unlocked["systems"]) == {"My Service", "Their Service"}


def test_a_new_scan_is_stamped_with_this_installation(two_installations, tmp_path):
    client, mine = two_installations
    from backend import main
    from backend.models import TargetType, DataSensitivityProfile

    ev, stats, df = main.run_all_scanners("backend/scanners", TargetType.SOURCE_CODE)
    result = main.execute_pipeline(
        target_name="Fresh", target_type=TargetType.SOURCE_CODE,
        raw_evidences=ev, mosca_z=8.0, scan_stats=stats, dataflow=df,
        sensitivity_profile=DataSensitivityProfile.FINANCIAL,
    )
    assert result.summary.installation_id == mine
    # And it shows up in the ordinary, locked list.
    assert "Fresh" in [s["target_name"] for s in client.get("/api/scans").json()]


# ================================================ leaving admin mode is gated

def test_exiting_admin_mode_requires_the_password(two_installations):
    client, _ = two_installations
    headers = _sign_in(client)

    wrong = client.post("/api/admin/logout", headers=headers,
                        json={"password": "not-the-password"})
    assert wrong.status_code == 401
    # The session survives a wrong password rather than half-tearing down.
    assert client.get("/api/admin/artefacts", headers=headers).status_code == 200

    right = client.post("/api/admin/logout", headers=headers,
                        json={"password": PASSWORD})
    assert right.status_code == 200
    assert client.get("/api/admin/artefacts", headers=headers).status_code == 401


def test_exiting_when_already_signed_out_is_not_an_error(two_installations):
    """A stale client must not be left wedged by a logout it cannot complete."""
    client, _ = two_installations
    body = client.post("/api/admin/logout",
                       headers={"Authorization": "Bearer stale"},
                       json={"password": "anything"}).json()
    assert body["success"] is True
    assert body["already_signed_out"] is True


def test_the_estate_is_hidden_again_after_exiting(two_installations):
    client, _ = two_installations
    headers = _sign_in(client)
    assert len(client.get("/api/admin/artefacts", headers=headers).json()["artefacts"]) == 2

    client.post("/api/admin/logout", headers=headers, json={"password": PASSWORD})
    names = [s["target_name"] for s in client.get("/api/scans").json()]
    assert names == ["My Service"]
