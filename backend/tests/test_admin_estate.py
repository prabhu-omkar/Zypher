"""
Tests for admin sessions and the estate-wide artefact register.

Two defects these pin down. Sessions were a bare set() of token strings: a token
never expired, signing out only made the browser forget it, and a wrong password
cost an attacker nothing. And the `artefacts` collection had an index but no
writer, so the only way to answer an estate-wide question was to load every scan
into memory — which is why the admin view could only ever show counts.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from backend.admin_session import (
    BASE_LOCKOUT_SECONDS, FAILURES_BEFORE_LOCKOUT, AdminSessions, bearer_token,
)
from backend.cbom import artefact_register as reg

PASSWORD = "a-sufficiently-long-password"


# ============================================================ admin sessions

def test_a_token_is_accepted_until_it_expires():
    sessions = AdminSessions(ttl_seconds=100)
    token, ttl = sessions.issue(now=1000)
    assert ttl == 100
    assert sessions.is_valid(token, now=1050) is True
    assert sessions.is_valid(token, now=1099) is True
    # Expiry is inclusive of the boundary: at the expiry instant it is gone.
    assert sessions.is_valid(token, now=1100) is False


def test_an_expired_token_is_dropped_on_read():
    """A stale token must not be accepted just because no purge has run."""
    sessions = AdminSessions(ttl_seconds=10)
    token, _ = sessions.issue(now=0)
    assert sessions.is_valid(token, now=999) is False
    assert sessions._tokens == {}


def test_signing_out_actually_revokes():
    sessions = AdminSessions()
    token, _ = sessions.issue()
    assert sessions.revoke(token) is True
    assert sessions.is_valid(token) is False
    assert sessions.revoke(token) is False


def test_an_unknown_token_is_never_valid():
    sessions = AdminSessions()
    sessions.issue()
    assert sessions.is_valid("not-a-real-token") is False
    assert sessions.is_valid(None) is False
    assert sessions.is_valid("") is False


def test_tokens_are_distinct_and_not_guessable_in_length():
    sessions = AdminSessions()
    tokens = {sessions.issue()[0] for _ in range(20)}
    assert len(tokens) == 20
    assert all(len(t) >= 32 for t in tokens)


def test_repeated_failures_trigger_a_growing_lockout():
    sessions = AdminSessions()
    for _ in range(FAILURES_BEFORE_LOCKOUT - 1):
        assert sessions.record_failure(now=0) == 0

    first = sessions.record_failure(now=0)
    assert first == BASE_LOCKOUT_SECONDS
    assert sessions.lockout_remaining(now=0) == BASE_LOCKOUT_SECONDS

    second = sessions.record_failure(now=0)
    assert second > first, "the lockout must grow, or guessing stays cheap"


def test_a_successful_login_clears_the_lockout():
    sessions = AdminSessions()
    for _ in range(FAILURES_BEFORE_LOCKOUT):
        sessions.record_failure(now=0)
    assert sessions.lockout_remaining(now=0) > 0

    sessions.record_success()
    assert sessions.lockout_remaining(now=0) == 0


def test_bearer_token_parsing():
    assert bearer_token("Bearer abc123") == "abc123"
    assert bearer_token("bearer abc123") == "abc123"
    assert bearer_token("Basic abc123") is None
    assert bearer_token("abc123") is None
    assert bearer_token(None) is None


# ========================================================= register plumbing

def _scan_doc():
    return {
        "summary": {
            "scan_id": "SCAN-TEST01",
            "target_name": "Payments API",
            "created_at": "2026-01-01T00:00:00Z",
            "sensitivity_profile": "financial",
        },
        "artefacts": [
            {"id": "ART-1", "name": "RSA-2048", "type": "algorithm",
             "algorithm_family": "RSA", "algorithm_class": "asymmetric_factoring",
             "key_size_bits": 2048, "location": "app/auth.py", "line_number": 14,
             "target_type": "source_code", "quantum_vulnerability": "fully_broken",
             "business_criticality": "High", "occurrence_count": 3,
             "crypto_usage": "key_transport", "known_vulnerabilities": []},
            {"id": "ART-2", "name": "AES-128", "type": "algorithm",
             "algorithm_family": "AES", "algorithm_class": "symmetric",
             "key_size_bits": 128, "location": "app/store.py",
             "target_type": "source_code", "quantum_vulnerability": "degraded",
             "business_criticality": "Medium", "occurrence_count": 1,
             "crypto_usage": "confidentiality", "known_vulnerabilities": []},
        ],
        "risk_assessments": {
            "ART-1": {"risk_category": "Critical", "shelf_life_x": 7.0,
                      "migration_time_y": 0.4, "must_start_by": "2026-03-01",
                      "must_complete_by": "2026-08-01", "is_overdue": True,
                      "binding_model": "mosca"},
            "ART-2": {"risk_category": "Low", "shelf_life_x": 7.0,
                      "migration_time_y": 0.3, "must_start_by": "2030-01-01",
                      "must_complete_by": "2030-05-01", "is_overdue": False,
                      "binding_model": "regulatory"},
        },
        "recommendations": {
            "ART-1": {"recommended_standard": "NIST FIPS 203 (ML-KEM-768)",
                      "nist_category": 3, "migration_urgency": "Overdue"},
            "ART-2": {"recommended_standard": "AES-256-GCM", "nist_category": 3,
                      "migration_urgency": "Start by 2030-01-01"},
        },
    }


def test_a_row_carries_the_system_and_the_assessment_together():
    """
    The point of the register: an asset's identity, its risk and its deadline in
    one row, so the estate can be sorted by any of them without a join.
    """
    rows = reg.rows_for_scan(_scan_doc())
    assert len(rows) == 2

    rsa = next(r for r in rows if r["name"] == "RSA-2048")
    assert rsa["system_name"] == "Payments API"
    assert rsa["scan_id"] == "SCAN-TEST01"
    assert rsa["risk_category"] == "Critical"
    assert rsa["must_start_by"] == "2026-03-01"
    assert rsa["is_overdue"] is True
    assert rsa["recommended_standard"] == "NIST FIPS 203 (ML-KEM-768)"
    # Unique across scans, so the same artefact id in two scans is two rows.
    assert rsa["_id"] == "SCAN-TEST01:ART-1"


def test_an_artefact_with_no_assessment_still_produces_a_row():
    doc = _scan_doc()
    doc["risk_assessments"] = {}
    doc["recommendations"] = {}
    rows = reg.rows_for_scan(doc)
    assert len(rows) == 2
    assert all(r["risk_category"] is None for r in rows)
    assert all(r["is_overdue"] is False for r in rows)


def test_filters_agree_between_the_two_backends():
    """
    The database query and the in-memory test must mean the same thing, or the
    same filter returns different estates depending on whether Mongo is attached.
    """
    f = reg.ArtefactFilter(risk_category="Critical", system_name="Payments API")
    assert f.as_mongo_query() == {
        "risk_category": "Critical", "system_name": "Payments API",
    }

    rows = reg.rows_for_scan(_scan_doc())
    assert [r["name"] for r in rows if f.matches(r)] == ["RSA-2048"]


def test_free_text_search_is_applied_in_python_for_both_backends():
    """Search is deliberately absent from the Mongo query so both agree."""
    f = reg.ArtefactFilter(search="auth.py")
    assert "search" not in f.as_mongo_query()
    rows = reg.rows_for_scan(_scan_doc())
    assert [r["name"] for r in rows if f.matches(r)] == ["RSA-2048"]


def test_overdue_filter():
    f = reg.ArtefactFilter(overdue_only=True)
    assert f.as_mongo_query()["is_overdue"] is True
    rows = reg.rows_for_scan(_scan_doc())
    assert [r["name"] for r in rows if f.matches(r)] == ["RSA-2048"]


def test_the_default_sort_is_risk_then_deadline():
    rows = reg.rows_for_scan(_scan_doc())
    rows.sort(key=reg.sort_key("risk"))
    assert [r["risk_category"] for r in rows] == ["Critical", "Low"]


def test_an_asset_with_no_deadline_sorts_last_not_first():
    """A null must_start_by must not read as 'due immediately'."""
    rows = reg.rows_for_scan(_scan_doc())
    rows[0]["must_start_by"] = None
    rows[0]["risk_category"] = "Low"
    rows.sort(key=reg.sort_key("deadline"))
    assert rows[-1]["must_start_by"] is None


def test_pagination_reports_totals_and_never_hides_a_cap():
    rows = [dict(name=f"A{i}", risk_category="Low") for i in range(120)]
    page = reg.paginate(list(rows), page=2, page_size=50, sort_by="name", capped=False)
    assert page["total"] == 120
    assert page["total_pages"] == 3
    assert len(page["artefacts"]) == 50
    assert page["results_capped"] is False
    assert page["cap"] is None

    capped = reg.paginate(list(rows), page=1, page_size=50, sort_by="name", capped=True)
    assert capped["results_capped"] is True
    assert capped["cap"] == reg.MAX_MATCHED_ROWS


def test_page_size_is_clamped():
    assert reg.clamp_paging(0, 10_000) == (1, reg.MAX_PAGE_SIZE)
    assert reg.clamp_paging(-5, 0) == (1, 1)


# ============================================================== the endpoints

@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """A client with an isolated local store and no admin password yet."""
    from backend import main

    monkeypatch.setattr(main.storage_manager, "data_dir", str(tmp_path))
    main.admin_sessions.revoke_all()
    main.admin_sessions.record_success()  # clear any lockout from another test

    with open(tmp_path / "scan_SCAN-TEST01.json", "w", encoding="utf-8") as f:
        json.dump(_scan_doc(), f)

    return TestClient(main.app)


def _sign_in(client):
    body = client.post("/api/admin/setup", json={"password": PASSWORD}).json()
    return {"Authorization": f"Bearer {body['token']}"}


def test_every_admin_route_refuses_an_anonymous_caller(admin_client):
    for path in ("/api/admin/artefacts", "/api/admin/facets", "/api/admin/overview"):
        assert admin_client.get(path).status_code == 401, path


def test_a_forged_token_is_refused(admin_client):
    _sign_in(admin_client)
    forged = {"Authorization": "Bearer definitely-not-a-real-token"}
    assert admin_client.get("/api/admin/artefacts", headers=forged).status_code == 401


def test_status_reports_whether_this_caller_holds_a_session(admin_client):
    assert admin_client.get("/api/admin/status").json()["is_authenticated"] is False
    headers = _sign_in(admin_client)
    assert admin_client.get("/api/admin/status", headers=headers).json()["is_authenticated"] is True


def test_the_estate_lists_assets_from_the_local_store_without_a_database(admin_client):
    """Mongo is opt-in, so admin mode has to work on the file store too."""
    headers = _sign_in(admin_client)
    body = admin_client.get("/api/admin/artefacts", headers=headers).json()

    assert body["total"] == 2
    assert {a["name"] for a in body["artefacts"]} == {"RSA-2048", "AES-128"}
    assert body["artefacts"][0]["risk_category"] == "Critical", "risk sorts first"
    assert body["artefacts"][0]["system_name"] == "Payments API"


def test_the_estate_can_be_filtered_and_searched(admin_client):
    headers = _sign_in(admin_client)
    get = lambda **p: admin_client.get("/api/admin/artefacts", headers=headers, params=p).json()

    assert get(risk_category="Critical")["total"] == 1
    assert get(algorithm_family="AES")["total"] == 1
    assert get(system_name="Payments API")["total"] == 2
    assert get(system_name="Nothing here")["total"] == 0
    assert get(overdue_only=True)["total"] == 1
    assert get(search="store.py")["total"] == 1
    assert get(search="no-such-thing")["total"] == 0


def test_paging_slices_the_estate(admin_client):
    headers = _sign_in(admin_client)
    first = admin_client.get("/api/admin/artefacts", headers=headers,
                             params={"page_size": 1}).json()
    second = admin_client.get("/api/admin/artefacts", headers=headers,
                              params={"page_size": 1, "page": 2}).json()

    assert first["total"] == second["total"] == 2
    assert first["total_pages"] == 2
    assert len(first["artefacts"]) == 1
    assert first["artefacts"][0]["name"] != second["artefacts"][0]["name"]


def test_facets_come_from_real_rows(admin_client):
    headers = _sign_in(admin_client)
    facets = admin_client.get("/api/admin/facets", headers=headers).json()
    assert facets["systems"] == ["Payments API"]
    assert set(facets["algorithm_families"]) == {"RSA", "AES"}


def test_signing_out_revokes_the_token_on_the_server(admin_client):
    headers = _sign_in(admin_client)
    assert admin_client.get("/api/admin/artefacts", headers=headers).status_code == 200

    out = admin_client.post("/api/admin/logout", headers=headers,
                            json={"password": PASSWORD})
    assert out.json()["success"] is True
    assert admin_client.get("/api/admin/artefacts", headers=headers).status_code == 401


def test_repeated_wrong_passwords_are_locked_out(admin_client):
    _sign_in(admin_client)  # establishes the password
    from backend import main
    main.admin_sessions.record_success()

    codes = [
        admin_client.post("/api/admin/login", json={"password": "wrong"}).status_code
        for _ in range(FAILURES_BEFORE_LOCKOUT + 1)
    ]
    assert codes[0] == 401
    assert 429 in codes, "guessing must eventually be throttled"
    main.admin_sessions.record_success()


def test_reindex_says_so_when_there_is_no_database(admin_client):
    headers = _sign_in(admin_client)
    body = admin_client.post("/api/admin/reindex", headers=headers).json()
    assert body["indexed"] == 0
    assert "no index to rebuild" in body["message"]
