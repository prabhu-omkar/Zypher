import io
import os
import time
import zipfile

import pytest


def _run_scan(client, tree, name="Target"):
    """Run a path scan to completion and return the stored ScanResult."""
    res = client.post("/api/scan/path", json={
        "target_name": name,
        "target_type": "multi_target",
        "path": str(tree),
    })
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]
    snap = _await_job(client, job_id)
    assert snap["state"] == "completed", snap["error"]
    return client.get(f"/api/scan/jobs/{job_id}/result").json()


def _await_job(client, job_id, timeout=60.0):
    """Poll a scan job until it reaches a terminal state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = client.get(f"/api/scan/jobs/{job_id}").json()
        if snap["state"] in ("completed", "failed", "cancelled"):
            return snap
        time.sleep(0.1)
    pytest.fail(f"Job {job_id} did not finish within {timeout}s")


def test_git_scan_is_not_gated_behind_a_database(client):
    """
    Git scanning must work in local mode.

    It previously returned 403 unless a MongoDB Atlas URI was configured, which
    made a core discovery feature unreachable for anyone running the desktop app
    offline. A missing/invalid repo is now a scan failure, never a paywall.
    """
    res = client.post("/api/scan/git", json={"repo_url": "https://github.com/example/definitely-not-real.git"})
    assert res.status_code != 403, "Git scanning must not require a cloud database"
    # Either git is absent (400 with actionable guidance) or the job starts and
    # then fails on the clone; both are legitimate, neither is a gate.
    if res.status_code == 400:
        assert "git" in res.json()["detail"].lower()
    else:
        assert res.status_code == 200
        snap = _await_job(client, res.json()["job_id"])
        assert snap["state"] == "failed"
        assert snap["error"]


def test_cicd_scan_is_not_gated_behind_a_database(client, sample_tree):
    """CI/CD scanning must work in local mode and report a build gate verdict."""
    res = client.post("/api/scan/cicd", json={
        "target_name": "Pipeline",
        "target_type": "multi_target",
        "path": str(sample_tree),
    })
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["gate"] in ("pass", "warn", "fail")
    assert body["total_artefacts"] > 0


def test_admin_password_setup_and_login(client, isolated_storage):
    local_auth_file = os.path.join(isolated_storage.data_dir, "admin_auth.json")

    # 1. Setup Password
    res = client.post("/api/admin/setup", json={"password": "EnterpriseSecretPassword123!"})
    assert res.status_code == 200
    token = res.json()["token"]
    assert token is not None

    # Verify password is NOT stored in plaintext
    with open(local_auth_file, "r") as f:
        auth_data = f.read()
    assert "EnterpriseSecretPassword123!" not in auth_data
    assert "PBKDF2-HMAC-SHA256" in auth_data

    # 2. Login with correct password
    login_res = client.post("/api/admin/login", json={"password": "EnterpriseSecretPassword123!"})
    assert login_res.status_code == 200
    assert login_res.json()["success"] is True

    # 3. Login with wrong password
    bad_res = client.post("/api/admin/login", json={"password": "WrongPassword"})
    assert bad_res.status_code == 401

    # 4. Access Admin Dashboard with Token
    dash_res = client.get("/api/admin/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert dash_res.status_code == 200
    data = dash_res.json()
    assert "total_systems_scanned" in data
    assert "total_enterprise_assets" in data


def test_admin_dashboard_requires_a_token(client):
    assert client.get("/api/admin/dashboard").status_code == 401
    assert client.get(
        "/api/admin/dashboard", headers={"Authorization": "Bearer not-a-real-token"}
    ).status_code == 401


def test_admin_password_minimum_length(client):
    res = client.post("/api/admin/setup", json={"password": "short"})
    assert res.status_code == 400


def test_zip_archive_upload_scan(client):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("auth.py", "import hashlib\nimport rsa\nprivate_key = rsa.generate_private_key(key_size=2048)")
        zf.writestr("cipher.py", "from Crypto.Cipher import AES\ncipher = AES.new(b'1234567890123456', AES.MODE_CBC)")
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        files={"file": ("project_archive.zip", zip_buffer, "application/zip")},
        data={"target_name": "Test Zipped Repo", "target_type": "multi_target", "mosca_z": "8.0"},
    )
    assert res.status_code == 200, res.text
    snap = _await_job(client, res.json()["job_id"])
    assert snap["state"] == "completed", snap["error"]

    result = client.get(f"/api/scan/jobs/{res.json()['job_id']}/result").json()
    assert result["summary"]["total_artefacts"] >= 2
    # Paths are reported relative to the archive, not the temp extraction dir.
    assert all("ecdat_upload_" not in a["location"] for a in result["artefacts"])


def test_zip_slip_archive_is_rejected(client):
    """
    An archive containing a traversal path must not be extracted.

    extractall() honours '../' entries, so a crafted upload could otherwise
    write outside the scratch directory.
    """
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../escaped.py", "import hashlib")
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        files={"file": ("evil.zip", zip_buffer, "application/zip")},
        data={"target_name": "Evil", "target_type": "multi_target", "mosca_z": "8.0"},
    )
    assert res.status_code == 200
    snap = _await_job(client, res.json()["job_id"])
    assert snap["state"] == "failed"
    assert "unsafe path" in (snap["error"] or "").lower()


def test_path_scan_reports_progress_and_completes(client, sample_tree):
    res = client.post("/api/scan/path", json={
        "target_name": "Sample Data",
        "target_type": "multi_target",
        "path": str(sample_tree),
    })
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]

    snap = _await_job(client, job_id)
    assert snap["state"] == "completed", snap["error"]
    # Progress must describe real work, not a simulated animation.
    assert snap["files_total"] > 0
    assert snap["files_done"] == snap["files_total"]
    assert snap["percent"] == 100.0


def test_path_scan_rejects_a_missing_path(client):
    res = client.post("/api/scan/path", json={
        "target_name": "Nope",
        "target_type": "multi_target",
        "path": "definitely/not/a/real/path",
    })
    assert res.status_code == 400


def test_recalculate_is_non_destructive_by_default(client, sample_tree):
    """
    Dragging the Mosca Z slider must not rewrite the stored scan.

    The endpoint used to persist on every call, so exploring a what-if timeline
    permanently changed the Z the scan was audited at.
    """
    scan = _run_scan(client, sample_tree)
    scan_id = scan["summary"]["scan_id"]
    assert scan["summary"]["mosca_global_z"] == 8.0

    projected = client.post(f"/api/scans/{scan_id}/recalculate", json={"mosca_z": 20.0}).json()
    assert projected["summary"]["mosca_global_z"] == 20.0

    stored = client.get(f"/api/scans/{scan_id}").json()
    assert stored["summary"]["mosca_global_z"] == 8.0, "projection must not mutate the stored scan"

    # Opting in persists.
    client.post(f"/api/scans/{scan_id}/recalculate", json={"mosca_z": 12.0, "persist": True})
    assert client.get(f"/api/scans/{scan_id}").json()["summary"]["mosca_global_z"] == 12.0


def test_recalculate_rejects_an_out_of_range_horizon(client, sample_tree):
    scan = _run_scan(client, sample_tree)
    scan_id = scan["summary"]["scan_id"]
    assert client.post(f"/api/scans/{scan_id}/recalculate", json={"mosca_z": -5}).status_code == 400
    assert client.post(f"/api/scans/{scan_id}/recalculate", json={"mosca_z": 900}).status_code == 400


def test_scan_can_be_deleted(client, sample_tree):
    scan_id = _run_scan(client, sample_tree)["summary"]["scan_id"]
    assert client.delete(f"/api/scans/{scan_id}").status_code == 200
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_quoted_path_from_windows_copy_as_path_is_accepted(client, sample_tree):
    r"""
    Windows Explorer's Shift+Right-click "Copy as path" wraps the path in double
    quotes. Pasting that verbatim used to fail with
    `Path not found: "C:\projects\..."` because the quotes were part of the
    string being looked up.
    """
    res = client.post("/api/scan/path", json={
        "target_name": "Quoted",
        "target_type": "multi_target",
        "path": f'"{sample_tree}"',
    })
    assert res.status_code == 200, res.text
    snap = _await_job(client, res.json()["job_id"])
    assert snap["state"] == "completed", snap["error"]


def test_single_quoted_and_padded_paths_are_accepted(client, sample_tree):
    """Dragging into a shell can add single quotes; copy/paste can add spaces."""
    for candidate in (f"'{sample_tree}'", f"   {sample_tree}   ", f'  "{sample_tree}"  '):
        res = client.post("/api/scan/path", json={
            "target_name": "Padded",
            "target_type": "source_code",
            "path": candidate,
        })
        assert res.status_code == 200, f"{candidate!r} was rejected: {res.text}"


def test_an_unbalanced_quote_is_not_stripped(client, sample_tree):
    """
    Only a balanced pair is removed. A stray leading quote is a genuine typo and
    must still be reported, not silently 'fixed' into a different path.
    """
    res = client.post("/api/scan/path", json={
        "target_name": "Broken",
        "target_type": "multi_target",
        "path": f'"{sample_tree}',
    })
    assert res.status_code == 400


def test_env_vars_and_tilde_expand_in_paths(client):
    """%VAR% and ~ should work as typed rather than being looked up literally."""
    from backend.main import normalise_path
    import os

    assert normalise_path("~") == os.path.normpath(os.path.expanduser("~"))
    if os.environ.get("LOCALAPPDATA"):
        assert normalise_path("%LOCALAPPDATA%") == os.path.normpath(os.environ["LOCALAPPDATA"])


def test_missing_path_error_names_the_parent_when_it_exists(client, sample_tree):
    """A typo in the last segment should say so, not just 'not found'."""
    res = client.post("/api/scan/path", json={
        "target_name": "Typo",
        "target_type": "multi_target",
        "path": str(sample_tree / "sorce_repo"),
    })
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "sorce_repo" in detail
    assert str(sample_tree) in detail
