"""
Tests for the installer's payload handling.

The shipped Zypher_Setup.exe installed nothing. Two independent defects caused
it, and both are the kind that pass silently:

  1. Zypher_Setup.spec bundles the payload as data, so PyInstaller extracts it to
     sys._MEIPASS/dist/Zypher — but the wizard looked beside the executable, then
     fell back to its own directory, found no Zypher.exe, copied nothing, and
     still displayed "Installation complete!".
  2. Copy errors were swallowed by `except Exception: print(...)`, and the
     packaged app routes stdout to devnull.

These tests pin the discovery order and the verification behaviour. They import
installer_wizard without constructing the Tk window.
"""
import os
import sys

import pytest

installer = pytest.importorskip(
    "installer_wizard", reason="Windows-only installer module"
)


def _make_payload(root, exe_name="Zypher.exe"):
    """Create a directory that looks like a built application."""
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, exe_name), "wb") as f:
        f.write(b"MZ" + b"\0" * 512)
    internal = os.path.join(root, "_internal")
    os.makedirs(internal, exist_ok=True)
    with open(os.path.join(internal, "base_library.zip"), "wb") as f:
        f.write(b"PK" + b"\0" * 256)
    return root


def test_payload_is_found_in_meipass_first(tmp_path, monkeypatch):
    """
    The frozen case: PyInstaller extracts bundled data under _MEIPASS.

    This is the location the old wizard never checked, which is the whole
    reason it installed nothing.
    """
    meipass = tmp_path / "meipass"
    _make_payload(str(meipass / "dist" / "Zypher"))

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Zypher_Setup.exe"), raising=False)

    found = installer.find_payload_dir()
    assert found is not None
    assert os.path.normcase(found) == os.path.normcase(str(meipass / "dist" / "Zypher"))


def test_payload_is_found_beside_the_executable_as_a_fallback(tmp_path, monkeypatch):
    """A setup exe shipped next to an unpacked build directory still works."""
    exe_dir = tmp_path / "release"
    _make_payload(str(exe_dir / "dist" / "Zypher"))

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "empty_meipass"), raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "Zypher_Setup.exe"), raising=False)

    found = installer.find_payload_dir()
    assert found is not None
    assert os.path.isfile(os.path.join(found, "Zypher.exe"))


def test_missing_payload_reports_none_rather_than_a_wrong_directory(tmp_path, monkeypatch):
    """
    An installer built without its payload must be detectable up front.

    The old code fell back to its own directory and proceeded as if it had
    found something.
    """
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "nothing_here"), raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Zypher_Setup.exe"), raising=False)

    assert installer.find_payload_dir() is None


def test_directory_size_counts_the_whole_tree(tmp_path):
    root = _make_payload(str(tmp_path / "app"))
    size = installer.directory_size(root)
    assert size > 512, "nested _internal contents must be counted"


def test_default_install_dir_is_per_user(monkeypatch):
    """Per-user install means no UAC elevation is required."""
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
    path = installer.default_install_dir()
    assert path.endswith(os.path.join("Programs", "Zypher"))
    assert "AppData" in path


def test_uninstaller_script_targets_the_right_artefacts(tmp_path):
    dest = str(tmp_path / "install")
    os.makedirs(dest)
    path = installer.write_uninstaller(dest)

    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as f:
        script = f.read()

    # It must remove every trace the installer created.
    assert installer.EXE_NAME in script          # stop the running app
    assert installer.UNINSTALL_KEY in script     # Add/Remove Programs entry
    assert "Desktop" in script                   # desktop shortcut
    assert "Start Menu" in script                # start menu entry
    assert "rmdir" in script                     # the install directory itself
    # It must not delete from inside the directory it is removing.
    assert "cd /d" in script


def test_uninstaller_registration_values(tmp_path, monkeypatch):
    """The Add/Remove Programs entry is written under HKCU, not HKLM."""
    assert installer.UNINSTALL_KEY.startswith("Software\\Microsoft\\Windows")
    # Registering under HKCU is what keeps the install elevation-free.
    import inspect

    source = inspect.getsource(installer.register_uninstaller)
    assert "HKEY_CURRENT_USER" in source
    assert "HKEY_LOCAL_MACHINE" not in source
