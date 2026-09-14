"""
Tests for the desktop download bridge.

Report downloads silently did nothing in the packaged app: pywebview ships with
ALLOW_DOWNLOADS disabled, so WebView2 swallowed every `<a download>` click, and
a same-origin target="_blank" does nothing there either. The click produced no
file and no error, which is the worst possible failure for the one view whose
entire purpose is producing files.

These cover the bridge that replaced it. The native Save dialog is the only part
stubbed, because it cannot be automated.
"""
import os

import pytest

launcher = pytest.importorskip("launcher", reason="Windows desktop launcher")


class FakeWindow:
    """Returns a path instead of prompting."""

    def __init__(self, directory):
        self.directory = directory
        self.calls = []

    def create_file_dialog(self, dialog_type, save_filename=None, file_types=None):
        self.calls.append({"save_filename": save_filename, "file_types": file_types})
        return os.path.join(self.directory, save_filename)


class CancellingWindow:
    def create_file_dialog(self, *args, **kwargs):
        return None


class TupleReturningWindow(FakeWindow):
    """Some pywebview backends hand back a tuple rather than a string."""

    def create_file_dialog(self, dialog_type, save_filename=None, file_types=None):
        return (super().create_file_dialog(dialog_type, save_filename, file_types),)


@pytest.fixture
def bridge(monkeypatch):
    b = launcher.DesktopBridge(port=12345)
    monkeypatch.setattr(b, "_fetch", lambda api_path: b"report-bytes-" + api_path.encode())
    return b


def test_downloads_are_enabled_before_the_window_is_created():
    """
    The root cause. pywebview defaults ALLOW_DOWNLOADS to False, so this must be
    switched on explicitly or every download is dropped without a trace.
    """
    import inspect

    source = inspect.getsource(launcher.main)
    assert "ALLOW_DOWNLOADS" in source
    assert "webview.settings['ALLOW_DOWNLOADS'] = True" in source
    # It has to be set before create_window, or the setting is not picked up.
    assert source.index("ALLOW_DOWNLOADS") < source.index("create_window")


def test_save_file_writes_the_fetched_bytes(bridge, tmp_path):
    window = FakeWindow(str(tmp_path))
    bridge.bind(window)

    result = bridge.save_file("/api/scans/S1/cbom", "cyclonedx.json")

    assert result["ok"] is True
    written = tmp_path / "cyclonedx.json"
    assert written.exists()
    assert written.read_bytes() == b"report-bytes-/api/scans/S1/cbom"
    assert result["bytes"] == written.stat().st_size


def test_save_dialog_gets_a_matching_file_filter(bridge, tmp_path):
    window = FakeWindow(str(tmp_path))
    bridge.bind(window)

    bridge.save_file("/api/scans/S1/report/csv", "inventory.csv")

    call = window.calls[0]
    assert call["save_filename"] == "inventory.csv"
    assert "*.csv" in call["file_types"][0]
    assert "All files" in call["file_types"][1]


def test_a_tuple_from_the_dialog_is_normalised(bridge, tmp_path):
    """A tuple path must not be written to as if it were a string."""
    bridge.bind(TupleReturningWindow(str(tmp_path)))

    result = bridge.save_file("/api/scans/S1/cbom", "cbom.json")

    assert result["ok"] is True
    assert (tmp_path / "cbom.json").exists()


def test_cancelling_the_dialog_is_not_an_error(bridge):
    bridge.bind(CancellingWindow())

    result = bridge.save_file("/api/scans/S1/cbom", "cbom.json")

    assert result["ok"] is False
    assert result["cancelled"] is True
    assert "error" not in result


def test_a_fetch_failure_is_reported_rather_than_raised(bridge, tmp_path, monkeypatch):
    bridge.bind(FakeWindow(str(tmp_path)))

    def boom(api_path):
        raise RuntimeError("HTTP Error 404: Not Found")

    monkeypatch.setattr(bridge, "_fetch", boom)

    result = bridge.save_file("/api/scans/NOPE/cbom", "cbom.json")

    assert result["ok"] is False
    assert "404" in result["error"]


def test_saving_before_the_window_exists_fails_cleanly():
    result = launcher.DesktopBridge(port=1).save_file("/api/x", "y.json")
    assert result["ok"] is False
    assert result["error"]


def test_open_external_targets_the_local_server(monkeypatch):
    opened = []
    import webbrowser

    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)

    result = launcher.DesktopBridge(port=8123).open_external("/api/scans/S1/report/html")

    assert result["ok"] is True
    assert opened == ["http://127.0.0.1:8123/api/scans/S1/report/html"]
