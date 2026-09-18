"""
Zypher — Native Desktop Application Launcher
Launches FastAPI backend + pywebview native window (no browser, no CMD).
"""
import os
import sys
import time
import socket
import threading
import traceback
import logging

# Suppress console output in frozen exe
if getattr(sys, 'frozen', False):
    # Redirect stdout/stderr to devnull in packaged mode
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

# Configure minimal logging
logging.basicConfig(level=logging.WARNING)


def get_base_dir():
    """Get the base directory for the application (works for both dev and frozen exe)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(os.path.dirname(__file__))


def find_free_port(start_port=8000, max_port=8100):
    """
    Find a port the backend can actually bind.

    Probing with connect_ex only tells you nobody is *listening*; the port can
    still be unbindable (reserved, or held in TIME_WAIT), and the failure then
    surfaces as an unexplained startup timeout. Binding it for real is the only
    reliable test.
    """
    for port in range(start_port, max_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    raise RuntimeError(
        f"No free port available in the range {start_port}-{max_port}."
    )


def wait_for_server(port, timeout=15):
    """Block until the backend server is accepting connections."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


# Whatever killed the backend thread, so the failure dialog can say what it
# was instead of "please try restarting".
STARTUP_ERROR = {}


def start_backend_server(port):
    """Start the FastAPI/Uvicorn backend in a daemon thread."""
    try:
        import uvicorn
        from config_manager import load_saved_config
        from backend.main import app, storage_manager

        # Auto-load saved MongoDB configuration from the installer
        saved_cfg = load_saved_config()
        if saved_cfg:
            mongo_uri = saved_cfg.get("mongo_uri", "")
            db_name = saved_cfg.get("database_name", "ecdat_enterprise_inventory")
            if mongo_uri:
                storage_manager.configure_mongo(mongo_uri, db_name)

        uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")
    except Exception:
        STARTUP_ERROR["traceback"] = traceback.format_exc()


class DesktopBridge:
    """
    Native operations the web layer cannot do for itself.

    Even with downloads enabled, WebView2's own download flow drops files into
    the browser download directory with no dialog and only a small flyout — poor
    for an audit tool whose output someone needs to file somewhere specific.
    These methods give a real Save dialog, and open the HTML report in the
    user's actual browser so it can be printed to PDF.

    Exposed to JS as ``window.pywebview.api``. The frontend falls back to plain
    anchor downloads when this is absent, i.e. when running in a dev browser.
    """

    def __init__(self, port: int):
        self._port = port
        self._window = None

    def bind(self, window):
        self._window = window

    def _fetch(self, api_path: str) -> bytes:
        import urllib.request

        url = f"http://127.0.0.1:{self._port}{api_path}"
        with urllib.request.urlopen(url, timeout=120) as response:
            return response.read()

    def save_file(self, api_path: str, suggested_name: str):
        """Fetch a report from the local server and save it via a native dialog."""
        try:
            import webview

            if self._window is None:
                return {"ok": False, "error": "Desktop window is not ready."}

            extension = os.path.splitext(suggested_name)[1].lstrip(".") or "*"
            target = self._window.create_file_dialog(
                webview.SAVE_DIALOG,
                save_filename=suggested_name,
                file_types=(f"{extension.upper()} file (*.{extension})", "All files (*.*)"),
            )
            if not target:
                return {"ok": False, "cancelled": True}

            # pywebview returns a string for SAVE_DIALOG, but a tuple on some
            # backends; normalise before touching the filesystem.
            if isinstance(target, (list, tuple)):
                target = target[0]

            data = self._fetch(api_path)
            with open(target, "wb") as f:
                f.write(data)
            return {"ok": True, "path": str(target), "bytes": len(data)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def open_external(self, api_path: str):
        """
        Open a report in the system browser.

        The HTML audit report is meant to be read and printed to PDF, which the
        app window cannot do — and a same-origin target="_blank" simply does
        nothing inside WebView2.
        """
        try:
            import webbrowser

            webbrowser.open(f"http://127.0.0.1:{self._port}{api_path}")
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


def main():
    port = find_free_port(8000)
    server_url = f"http://127.0.0.1:{port}/"

    # Start FastAPI backend in a background daemon thread
    server_thread = threading.Thread(target=start_backend_server, args=(port,), daemon=True)
    server_thread.start()

    # Wait for the server to be ready before opening the window
    if not wait_for_server(port, timeout=30):
        # Report what actually went wrong. Previously this said only "please try
        # restarting", while the real traceback was discarded with the thread.
        detail = STARTUP_ERROR.get("traceback", "")
        message = "Zypher could not start its analysis engine."
        if detail:
            message += f"\n\n{detail.strip().splitlines()[-1]}"
        else:
            message += f"\n\nThe server did not respond on port {port} within 30 seconds."

        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Zypher", message)
            root.destroy()
        except Exception:
            print(message, file=sys.__stderr__)
        sys.exit(1)

    # Launch native desktop window using pywebview
    import webview

    # pywebview ships with ALLOW_DOWNLOADS disabled, so WebView2 silently
    # swallowed every CBOM / CSV download in the packaged app — the click did
    # nothing and reported nothing. Downloads are the whole point of the
    # Reports view, so they are enabled here.
    webview.settings['ALLOW_DOWNLOADS'] = True

    api = DesktopBridge(port)
    window = webview.create_window(
        title="Zypher — Cryptographic Discovery & Quantum Risk Analysis",
        url=server_url,
        js_api=api,
        width=1440,
        height=900,
        min_size=(1024, 700),
        background_color='#f6f7f9',  # matches --canvas in the UI theme
        text_select=True
    )
    api.bind(window)

    # Start pywebview with EdgeChromium on Windows for best rendering
    webview.start(gui='edgechromium', debug=False)
    sys.exit(0)


if __name__ == "__main__":
    main()
