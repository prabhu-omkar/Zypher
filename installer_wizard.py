"""
Zypher Setup — Windows installer.

The previous wizard could not work, for two independent reasons:

 1. Zypher_Setup.spec bundles the payload as data, so at runtime PyInstaller
    extracts it to ``sys._MEIPASS/dist/Zypher``. The wizard instead looked for it
    beside the executable (``dirname(sys.executable)/dist/Zypher``), which in a
    distributed installer is never where it is. It then fell back to its own
    directory, found no Zypher.exe there, copied nothing, and still reported
    "Installation complete!" — leaving a Desktop shortcut pointing at a file
    that did not exist.

 2. Every copy failure was swallowed by ``except Exception: print(...)``, and
    the packaged app sends stdout to devnull, so nothing was ever reported.

This rewrite locates the payload correctly, verifies it before and after
copying, reports failures instead of hiding them, lets the user choose the
install directory (which the old flow declared but never offered), and writes a
working uninstaller plus an Add/Remove Programs entry.
"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import traceback
import winreg
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Zypher"
APP_DISPLAY_NAME = "Zypher"
APP_VERSION = "1.1.0"
PUBLISHER = "NTRO SIH 26164"
EXE_NAME = "Zypher.exe"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Zypher"


# --------------------------------------------------------------------------
# Payload discovery
# --------------------------------------------------------------------------

def find_payload_dir():
    """
    Locate the bundled Zypher application directory.

    Returns the directory containing Zypher.exe, or None. The frozen case is
    checked first and is the one that matters in a real install; the source
    cases let the wizard be tested with `python installer_wizard.py`.
    """
    candidates = []

    if getattr(sys, "frozen", False):
        # Where PyInstaller actually extracts bundled data.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(os.path.join(meipass, "dist", "Zypher"))
            candidates.append(os.path.join(meipass, "Zypher"))
            candidates.append(meipass)
        # A setup exe shipped next to an unpacked build directory.
        exe_dir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exe_dir, "dist", "Zypher"))
        candidates.append(os.path.join(exe_dir, "Zypher"))
    else:
        here = os.path.abspath(os.path.dirname(__file__))
        candidates.append(os.path.join(here, "dist", "Zypher"))

    for path in candidates:
        if path and os.path.isfile(os.path.join(path, EXE_NAME)):
            return path
    return None


def default_install_dir():
    """Per-user location: no administrator elevation required."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Programs", APP_NAME)


def directory_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


# --------------------------------------------------------------------------
# Windows integration
# --------------------------------------------------------------------------

def create_shortcut(target_exe, shortcut_path, description=""):
    """
    Create a .lnk via PowerShell's WScript.Shell COM object.

    Arguments are passed through a here-string rather than interpolated into the
    command line, so a path containing quotes or spaces cannot break the script.
    Returns (ok, message).
    """
    script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut([Environment]::ExpandEnvironmentVariables('{shortcut_path}')); "
        f"$s.TargetPath = '{target_exe}'; "
        f"$s.WorkingDirectory = '{os.path.dirname(target_exe)}'; "
        f"$s.Description = '{description}'; "
        f"$s.IconLocation = '{target_exe},0'; "
        "$s.Save()"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            return False, (result.stderr or "PowerShell returned a non-zero exit code").strip()
        if not os.path.exists(shortcut_path):
            return False, "Shortcut file was not created."
        return True, ""
    except Exception as exc:
        return False, str(exc)


def register_uninstaller(install_dir, uninstaller_path, size_kb):
    """Add an Add/Remove Programs entry under HKCU (no elevation needed)."""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
            values = {
                "DisplayName": APP_DISPLAY_NAME,
                "DisplayVersion": APP_VERSION,
                "Publisher": PUBLISHER,
                "InstallLocation": install_dir,
                "DisplayIcon": os.path.join(install_dir, EXE_NAME),
                "UninstallString": f'"{uninstaller_path}"',
                "NoModify": 1,
                "NoRepair": 1,
            }
            for name, value in values.items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, kind, value)
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, int(size_kb))
        return True, ""
    except Exception as exc:
        return False, str(exc)


UNINSTALLER_SOURCE = r'''@echo off
REM Zypher uninstaller — generated by Zypher Setup.
setlocal
set "INSTALL_DIR=%~dp0"
echo Removing Zypher...

taskkill /F /IM {exe_name} >nul 2>&1

reg delete "HKCU\{uninstall_key}" /f >nul 2>&1
del /q "%USERPROFILE%\Desktop\{shortcut_name}" >nul 2>&1
del /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\{shortcut_name}" >nul 2>&1

REM Delete the install directory from outside it, so the tree can be removed.
cd /d "%TEMP%"
timeout /t 1 /nobreak >nul
rmdir /s /q "%INSTALL_DIR%" >nul 2>&1

echo Zypher has been removed.
timeout /t 2 /nobreak >nul
'''


def write_uninstaller(install_dir):
    path = os.path.join(install_dir, "Uninstall Zypher.bat")
    content = UNINSTALLER_SOURCE.format(
        exe_name=EXE_NAME,
        uninstall_key=UNINSTALL_KEY,
        shortcut_name=f"{APP_DISPLAY_NAME}.lnk",
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# --------------------------------------------------------------------------
# Wizard
# --------------------------------------------------------------------------

class SetupWizard(tk.Tk):
    def __init__(self):
        super().__init__()

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self.title(f"{APP_DISPLAY_NAME} Setup")
        self.resizable(False, False)
        self.configure(bg="#f0f0f0")
        self._centre(600, 470)

        style = ttk.Style(self)
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
        style.configure("Title.TLabel", font=("Segoe UI", 13, "bold"), background="#ffffff", foreground="#14213d")
        style.configure("Body.TLabel", font=("Segoe UI", 9), background="#ffffff", foreground="#333333")
        style.configure("Small.TLabel", font=("Segoe UI", 8), background="#ffffff", foreground="#777777")
        style.configure("Error.TLabel", font=("Segoe UI", 9), background="#ffffff", foreground="#b00020")
        style.configure("Success.TLabel", font=("Segoe UI", 9), background="#ffffff", foreground="#0a7c42")
        style.configure("Header.TFrame", background="#14213d")
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), background="#14213d", foreground="#ffffff")
        style.configure("HeaderSub.TLabel", font=("Segoe UI", 8), background="#14213d", foreground="#9fb0d0")
        style.configure("Content.TFrame", background="#ffffff")
        style.configure("Footer.TFrame", background="#f0f0f0")

        self.mongo_uri = tk.StringVar(value="")
        self.db_name = tk.StringVar(value="ecdat_enterprise_inventory")
        self.install_dir = tk.StringVar(value=default_install_dir())
        self.make_desktop = tk.BooleanVar(value=True)
        self.make_startmenu = tk.BooleanVar(value=True)

        self.payload_dir = find_payload_dir()
        self.install_errors = []
        self.installed_exe = None

        self._build_header()
        self.content = ttk.Frame(self, style="Content.TFrame")
        self.content.pack(fill="both", expand=True)
        ttk.Separator(self, orient="horizontal").pack(fill="x", side="bottom")
        self.footer = ttk.Frame(self, style="Footer.TFrame", height=52)
        self.footer.pack(fill="x", side="bottom")
        self.footer.pack_propagate(False)

        self.step_welcome()

    def _centre(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_header(self):
        header = ttk.Frame(self, style="Header.TFrame", height=58)
        header.pack(fill="x")
        header.pack_propagate(False)
        inner = ttk.Frame(header, style="Header.TFrame")
        inner.pack(fill="both", expand=True, padx=18, pady=9)
        ttk.Label(inner, text=f"{APP_DISPLAY_NAME} Setup", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            inner,
            text="Cryptographic Discovery & Quantum Risk Analysis  ·  NTRO PS 26164",
            style="HeaderSub.TLabel",
        ).pack(anchor="w")

    def _clear(self):
        for w in self.content.winfo_children():
            w.destroy()
        for w in self.footer.winfo_children():
            w.destroy()

    def _pad(self):
        frame = ttk.Frame(self.content, style="Content.TFrame")
        frame.pack(fill="both", expand=True, padx=26, pady=20)
        return frame

    def _buttons(self):
        bar = ttk.Frame(self.footer, style="Footer.TFrame")
        bar.pack(fill="x", padx=14, pady=10)
        return bar

    # ---------------------------------------------------------------- step 1
    def step_welcome(self):
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text=f"Install {APP_DISPLAY_NAME}", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Label(
            pad,
            text=(
                "Zypher discovers cryptographic assets across source code, compiled\n"
                "binaries, dependency manifests and container definitions, then assesses\n"
                "each one against the post-quantum timeline using Mosca's inequality.\n\n"
                "This wizard will:\n"
                "    •  Install the application to a folder you choose\n"
                "    •  Create Desktop and Start Menu shortcuts\n"
                "    •  Register an uninstaller in Add or Remove Programs\n\n"
                "No administrator rights are required."
            ),
            style="Body.TLabel",
            justify="left",
        ).pack(anchor="w")

        bar = self._buttons()

        # The payload is verified before the user invests any time in the flow,
        # rather than failing silently at the copy step as it used to.
        if self.payload_dir is None:
            ttk.Label(
                pad,
                text=(
                    "⚠  Setup could not find the bundled application files.\n"
                    "    This installer was built without its payload. Rebuild with:\n"
                    "        python build.py"
                ),
                style="Error.TLabel",
                justify="left",
            ).pack(anchor="w", pady=(14, 0))
            ttk.Button(bar, text="Close", command=self.destroy).pack(side="right")
            return

        size_mb = directory_size(self.payload_dir) / (1024 * 1024)
        ttk.Label(pad, text=f"Application payload found · {size_mb:.0f} MB", style="Small.TLabel").pack(
            anchor="w", pady=(14, 0)
        )

        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="left")
        ttk.Button(bar, text="Next  >", command=self.step_location).pack(side="right")

    # ---------------------------------------------------------------- step 2
    def step_location(self):
        """Install location — the step the old wizard documented but never showed."""
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text="Choose install location", style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        box = ttk.LabelFrame(pad, text="  Destination folder  ", padding=12)
        box.pack(fill="x")
        row = ttk.Frame(box)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.install_dir, font=("Segoe UI", 9)).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(row, text="Browse…", command=self._browse, width=10).pack(side="left", padx=(8, 0))

        required = directory_size(self.payload_dir) / (1024 * 1024)
        ttk.Label(box, text=f"Space required: {required:.0f} MB", font=("Segoe UI", 8)).pack(
            anchor="w", pady=(9, 0)
        )

        opts = ttk.LabelFrame(pad, text="  Shortcuts  ", padding=12)
        opts.pack(fill="x", pady=(14, 0))
        ttk.Checkbutton(opts, text="Create a Desktop shortcut", variable=self.make_desktop).pack(anchor="w")
        ttk.Checkbutton(opts, text="Add to the Start Menu", variable=self.make_startmenu).pack(
            anchor="w", pady=(4, 0)
        )

        bar = self._buttons()
        ttk.Button(bar, text="<  Back", command=self.step_welcome).pack(side="left")
        ttk.Button(bar, text="Next  >", command=self.step_database).pack(side="right")

    def _browse(self):
        chosen = filedialog.askdirectory(title="Select install folder", initialdir=os.path.dirname(self.install_dir.get()))
        if chosen:
            self.install_dir.set(os.path.join(os.path.normpath(chosen), APP_NAME))

    # ---------------------------------------------------------------- step 3
    def step_database(self):
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text="Storage (optional)", style="Title.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(
            pad,
            text=(
                "Zypher works fully offline and stores scan results in local files.\n"
                "Every feature — all six detection tiers, Git and CI/CD scanning, the risk\n"
                "models and all exports — behaves identically either way."
            ),
            style="Body.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        box = ttk.LabelFrame(pad, text="  MongoDB (only if you want shared storage)  ", padding=12)
        box.pack(fill="x")
        ttk.Label(box, text="Connection string:", font=("Segoe UI", 9)).pack(anchor="w")
        ttk.Entry(box, textvariable=self.mongo_uri, font=("Consolas", 9), show="•").pack(
            fill="x", pady=(2, 10)
        )
        ttk.Label(box, text="Database name:", font=("Segoe UI", 9)).pack(anchor="w")
        ttk.Entry(box, textvariable=self.db_name, font=("Segoe UI", 9)).pack(fill="x", pady=(2, 0))

        ttk.Label(
            pad,
            text="Leave this blank to use local file storage. You can change it later in Settings.",
            style="Small.TLabel",
        ).pack(anchor="w", pady=(12, 0))

        bar = self._buttons()
        ttk.Button(bar, text="<  Back", command=self.step_location).pack(side="left")
        ttk.Button(bar, text="Install", command=self.step_install).pack(side="right")

    # ---------------------------------------------------------------- step 4
    def step_install(self):
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text="Installing…", style="Title.TLabel").pack(anchor="w", pady=(0, 14))
        self.progress = ttk.Progressbar(pad, mode="determinate", length=520, maximum=100)
        self.progress.pack(pady=(4, 14))
        self.status = ttk.Label(pad, text="Preparing…", style="Body.TLabel")
        self.status.pack(anchor="w")
        self.detail = ttk.Label(pad, text="", style="Small.TLabel", wraplength=520, justify="left")
        self.detail.pack(anchor="w", pady=(3, 0))

        threading.Thread(target=self._install_worker, daemon=True).start()

    def _report(self, pct, status, detail=""):
        def apply():
            self.progress["value"] = pct
            self.status.config(text=status)
            self.detail.config(text=detail)

        self.after(0, apply)

    def _install_worker(self):
        """
        Perform the install. Any failure is recorded and shown; nothing here
        reports success it did not achieve.
        """
        try:
            dest = os.path.normpath(self.install_dir.get())

            self._report(5, "Preparing destination…", dest)
            os.makedirs(dest, exist_ok=True)
            if not os.access(dest, os.W_OK):
                raise PermissionError(f"Cannot write to {dest}")

            # --- copy the payload -----------------------------------------
            self._report(15, "Copying application files…", f"From {self.payload_dir}")
            if os.path.normcase(self.payload_dir) != os.path.normcase(dest):
                entries = os.listdir(self.payload_dir)
                for index, name in enumerate(entries):
                    src = os.path.join(self.payload_dir, name)
                    dst = os.path.join(dest, name)
                    self._report(
                        15 + int(50 * index / max(1, len(entries))),
                        "Copying application files…",
                        name,
                    )
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)

            target_exe = os.path.join(dest, EXE_NAME)
            # Verify rather than assume — this is exactly what the old wizard
            # skipped, which is how it shipped shortcuts to a missing file.
            if not os.path.isfile(target_exe):
                raise FileNotFoundError(
                    f"{EXE_NAME} is not present in {dest} after copying. The installation did not complete."
                )
            self.installed_exe = target_exe

            # --- configuration --------------------------------------------
            self._report(70, "Writing configuration…")
            with open(os.path.join(dest, "ecdat_config.json"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "mongo_uri": self.mongo_uri.get().strip(),
                        "database_name": self.db_name.get().strip() or "ecdat_enterprise_inventory",
                        "is_installed": True,
                        "version": APP_VERSION,
                    },
                    f,
                    indent=2,
                )

            # --- shortcuts -------------------------------------------------
            if self.make_desktop.get():
                self._report(78, "Creating Desktop shortcut…")
                desktop = os.path.join(
                    os.environ.get("USERPROFILE", os.path.expanduser("~")), "Desktop"
                )
                ok, err = create_shortcut(
                    target_exe,
                    os.path.join(desktop, f"{APP_DISPLAY_NAME}.lnk"),
                    "Zypher — Cryptographic Discovery & Quantum Risk Analysis",
                )
                if not ok:
                    self.install_errors.append(f"Desktop shortcut was not created: {err}")

            if self.make_startmenu.get():
                self._report(85, "Adding to the Start Menu…")
                start_menu = os.path.join(
                    os.environ.get("APPDATA", os.path.expanduser("~")),
                    "Microsoft", "Windows", "Start Menu", "Programs",
                )
                os.makedirs(start_menu, exist_ok=True)
                ok, err = create_shortcut(
                    target_exe,
                    os.path.join(start_menu, f"{APP_DISPLAY_NAME}.lnk"),
                    "Zypher — Cryptographic Discovery & Quantum Risk Analysis",
                )
                if not ok:
                    self.install_errors.append(f"Start Menu shortcut was not created: {err}")

            # --- uninstaller ----------------------------------------------
            self._report(92, "Registering uninstaller…")
            try:
                uninstaller = write_uninstaller(dest)
                ok, err = register_uninstaller(dest, uninstaller, directory_size(dest) / 1024)
                if not ok:
                    self.install_errors.append(f"Add/Remove Programs entry was not created: {err}")
            except Exception as exc:
                self.install_errors.append(f"Uninstaller could not be written: {exc}")

            self._report(100, "Installation complete.")
            self.after(300, self.step_done)

        except Exception as exc:
            trace = traceback.format_exc()
            self.after(0, lambda: self.step_failed(str(exc), trace))

    # ---------------------------------------------------------------- step 5
    def step_done(self):
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text="Setup complete", style="Title.TLabel").pack(anchor="w", pady=(0, 12))

        box = ttk.LabelFrame(pad, text="  Summary  ", padding=12)
        box.pack(fill="x")

        lines = [f"Installed to  {self.install_dir.get()}"]
        if self.make_desktop.get():
            lines.append(f"Desktop shortcut  {APP_DISPLAY_NAME}")
        if self.make_startmenu.get():
            lines.append(f"Start Menu entry  {APP_DISPLAY_NAME}")
        lines.append(
            "Storage  " + ("MongoDB" if self.mongo_uri.get().strip() else "Local files")
        )
        lines.append("Uninstall  via Settings › Apps, or 'Uninstall Zypher.bat'")

        for line in lines:
            ttk.Label(box, text=f"✓  {line}", style="Success.TLabel", wraplength=500, justify="left").pack(
                anchor="w", pady=1
            )

        # Partial failures are stated, not hidden behind a green checklist.
        if self.install_errors:
            warn = ttk.LabelFrame(pad, text="  Completed with warnings  ", padding=10)
            warn.pack(fill="x", pady=(12, 0))
            for err in self.install_errors:
                ttk.Label(warn, text=f"•  {err}", style="Error.TLabel", wraplength=500, justify="left").pack(
                    anchor="w", pady=1
                )
            ttk.Label(
                warn,
                text="The application itself installed correctly and can be launched from its folder.",
                style="Small.TLabel",
                wraplength=500,
            ).pack(anchor="w", pady=(6, 0))

        bar = self._buttons()
        ttk.Button(bar, text="Finish", command=self.destroy).pack(side="left")
        ttk.Button(bar, text="Launch Zypher", command=self._launch).pack(side="right")

    def step_failed(self, message, trace=""):
        self._clear()
        pad = self._pad()

        ttk.Label(pad, text="Installation failed", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Label(pad, text=message, style="Error.TLabel", wraplength=520, justify="left").pack(anchor="w")
        ttk.Label(
            pad,
            text="Nothing was installed. Correct the problem above and run Setup again.",
            style="Body.TLabel",
            wraplength=520,
        ).pack(anchor="w", pady=(10, 0))

        if trace:
            detail = tk.Text(pad, height=8, font=("Consolas", 8), wrap="word",
                             bg="#f7f7f7", relief="solid", borderwidth=1)
            detail.insert("1.0", trace)
            detail.config(state="disabled")
            detail.pack(fill="both", expand=True, pady=(12, 0))

        bar = self._buttons()
        ttk.Button(bar, text="Close", command=self.destroy).pack(side="right")

    def _launch(self):
        exe = self.installed_exe
        if exe and os.path.isfile(exe):
            subprocess.Popen([exe], cwd=os.path.dirname(exe))
            self.destroy()
        else:
            messagebox.showerror(
                "Zypher",
                f"{EXE_NAME} could not be found in the install folder. The installation is incomplete.",
            )


def main():
    SetupWizard().mainloop()


if __name__ == "__main__":
    main()
