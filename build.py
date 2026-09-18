"""
Zypher build orchestrator.

Build order is not optional here, and getting it wrong is exactly how the
shipped installer came to be empty: Zypher_Setup.spec bundles ``dist/Zypher`` as
data, so if the setup executable is built before (or without) the application,
PyInstaller silently packages nothing and produces a 12 MB installer that
installs no files.

This script enforces the order and verifies each stage:

    1. npm run build            → frontend/dist
    2. pyinstaller Zypher.spec   → dist/Zypher/Zypher.exe
    3. pyinstaller Zypher_Setup.spec → dist/Zypher_Setup.exe

and then asserts that the finished installer actually contains the payload.

Usage:
    python build.py                # everything
    python build.py --app          # frontend + application, skip the installer
    python build.py --skip-frontend
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.dirname(__file__))
FRONTEND = os.path.join(ROOT, "frontend")
DIST = os.path.join(ROOT, "dist")
APP_DIR = os.path.join(DIST, "Zypher")
APP_EXE = os.path.join(APP_DIR, "Zypher.exe")
SETUP_EXE = os.path.join(DIST, "Zypher_Setup.exe")


class BuildError(Exception):
    pass


def log(step, message):
    print(f"[{step}] {message}", flush=True)


def run(cmd, cwd=None, step="run"):
    log(step, " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd, shell=(os.name == "nt" and cmd[0] in {"npm", "npx"}))
    if result.returncode != 0:
        raise BuildError(f"{cmd[0]} failed with exit code {result.returncode}")


def human(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def _built_css(frontend_dir):
    """Every CSS file the frontend build emitted."""
    assets = os.path.join(frontend_dir, "dist", "assets")
    if not os.path.isdir(assets):
        return []
    return [os.path.join(assets, n) for n in os.listdir(assets) if n.endswith(".css")]


def build_frontend():
    log("1/3", "Building the frontend bundle")
    if not os.path.isdir(os.path.join(FRONTEND, "node_modules")):
        run(["npm", "install"], cwd=FRONTEND, step="1/3")
    run(["npm", "run", "build"], cwd=FRONTEND, step="1/3")

    index = os.path.join(FRONTEND, "dist", "index.html")
    if not os.path.isfile(index):
        raise BuildError("frontend/dist/index.html was not produced.")

    # Fonts and stylesheets must be bundled, not fetched: this is an offline
    # desktop app, so a remote asset simply never loads. Comments are stripped
    # first so a comment *mentioning* a CDN does not trip the check.
    import re as _re

    for asset in (index, *_built_css(FRONTEND)):
        with open(asset, "r", encoding="utf-8") as f:
            text = f.read()
        text = _re.sub(r"<!--.*?-->", "", text, flags=_re.S)
        text = _re.sub(r"/\*.*?\*/", "", text, flags=_re.S)
        # Only URLs in a fetch position count. An XML namespace inside an inline
        # SVG (http://www.w3.org/2000/svg) is an identifier, not a request.
        remote = [
            url
            for url in _re.findall(
                r"""(?:href|src)\s*=\s*["'](https?://[^"']+)|url\(\s*["']?(https?://[^"')]+)""",
                text,
            )
            for url in (url[0] or url[1],)
            if not url.startswith(("http://www.w3.org/", "https://www.w3.org/"))
        ]
        if remote:
            raise BuildError(
                f"{os.path.basename(asset)} references remote assets: "
                f"{', '.join(sorted(set(remote))[:3])}. Everything must be bundled "
                f"so the packaged app renders correctly offline."
            )

    fonts = [
        n for n in os.listdir(os.path.join(FRONTEND, "dist", "assets"))
        if n.endswith((".woff", ".woff2"))
    ]
    if not fonts:
        raise BuildError("No font files were emitted — the bundled fonts are missing.")

    log("1/3", f"OK · {human(dir_size(os.path.join(FRONTEND, 'dist')))} · {len(fonts)} font files")


def build_app():
    log("2/3", "Building the application executable")
    if os.path.isdir(APP_DIR):
        shutil.rmtree(APP_DIR, ignore_errors=True)

    run([sys.executable, "-m", "PyInstaller", "Zypher.spec", "--noconfirm", "--clean"],
        cwd=ROOT, step="2/3")

    if not os.path.isfile(APP_EXE):
        raise BuildError(f"{APP_EXE} was not produced.")

    # The bundled SPA must actually be inside the build.
    internal = os.path.join(APP_DIR, "_internal")
    for required in [
        os.path.join(internal, "frontend", "dist", "index.html"),
    ]:
        if not os.path.exists(required):
            raise BuildError(f"Bundled resource missing from the build: {required}")

    # The tree-sitter grammars are a compiled extension PyInstaller does not
    # trace from a pure-Python import. If they are missing the app still runs —
    # it just quietly degrades to regex matching, losing real key sizes and
    # gaining comment false-positives. That must fail the build, not ship.
    grammars = [
        n for n in os.listdir(internal)
        if n.startswith("tree_sitter") or n == "_native.pyd"
    ] + [
        n for n in os.listdir(os.path.join(internal, "tree_sitter_language_pack"))
        if n.endswith((".pyd", ".dll", ".so"))
    ] if os.path.isdir(os.path.join(internal, "tree_sitter_language_pack")) else []
    if not grammars:
        raise BuildError(
            "tree-sitter grammars are not in the build — the packaged app would "
            "silently fall back to regex scanning. Check collect_dynamic_libs in "
            "Zypher.spec."
        )

    # The YARA rules are data files. If they are missing the app still runs and
    # still scans binaries, just with the older built-in tables — a silent loss
    # of coverage that must fail the build rather than ship.
    rules = os.path.join(internal, "backend", "scanners", "rules", "crypto.yar")
    if not os.path.isfile(rules):
        raise BuildError(
            "backend/scanners/rules/crypto.yar is not in the build — binary "
            "scanning would silently fall back to the built-in tables. Check the "
            "'datas' entry in Zypher.spec."
        )

    # Tier 4 is the same class of silent degradation: without the binary or its
    # rules the app runs and scans, but every key size passed through a helper
    # reverts to an assumed default. An assumed RSA-2048 in place of a real
    # RSA-1024 is a wrong risk band, not a missing detail, so a build that has
    # lost either piece must fail here.
    taint_rules = os.path.join(internal, "backend", "scanners", "rules", "crypto-taint.yaml")
    if not os.path.isfile(taint_rules):
        raise BuildError(
            "backend/scanners/rules/crypto-taint.yaml is not in the build — "
            "dataflow analysis would be unavailable and key sizes would fall back "
            "to assumed defaults. Check the 'datas' entry in Zypher.spec."
        )
    with open(taint_rules, encoding="utf-8") as f:
        declared = sum(1 for line in f if line.lstrip().startswith("- id:"))
    if declared < 15:
        raise BuildError(
            f"crypto-taint.yaml shipped with only {declared} rules; the rule set "
            f"looks truncated."
        )

    opengrep = os.path.join(internal, "vendor", "opengrep", "opengrep.exe")
    if not os.path.isfile(opengrep):
        raise BuildError(
            "vendor/opengrep/opengrep.exe is not in the build — dataflow analysis "
            "would be unavailable. Check the 'datas' entry in Zypher.spec."
        )
    # A truncated or UPX-mangled copy would still be present and still fail at
    # run time, so the shipped binary is executed rather than merely counted.
    probe = subprocess.run([opengrep, "--version"], capture_output=True, text=True,
                           timeout=120)
    if probe.returncode != 0 or not (probe.stdout or "").strip():
        raise BuildError(
            f"the bundled opengrep.exe does not run (exit {probe.returncode}). "
            f"If UPX was applied to it, exclude it in Zypher.spec."
        )
    log("2/3", f"dataflow engine bundled: opengrep {probe.stdout.strip()} "
               f"· {declared} taint rules")

    # LGPL-2.1 redistribution requires the licence to travel with the binary.
    for required_doc in ["LICENSE", "NOTICE.md"]:
        doc = os.path.join(internal, "vendor", "opengrep", required_doc)
        if not os.path.isfile(doc):
            raise BuildError(
                f"vendor/opengrep/{required_doc} is missing from the build. "
                f"OpenGrep is redistributed under LGPL-2.1 and its licence text "
                f"must ship alongside it."
            )

    log("2/3", f"OK · {APP_EXE} · {human(dir_size(APP_DIR))}")


def purge_runtime_data():
    """Empty the packaged application's data directory before it is bundled."""
    data_dir = os.path.join(APP_DIR, "data_store")
    if not os.path.isdir(data_dir):
        return
    removed = 0
    for name in os.listdir(data_dir):
        path = os.path.join(data_dir, name)
        try:
            if os.path.isfile(path):
                os.remove(path)
                removed += 1
            else:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        except OSError as e:
            raise BuildError(
                f"Could not clear {path} before packaging: {e}. Shipping it "
                f"would put runtime data inside the installer."
            )
    if removed:
        log("3/3", f"Cleared {removed} file(s) from the packaged data directory")


def build_installer():
    log("3/3", "Building the installer")
    # Guard the ordering mistake that produced an empty installer.
    if not os.path.isfile(APP_EXE):
        raise BuildError(
            "Refusing to build the installer: dist/Zypher/Zypher.exe does not exist. "
            "The installer bundles that directory as its payload, so building it "
            "now would produce a setup executable that installs nothing."
        )

    # The installer bundles dist/Zypher wholesale, so anything left in the
    # application's own data directory ships to every customer. Two things end
    # up there from running the built app even once:
    #
    #   installation.json  the per-install identity. Shipping one would give
    #                      every installation the same id, and the whole point
    #                      of that id is to keep one installation's scans out of
    #                      another's view when they share a database.
    #   scan_*.json        somebody's actual scan results.
    #
    # Neither belongs in a distributable, and both are regenerated on first run.
    purge_runtime_data()

    if os.path.isfile(SETUP_EXE):
        os.remove(SETUP_EXE)

    run([sys.executable, "-m", "PyInstaller", "Zypher_Setup.spec", "--noconfirm", "--clean"],
        cwd=ROOT, step="3/3")

    if not os.path.isfile(SETUP_EXE):
        raise BuildError(f"{SETUP_EXE} was not produced.")

    verify_installer_payload()
    log("3/3", f"OK · {SETUP_EXE} · {human(os.path.getsize(SETUP_EXE))}")


def verify_installer_payload():
    """
    Confirm the installer really carries the application.

    The shipped Zypher_Setup.exe was 12 MB against a 106 MB payload and contained
    no reference to Zypher.exe at all. A size floor plus a content probe catches
    that class of failure before the file is distributed.
    """
    payload = dir_size(APP_DIR)
    setup = os.path.getsize(SETUP_EXE)

    # Compression is roughly 2-4x on this payload; anything under a third of it
    # cannot plausibly contain the application.
    floor = payload * 0.25
    if setup < floor:
        raise BuildError(
            f"The installer is {human(setup)} but the payload is {human(payload)}. "
            f"It almost certainly does not contain the application. "
            f"Check the 'datas' entry in Zypher_Setup.spec."
        )

    with open(SETUP_EXE, "rb") as f:
        blob = f.read()
    if b"Zypher.exe" not in blob:
        raise BuildError(
            "The installer does not reference Zypher.exe anywhere in its archive — "
            "the payload was not bundled."
        )

    log("3/3", f"Payload verified · installer {human(setup)} carries {human(payload)} of files")


def main():
    parser = argparse.ArgumentParser(description="Build Zypher.")
    parser.add_argument("--app", action="store_true", help="Build the app but not the installer.")
    parser.add_argument("--skip-frontend", action="store_true", help="Reuse the existing frontend/dist.")
    args = parser.parse_args()

    started = time.time()
    try:
        if not args.skip_frontend:
            build_frontend()
        else:
            log("1/3", "Skipped (using the existing frontend/dist)")

        build_app()

        if args.app:
            log("3/3", "Skipped (--app)")
        else:
            build_installer()

    except BuildError as exc:
        print(f"\nBUILD FAILED: {exc}\n", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    print(f"\nBuild finished in {time.time() - started:.0f}s")
    print(f"  Application : {APP_EXE}")
    if not args.app:
        print(f"  Installer   : {SETUP_EXE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
