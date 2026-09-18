# -*- mode: python ; coding: utf-8 -*-
# ECDAT Enterprise — PyInstaller Spec
# Builds the main ECDAT native desktop application

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules

# The grammars live in a single compiled extension (_native.pyd). PyInstaller
# does not trace it from the pure-Python import, and without it the packaged app
# would quietly lose syntax-aware detection and fall back to regex.
_ts_binaries = collect_dynamic_libs("tree_sitter_language_pack")
_ts_binaries += collect_dynamic_libs("tree_sitter")
# yara-x is a Rust extension; same problem, same fix.
_ts_binaries += collect_dynamic_libs("yara_x")

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=_ts_binaries,
    datas=[
        ('assets/zypher.ico', 'assets'),
        ('frontend/dist', 'frontend/dist'),
        # The YARA signatures and the Tier 4 taint rules are data, not code, so
        # PyInstaller does not trace them from any import. Without them the binary
        # scanner silently falls back to its built-in tables and dataflow
        # resolution stops happening.
        ('backend/scanners/rules', 'backend/scanners/rules'),
        # The OpenGrep binary for Tier 4. Carried as data rather than as a
        # `binaries` entry on purpose: it is an independent executable invoked as
        # a subprocess, not a Python extension to be loaded into this process,
        # and `datas` is also not subject to UPX compression. Its LICENSE and
        # NOTICE travel with it — LGPL-2.1 redistribution requires them.
        ('vendor/opengrep', 'vendor/opengrep'),
    ],
    hiddenimports=[
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'webview',
        'webview.platforms.edgechromium',
        'clr_loader',
        'pythonnet',
        'bottle',
        'fastapi',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.middleware.cors',
        'starlette.responses',
        'starlette.staticfiles',
        'anyio',
        'anyio._backends',
        'anyio._backends._asyncio',
        'pydantic',
        'pymongo',
        'dns',
        'cryptography',
        # X.509 parsing for the certificate scanner. PyInstaller does not
        # always follow the lazy import inside CertificateScanner, and a
        # missing parser would silently downgrade every certificate to
        # "unreadable" in the packaged build.
        'cryptography.x509',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.dsa',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.ed448',
        'config_manager',
        'backend',
        'backend.main',
        'backend.config',
        'backend.models',
        'backend.scanners',
        'backend.scan_jobs',
        'backend.scanners.walker',
        'backend.scanners.yara_engine',
        'yara_x',
        'backend.scanners.certificate_scanner',
        'backend.analysis.agility',
        'backend.analysis.delta',
        'backend.cbom.artefact_register',
        'backend.admin_session',
        'backend.recommendation.pqc_targets',
        'backend.recommendation.migration_planner',
        'backend.analysis.risk_inputs',
        'backend.scanners.ast_scanner',
        'tree_sitter',
        'tree_sitter_language_pack',
        'backend.scanners.source_scanner',
        'backend.scanners.binary_scanner',
        'backend.scanners.dependency_scanner',
        'backend.scanners.container_scanner',
        'backend.cbom',
        'backend.cbom.artefact_extractor',
        'backend.cbom.aggregator',
        'backend.cbom.purl',
        'backend.cbom.cbom_builder',
        'backend.cbom.storage',
        'backend.analysis',
        'backend.analysis.classifier',
        'backend.analysis.quantum_risk_engine',
        'backend.analysis.vulnerability_lookup',
        'backend.recommendation',
        'backend.recommendation.recommendation_engine',
        'backend.reporting',
        'backend.reporting.report_generator',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Zypher',
    icon='assets/zypher.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Zypher',
)
