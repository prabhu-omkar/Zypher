# -*- mode: python ; coding: utf-8 -*-
# ECDAT Enterprise — Setup Wizard PyInstaller Spec
# Builds the one-time installer/setup wizard executable

a = Analysis(
    ['installer_wizard.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('dist/Zypher', 'dist/Zypher'),
    ],
    hiddenimports=[],
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
    a.binaries,
    a.datas,
    [],
    name='Zypher_Setup',
    icon='assets/zypher.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
