# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_data_files

# Pull in CustomTkinter's bundled themes and images automatically
ctk_datas = collect_data_files('customtkinter')
build_mode = os.environ.get('WINMEND_BUILD_MODE', 'onefile').strip().lower()
if build_mode not in {'onefile', 'onedir'}:
    raise ValueError("WINMEND_BUILD_MODE must be 'onefile' or 'onedir'")

a = Analysis(
    ['WinMend.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Fonts
        ('Chopsic.otf', '.'),
        ('Exo2-Regular.otf', '.'),
        ('Codec-Cold-Bold-trial.ttf', '.'),
        ('Microsport Bold.ttf', '.'),
        ('TT Lakes Neue Trial Regular.ttf', '.'),
        ('NIKEA.otf', '.'),
        # Assets
        ('icon.ico', '.'),
    ] + ctk_datas,
    hiddenimports=['customtkinter'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if build_mode == 'onedir':
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='WinMend',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        uac_admin=True,
        icon=['icon.ico'],
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name='WinMend',
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='WinMend',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        uac_admin=True,
        icon=['icon.ico'],
    )
