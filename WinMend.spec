# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files

# Pull in CustomTkinter's bundled themes and images automatically
ctk_datas = collect_data_files('customtkinter')

a = Analysis(
    ['WinMend.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Fonts
        ('Chopsic.otf', '.'),
        ('ThisAppeal-FreeDemo.ttf', '.'),
        ('Evogria.otf', '.'),
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
    upx=True,
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
