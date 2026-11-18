# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_data_files

# Bundle certifi's CA cert bundle explicitly so the Speed Test's TLS calls can
# always find a valid bundle. Without it, requests raises "Could not find a
# suitable TLS CA certificate bundle, invalid path" in the frozen build.
certifi_datas = collect_data_files('certifi')
# python310.dll imports VCRUNTIME140.dll, but CPython 3.10 does not place a copy
# in its install directory -- it relies on the machine-wide "Visual C++ 2015-2022
# Redistributable". So PyInstaller has nothing to bundle at the root, and the
# frozen app silently inherits that redistributable as an install requirement.
# On a machine without it the bootloader cannot resolve python310.dll's imports
# and dies with "Failed to load Python DLL ... python310.dll" before any of our
# code runs. The VCRUNTIME140*.dll copies nested under PySide6/ and shiboken6/
# do not help: the loader does not search those subdirectories on behalf of
# python310.dll.
#
# Microsoft permits app-local deployment of the VC++ runtime, which is exactly
# how the PySide6 and shiboken6 wheels ship it, so reuse their copies at the
# bundle root. They are newer than the toolset python310.dll was built with, and
# the v14x runtime is backward compatible, so this is safe.
def _vcruntime_binaries():
    import glob
    import sysconfig
    site_packages = sysconfig.get_paths()['purelib']
    found = {}
    for package in ('shiboken6', 'PySide6'):
        for path in glob.glob(os.path.join(site_packages, package, 'vcruntime140*.dll')):
            found.setdefault(os.path.basename(path).upper(), path)
    if 'VCRUNTIME140.DLL' not in found:
        raise RuntimeError(
            'VCRUNTIME140.dll not found in the PySide6/shiboken6 wheels; the build '
            'would only run on machines that already have the VC++ redistributable.'
        )
    return [(path, '.') for path in found.values()]

vcruntime_binaries = _vcruntime_binaries()
print('WinMend.spec: bundling VC++ runtime at root: %s'
      % ', '.join(os.path.basename(src) for src, _ in vcruntime_binaries))

build_mode = os.environ.get('WINMEND_BUILD_MODE', 'onefile').strip().lower()
if build_mode not in {'onefile', 'onedir'}:
    raise ValueError("WINMEND_BUILD_MODE must be 'onefile' or 'onedir'")

a = Analysis(
    ['WinMend.py'],
    pathex=[],
    binaries=vcruntime_binaries,
    # The six display fonts that used to be bundled here belonged to the old
    # tkinter theme (two of them trial-licensed). The Qt UI asks only for fonts
    # Windows already ships -- Segoe UI Variable / Segoe UI and Cascadia Mono /
    # Consolas -- so nothing is bundled and nothing is redistributed.
    datas=[
        ('icon.ico', '.'),
    ] + certifi_datas,
    # Keep historical import facades available alongside the new package.
    hiddenimports=['winmend.compat', 'winmend_safety', 'winmend_diagnostics', 'certifi'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# --- Strip OS-owned runtime DLLs -------------------------------------------
# PyInstaller resolves dependencies via PATH, and any JDK / third-party tool on
# PATH that ships a copy of the Universal C Runtime will get harvested into the
# bundle. Those copies are version-locked to the Windows build they came from,
# and because the onefile extraction dir is first in the DLL search order they
# override the target machine's own System32 copies. A newer ucrtbase.dll then
# fails to load on an older Windows, and the bootloader reports it as
# "Failed to load Python DLL ... python310.dll" (ucrtbase is a dependency of it).
#
# Microsoft only permits redistributing the SDK's app-local UCRT, never the
# System32 copy, and never the api-ms-win-* API-set stubs (the loader resolves
# those through ntdll's API set schema anyway, so shipping them is pointless).
# Dropping them makes every machine use its own in-box runtime, which is correct
# on Windows 10 and 11. The MSVC runtime that ships inside the PySide6 and
# shiboken6 wheels (VCRUNTIME140*.dll, MSVCP140*.dll) is a genuine
# redistributable and is deliberately left in place.
#
# Qt6Core also imports Windows' unversioned ICU functions from icuuc.dll.
# A Poppler installation on PATH can supply a different icuuc.dll exporting
# version-suffixed functions instead. Bundling that file makes QtCore fail with
# "The specified procedure could not be found" before the UI can start. Keep
# the Windows-owned ICU entry-point DLLs out of the bundle for the same reason.
def _is_os_runtime(entry):
    name = os.path.basename(entry[0]).lower()
    return name in {'ucrtbase.dll', 'icu.dll', 'icuuc.dll', 'icuin.dll'} or name.startswith('api-ms-win-')

_stripped = [b for b in a.binaries if _is_os_runtime(b)]
a.binaries = [b for b in a.binaries if not _is_os_runtime(b)]
if _stripped:
    print('WinMend.spec: dropped %d OS runtime DLL(s) from the bundle:' % len(_stripped))
    for _name, _src, _typ in sorted(_stripped):
        print('    %-44s <- %s' % (_name, _src))

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
