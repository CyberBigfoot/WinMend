"""WinMend core: preferences."""

from __future__ import annotations

import os


def _get_pref_path(filename):
    """Return path to a preference file stored in %APPDATA%\\WinMend."""
    appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
    pref_dir = os.path.join(appdata, 'WinMend')
    os.makedirs(pref_dir, exist_ok=True)
    return os.path.join(pref_dir, filename)
