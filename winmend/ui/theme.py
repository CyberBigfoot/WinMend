"""WinMend ui: theme."""

from __future__ import annotations

import platform
import sys
import winreg


# ============================================================================
# ==================== WINMEND 2.0 — QT DESIGN SYSTEM ========================
# ============================================================================
# Fluent-style design tokens. Every colour in the Qt UI resolves through here;
# nothing hardcodes a hex value. Light and dark are the same token names, so a
# theme switch is a dict swap and a restyle -- never a code change.

WM_DARK = {
    'name':      'dark',
    'bg':        '#1B1B1B',   # window substrate
    'sidebar':   '#202020',   # nav + queue rails
    'card':      '#272727',   # task card rest
    'card_hi':   '#2F2F2F',   # task card hover / nav active
    'border':    '#3A3A3A',
    'border_hi': '#4A4A4A',
    'text':      '#FFFFFF',
    'text_2':    '#C7C7C7',   # secondary
    'text_3':    '#8B8B8B',   # tertiary / muted
    'accent':    '#0078D4',   # Windows blue
    'accent_hi': '#1A86D9',
    'accent_dim':'#0B3E6B',
    'ok':        '#6CCB5F',
    'warn':      '#FCE100',
    'danger':    '#FF6B7A',
    'shadow':    'rgba(0,0,0,0.45)',
}


WM_LIGHT = {
    'name':      'light',
    'bg':        '#F3F3F3',
    'sidebar':   '#EAEAEA',
    'card':      '#FFFFFF',
    'card_hi':   '#F7F7F7',
    'border':    '#E0E0E0',
    'border_hi': '#C8C8C8',
    'text':      '#1A1A1A',
    'text_2':    '#444444',
    'text_3':    '#707070',
    'accent':    '#0067C0',
    'accent_hi': '#1A7AD0',
    'accent_dim':'#CCE4F7',
    'ok':        '#0F7B0F',
    'warn':      '#9D5D00',
    'danger':    '#C42B1C',
    'shadow':    'rgba(0,0,0,0.10)',
}


# Type scale + rhythm. Segoe UI Variable is the Win11 system font; Segoe UI is
# the Win10 fallback. Both ship with the OS -- nothing is bundled, so there is
# no font redistribution licensing exposure.
WM_FONT = 'Segoe UI Variable Display, Segoe UI, sans-serif'


WM_FONT_MONO = 'Cascadia Mono, Consolas, monospace'


WM_ICON_FONT = 'Segoe Fluent Icons, Segoe MDL2 Assets'


# Segoe Fluent Icons / MDL2 codepoints — present on both Win10 and Win11.
WM_GLYPH = {
    'guide': '\ue946', 'journal': '\ue7a7',
    'dashboard': '', 'cleanup': '', 'repair': '',
    'performance': '', 'network': '', 'security': '',
    'updates': '',
    'storage': '',      # Hard drive
    'startup': '',  # LightningBolt
    # pages added by the category rebalance; reuse two known-good MDL2 glyphs
    'diagnostics': '',   # DeveloperTools
    'advanced': '',      # AllApps
    # general-purpose glyphs; WM_GLYPH is looked up by key, so these stay
    # even where no page currently names one
    'hardware': '', 'utilities': '',
    'settings': '', 'search': '', 'run': '',
    'cancel': '', 'done': '', 'wait': '',
    'shield': '', 'undo': '', 'collapse': '',
    'expand': '', 'warn': '', 'info': '',
}


# speedtest reuses the network glyph -- avoids a wrong PUA codepoint that
# would render as tofu on machines missing the newer Fluent icon font.
WM_GLYPH['speedtest'] = WM_GLYPH.get('network', '')


# App catalogue: MDL2 "Download" (U+E896) -- checked against both segmdl2.ttf
# (Win10) and segoeicons.ttf (Win11) before being used, so it cannot render as
# tofu the way a guessed PUA codepoint would. The Windows Settings page uses
# MDL2 "Switch" (U+F19E), checked the same way.
WM_GLYPH['apps'] = ''


WM_GLYPH['tweaks'] = ''


def wm_windows_name():
    """Human-readable Windows name, e.g. 'Windows 11  ·  build 26200'.

    platform.release() reports '10' on Windows 11 -- the version number Microsoft
    kept for application compatibility. Build 22000 is the real Win10/11 boundary,
    so read the build directly rather than trusting release().
    """
    try:
        build = sys.getwindowsversion().build
        return f"{'Windows 11' if build >= 22000 else 'Windows 10'}  ·  build {build}"
    except Exception:
        return f"{platform.system()} {platform.release()}"


def wm_detect_windows_theme():
    """Return 'light' or 'dark' from the user's Windows personalisation setting.

    Falls back to dark (WinMend's historical default) if the key is unreadable.
    """
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as k:
            # AppsUseLightTheme: 0 = dark, 1 = light
            return 'light' if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] else 'dark'
    except (OSError, FileNotFoundError, IndexError):
        return 'dark'


def wm_load_theme_pref():
    """Start with Windows' current theme; manual overrides last this session."""
    return WM_LIGHT if wm_detect_windows_theme() == 'light' else WM_DARK
