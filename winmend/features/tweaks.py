"""WinMend features: tweaks."""

from __future__ import annotations

from winmend.core.registry_values import _hive
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ---------------------------------------------------------------------------
# Windows preference tweaks
#
# Every tweak here is one or more registry VALUES with a defined on-state and
# off-state, which is what makes the page honest in both directions: the switch
# shows what the registry actually says right now (not what WinMend last wrote),
# and flipping it back restores the other state exactly. Nothing is deleted
# except values WinMend itself added, and nothing needs an "undo script".
#
# The keys, value names and numbers were taken from Chris Titus's WinUtil
# (config/tweaks.json), which is where they have been exercised on real
# machines -- they are deliberately NOT invented here. One WinUtil toggle was
# left out on purpose: "File Explorer Automatic Folder Discovery" works by
# recursively deleting the Bags/BagMRU trees, which is destructive and not a
# reversible switch.
# ---------------------------------------------------------------------------

REMOVE = object()   # sentinel: this state is expressed by the value being absent


class TweakValue:
    """One registry value, with the data that means "on" and "off".

    optional  a companion value that improves the tweak but is not what makes
              it work -- if it needs rights we do not have, it is skipped
              instead of failing the whole toggle.
    mask      for values that are bitfields rather than a single setting: only
              these bits are read and written, so the other bits (someone
              else's preferences) survive the toggle untouched.
    """

    __slots__ = ("root", "path", "name", "kind", "on", "off", "optional", "mask")

    def __init__(self, root, path, name, kind, on, off, optional=False, mask=0):
        self.root = root          # "HKCU" | "HKLM" | "HKU"
        self.path = path
        self.name = name
        self.kind = kind          # "dword" | "string"
        self.on = on              # value, or REMOVE
        self.off = off
        self.optional = optional
        self.mask = mask

    def needs_admin(self):
        return self.root in ("HKLM", "HKU") and not self.optional


class WindowsTweak:
    """One user-facing switch.

    default_on  what Windows does when the value is absent -- so a machine that
                has never been tweaked reads correctly instead of showing every
                switch off.
    after       what has to happen before the change is visible:
                "" | "explorer" | "signout" | "reboot".
    reader/     for the rare setting that is not a registry value at all (a key
    writer      that exists or does not). When set, they replace the value
                machinery so the page can treat every switch identically.
    """

    __slots__ = ("id", "name", "description", "group", "values",
                 "default_on", "after", "note", "reader", "writer", "admin")

    def __init__(self, id, name, description, group, values,
                 default_on=True, after="", note="", reader=None, writer=None,
                 admin=False):
        self.id = id
        self.name = name
        self.description = description
        self.group = group
        self.values = values
        self.default_on = default_on
        self.after = after
        self.note = note
        self.reader = reader
        self.writer = writer
        self.admin = admin

    def needs_admin(self):
        return self.admin or any(v.needs_admin() for v in self.values)


def _read_typed(value):
    """(data, registry type) for one TweakValue, or (REMOVE, None) if unset."""
    try:
        with winreg.OpenKey(_hive(value.root), value.path) as key:
            return winreg.QueryValueEx(key, value.name)
    except OSError:
        return REMOVE, None


def _read_value(value):
    """Current data for one TweakValue, or REMOVE if it is not set."""
    return _read_typed(value)[0]


def _matches(current, wanted, mask=0):
    if wanted is REMOVE or current is REMOVE:
        return current is wanted
    if mask:
        try:
            return (int(current) & mask) == (int(wanted) & mask)
        except (TypeError, ValueError):
            return False
    # registry string values come back as str, dwords as int; compare loosely
    # so "2" and 2 do not read as different states
    return str(current).strip().lower() == str(wanted).strip().lower()


def _masked_write(current, wanted, mask):
    """The new value: `wanted`'s bits inside the mask, everything else kept."""
    try:
        base = int(current) if current is not REMOVE else 0
    except (TypeError, ValueError):
        base = 0
    return (base & ~mask) | (int(wanted) & mask)


def read_tweak_state(tweak):
    """True (on), False (off), or None if the registry could not be read.

    The FIRST value decides -- a tweak's extra values are companions, and a
    half-applied tweak should read as whatever its headline value says rather
    than refusing to display.
    """
    if winreg is None:
        return None
    if tweak.reader is not None:
        try:
            return tweak.reader()
        except Exception:
            return None
    primary = tweak.values[0]
    try:
        current = _read_value(primary)
    except Exception:
        return None
    if _matches(current, primary.on, primary.mask):
        return True
    if _matches(current, primary.off, primary.mask):
        return False
    if current is REMOVE:
        return bool(tweak.default_on)
    # Some other value entirely (a third state, or set by another tool). Report
    # it as "not the on-state" rather than guessing.
    return False


def apply_tweak(tweak, enable):
    """Write one tweak's on- or off-state. Returns "" on success, else why not."""
    if winreg is None:
        return "Registry access is unavailable."
    if tweak.writer is not None:
        return tweak.writer(enable)
    for value in tweak.values:
        wanted = value.on if enable else value.off
        try:
            if wanted is REMOVE:
                try:
                    with winreg.OpenKey(_hive(value.root), value.path, 0,
                                        winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, value.name)
                except FileNotFoundError:
                    pass          # already absent: that IS the requested state
            else:
                current, existing_kind = _read_typed(value)
                # If the value already exists, write back the type it already
                # has. Windows is inconsistent about this -- StickyKeys' Flags
                # is a REG_SZ holding a number -- and rewriting a REG_SZ as a
                # REG_DWORD changes something the user never asked us to touch.
                kind = existing_kind
                if kind not in (winreg.REG_DWORD, winreg.REG_SZ):
                    kind = winreg.REG_DWORD if value.kind == "dword" else winreg.REG_SZ
                if value.mask:
                    # Bitfield: keep every bit this tweak is not about.
                    data = _masked_write(current, wanted, value.mask)
                else:
                    data = wanted
                data = int(data) if kind == winreg.REG_DWORD else str(data)
                with winreg.CreateKeyEx(_hive(value.root), value.path, 0,
                                        winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, value.name, 0, kind, data)
        except PermissionError:
            if value.optional:
                continue
            return ("This setting applies to everyone on the PC — restart "
                    "WinMend as administrator to change it.")
        except OSError as exc:
            if value.optional:
                continue
            return f"Windows refused the change: {exc}"
    return ""


# The classic Windows 11 context menu is a key that exists or does not, rather
# than a value, so it gets its own pair of functions instead of a TweakValue.
CLASSIC_MENU_KEY = (r"Software\Classes\CLSID"
                    r"\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}")


def read_classic_context_menu():
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            CLASSIC_MENU_KEY + r"\InprocServer32"):
            return True
    except OSError:
        return False


def set_classic_context_menu(enable):
    """Restore or remove the pre-Windows 11 right-click menu.

    Enabling creates an empty InprocServer32 default value, which is the
    documented way to opt out of the new menu; disabling deletes only the key
    WinMend created, so this is fully reversible.
    """
    if winreg is None:
        return "Registry access is unavailable."
    try:
        if enable:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  CLASSIC_MENU_KEY + r"\InprocServer32") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "")
        else:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                                 CLASSIC_MENU_KEY + r"\InprocServer32")
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, CLASSIC_MENU_KEY)
            except FileNotFoundError:
                pass
        return ""
    except OSError as exc:
        return f"Windows refused the change: {exc}"


def _v(root, path, name, kind, on, off, optional=False, mask=0):
    return TweakValue(root, path, name, kind, on, off, optional, mask)


_EXPLORER_ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"


_SEARCH = r"Software\Microsoft\Windows\CurrentVersion\Search"


WM_TWEAKS = [
    # ---- Appearance ----
    WindowsTweak(
        "dark_theme", "Dark theme",
        "Dark colours for Windows and for apps that follow the system theme.",
        "Appearance",
        [_v("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "AppsUseLightTheme", "dword", 0, 1),
         _v("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "SystemUsesLightTheme", "dword", 0, 1)],
        default_on=False, after="explorer"),
    WindowsTweak(
        "scrollbars", "Always show scrollbars",
        "Keeps scrollbars visible instead of letting Windows shrink them away "
        "when the mouse moves off.",
        "Appearance",
        [_v("HKCU", r"Control Panel\Accessibility", "DynamicScrollbars", "dword", 0, 1)],
        default_on=False, after="signout"),
    WindowsTweak(
        "settings_home", "Settings app home page",
        "The summary page the Settings app opens on. Off goes straight to the "
        "System list.",
        "Appearance",
        # On removes the policy rather than writing "show:home" -- absent is the
        # real Windows default, and an unrecognised filter string only happens
        # to work.
        [_v("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "SettingsPageVisibility", "string", REMOVE, "hide:home")],
        default_on=True),
    WindowsTweak(
        "logon_blur", "Blurred sign-in background",
        "The frosted blur behind the sign-in screen. Off shows the wallpaper sharp.",
        "Appearance",
        [_v("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableAcrylicBackgroundOnLogon", "dword", 0, 1)],
        default_on=True),

    # ---- File Explorer ----
    WindowsTweak(
        "file_extensions", "Show file extensions",
        "Shows .exe, .png and the rest in File Explorer. Worth leaving on — "
        "hidden extensions are how a file pretends to be something it isn't.",
        "File Explorer",
        [_v("HKCU", _EXPLORER_ADV, "HideFileExt", "dword", 0, 1)],
        default_on=False, after="explorer"),
    WindowsTweak(
        "hidden_files", "Show hidden files",
        "Reveals files and folders Windows normally keeps out of sight.",
        "File Explorer",
        # 1 = show, 2 = don't show. WinUtil writes 0 for off; Explorer treats
        # anything but 1 as "don't show", but 2 is what the Folder Options
        # dialog itself writes, so a user who later opens that dialog sees a
        # checkbox that agrees with reality.
        [_v("HKCU", _EXPLORER_ADV, "Hidden", "dword", 1, 2)],
        default_on=False, after="explorer"),
    WindowsTweak(
        "classic_menu", "Classic right-click menu",
        "The full Windows 10 context menu instead of Windows 11's short one "
        "with 'Show more options' at the bottom.",
        "File Explorer", [],
        default_on=False, after="explorer",
        reader=read_classic_context_menu, writer=set_classic_context_menu),
    WindowsTweak(
        "explorer_home", "Home and Gallery in Explorer",
        "The Home and Gallery entries in Explorer's sidebar. Off removes both "
        "and opens This PC instead.",
        "File Explorer",
        [_v("HKCU", r"Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}",
            "System.IsPinnedToNameSpaceTree", "dword", REMOVE, 0),
         _v("HKCU", r"Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}",
            "System.IsPinnedToNameSpaceTree", "dword", REMOVE, 0),
         _v("HKCU", _EXPLORER_ADV, "LaunchTo", "dword", REMOVE, 1)],
        default_on=True, after="explorer"),

    # ---- Taskbar & Start ----
    WindowsTweak(
        "taskbar_centre", "Center the taskbar icons",
        "Windows 11's centered taskbar. Off pins the icons to the left, "
        "Windows 10 style.",
        "Taskbar & Start",
        [_v("HKCU", _EXPLORER_ADV, "TaskbarAl", "dword", 1, 0)],
        default_on=True, after="explorer"),
    WindowsTweak(
        "taskbar_search", "Search button on the taskbar",
        "The search icon next to Start.",
        "Taskbar & Start",
        [_v("HKCU", _SEARCH, "SearchboxTaskbarMode", "dword", 1, 0)],
        default_on=True, after="explorer"),
    WindowsTweak(
        "task_view", "Task View button",
        "The virtual-desktops button on the taskbar.",
        "Taskbar & Start",
        [_v("HKCU", _EXPLORER_ADV, "ShowTaskViewButton", "dword", 1, 0)],
        default_on=True, after="explorer"),
    WindowsTweak(
        "bing_search", "Web results in Start search",
        "Bing results mixed into the Start menu search. Off searches only this PC.",
        "Taskbar & Start",
        [_v("HKCU", _SEARCH, "BingSearchEnabled", "dword", 1, 0)],
        default_on=True, after="explorer"),
    WindowsTweak(
        "start_recommendations", "Start menu recommendations",
        "The recommended files and apps below the pinned tiles.",
        "Taskbar & Start",
        [_v("HKLM", r"SOFTWARE\Microsoft\PolicyManager\current\device\Start",
            "HideRecommendedSection", "dword", 0, 1),
         _v("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "HideRecommendedSection", "dword", 0, 1)],
        default_on=True, after="explorer",
        note="Turning this off also hides Windows Spotlight on the lock screen."),
    WindowsTweak(
        "end_task", "End task on taskbar right-click",
        "Adds End task to the right-click menu of taskbar buttons, so a frozen "
        "app can be killed without opening Task Manager.",
        "Taskbar & Start",
        [_v("HKCU", _EXPLORER_ADV + r"\TaskbarDeveloperSettings",
            "TaskbarEndTask", "dword", 1, REMOVE)],
        default_on=False, after="explorer"),
    WindowsTweak(
        "battery_percentage", "Battery percentage in the tray",
        "Shows the number next to the battery icon. Laptops only — desktops "
        "have no battery icon to label.",
        "Taskbar & Start",
        [_v("HKCU", _EXPLORER_ADV, "IsBatteryPercentageEnabled", "dword", 1, REMOVE)],
        default_on=False, after="explorer"),

    # ---- Input ----
    WindowsTweak(
        "mouse_acceleration", "Mouse acceleration",
        "Lets pointer distance depend on how fast you move the mouse. Off gives "
        "1:1 movement, which most games want.",
        "Input",
        [_v("HKCU", r"Control Panel\Mouse", "MouseSpeed", "dword", 1, 0),
         _v("HKCU", r"Control Panel\Mouse", "MouseThreshold1", "dword", 6, 0),
         _v("HKCU", r"Control Panel\Mouse", "MouseThreshold2", "dword", 10, 0)],
        default_on=True, after="signout"),
    WindowsTweak(
        "num_lock", "Num Lock on at startup",
        "Turns the number pad on at the sign-in screen instead of leaving it off.",
        "Input",
        [_v("HKCU", r"Control Panel\Keyboard",
            "InitialKeyboardIndicators", "string", "2", "0"),
         # .DEFAULT is what the sign-in screen itself uses. It needs admin, but
         # the HKCU value above is what affects the signed-in session, so this
         # one is skipped rather than blocking the toggle when unelevated.
         _v("HKU", r".DEFAULT\Control Panel\Keyboard",
            "InitialKeyboardIndicators", "string", "2", "0", optional=True)],
        default_on=False),
    WindowsTweak(
        "window_snapping", "Window snapping",
        "Snapping windows to the screen edges when you drag them there.",
        "Input",
        [_v("HKCU", r"Control Panel\Desktop",
            "WindowArrangementActive", "string", "1", "0")],
        default_on=True, after="signout"),
    WindowsTweak(
        "sticky_keys", "Sticky Keys shortcut",
        "The prompt that appears when Shift is pressed five times.",
        "Input",
        # Flags is a REG_SZ holding a number (verified on this machine, and its
        # ToggleKeys / Keyboard Response siblings match), and it is a bitfield
        # of several accessibility preferences. 0x08 is SKF_HOTKEYACTIVE, the
        # five-taps shortcut. WinUtil writes the whole value (506/58), which
        # discards whatever else the user had set -- this machine reads 498,
        # neither of those. Masking touches only the bit the switch is about.
        [_v("HKCU", r"Control Panel\Accessibility\StickyKeys",
            "Flags", "string", 0x08, 0x00, mask=0x08)],
        default_on=True),

    # ---- System ----
    WindowsTweak(
        "game_mode", "Game Mode",
        "Lets Windows prioritise a game over background work while it is running.",
        "System",
        [_v("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled", "dword", 1, 0),
         _v("HKCU", r"Software\Microsoft\GameBar", "AllowAutoGameMode", "dword", 1, 0)],
        default_on=True),
    WindowsTweak(
        "fullscreen_optimizations", "Fullscreen optimizations",
        "Windows' borderless-window substitute for exclusive fullscreen. Off can "
        "cut input lag in games, but disables colour management in exclusive "
        "fullscreen.",
        "System",
        [_v("HKCU", r"System\GameConfigStore",
            "GameDVR_DXGIHonorFSEWindowsCompatible", "dword", 0, 1)],
        default_on=True),
    WindowsTweak(
        "background_apps", "Background apps",
        "Lets Store apps keep running when you are not using them.",
        "System",
        [_v("HKCU", r"Software\Microsoft\Windows\CurrentVersion"
                    r"\BackgroundAccessApplications",
            "GlobalUserDisabled", "dword", 0, 1)],
        default_on=True),
    WindowsTweak(
        "notifications", "Notifications and calendar",
        "Toast notifications and the calendar flyout on the clock. Off silences "
        "every app, including reminders.",
        "System",
        [_v("HKCU", r"Software\Microsoft\Windows\CurrentVersion\PushNotifications",
            "ToastEnabled", "dword", 1, 0),
         _v("HKCU", r"Software\Policies\Microsoft\Windows\Explorer",
            "DisableNotificationCenter", "dword", REMOVE, 1)],
        default_on=True, after="explorer"),
    WindowsTweak(
        "lock_screen", "Lock screen before sign-in",
        "The wallpaper-and-clock screen you dismiss before typing a password. "
        "Off goes straight to the sign-in box.",
        "System",
        [_v("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
            "NoLockScreen", "dword", REMOVE, 1)],
        default_on=True),
    WindowsTweak(
        "long_paths", "Long file path support",
        "Lets programs use paths longer than 260 characters. Safe to leave on; "
        "some older programs ignore it either way.",
        "System",
        [_v("HKLM", r"SYSTEM\CurrentControlSet\Control\FileSystem",
            "LongPathsEnabled", "dword", 1, 0)],
        default_on=False, after="reboot"),
    WindowsTweak(
        "verbose_logon", "Detailed sign-in messages",
        "Shows what Windows is actually doing during sign-in and shutdown "
        "instead of 'Please wait'. Useful when a boot is mysteriously slow.",
        "System",
        [_v("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "VerboseStatus", "dword", 1, 0)],
        default_on=False, after="reboot"),
    WindowsTweak(
        "detailed_bsod", "Detailed blue screens",
        "Puts the technical stop-code details back on the blue screen instead of "
        "just a sad face — worth having before a crash, not after.",
        "System",
        [_v("HKLM", r"SYSTEM\CurrentControlSet\Control\CrashControl",
            "DisplayParameters", "dword", 1, 0),
         _v("HKLM", r"SYSTEM\CurrentControlSet\Control\CrashControl",
            "DisableEmoticon", "dword", 1, 0)],
        default_on=False, after="reboot"),
]


def tweak_groups():
    """Tweaks in display order, grouped, preserving the order above."""
    groups = []
    for tweak in WM_TWEAKS:
        if not groups or groups[-1][0] != tweak.group:
            groups.append((tweak.group, []))
        groups[-1][1].append(tweak)
    return groups
