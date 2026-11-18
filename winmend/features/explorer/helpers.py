"""WinMend features: explorer: helpers."""

from __future__ import annotations

from pathlib import Path
from winmend.features.startup.helpers import _resolve_lnk, file_company
import os
import re
import socket
import struct
import subprocess
import threading
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


def stop_explorer():
    """End every explorer.exe. "" on success, else the reason."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.run(["taskkill", "/f", "/im", "explorer.exe"],
                       capture_output=True, timeout=25, creationflags=flags)
    except Exception as exc:
        return f"Could not stop Explorer: {exc}"
    return ""


def start_explorer():
    """Launch the shell again. "" on success, else the reason."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.Popen([os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                                       "explorer.exe")], creationflags=flags)
    except Exception as exc:
        return f"Explorer did not come back automatically: {exc}"
    return ""


def restart_explorer():
    """Restart Explorer so shell tweaks show up without a sign-out.

    Explorer relaunches itself; the desktop and taskbar blink but nothing the
    user has open is closed.
    """
    return stop_explorer() or start_explorer()


# ---------------------------------------------------------------------------
# Closing Explorer so that it stays closed
#
# stop_explorer() ends Explorer by force. Windows counts that as a shell crash
# and starts a new Explorer within a second or two, which is harmless when the
# point is a restart, and fatal when the point is to get at files Explorer keeps
# open: the icon cache rebuild used to find the new Explorer holding the cache
# again before it reached the first file.
# ---------------------------------------------------------------------------

# WM_USER + 436: what the taskbar's own "Exit Explorer" command sends. The shell
# then quits cleanly, and a clean exit is not restarted.
_WM_EXIT_EXPLORER = 0x05B4


def _session_id(pid):
    """Desktop session of a process, or None when Windows will not say."""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
        out = wintypes.DWORD()
        if kernel32.ProcessIdToSessionId(int(pid), ctypes.byref(out)):
            return out.value
    except (AttributeError, OSError):
        pass
    return None


def session_explorer_pids():
    """Process ids of the explorer.exe processes in WinMend's own desktop session.

    Elevated, WinMend can see the Explorer of everyone signed in to this PC, and
    `taskkill /im explorer.exe` would end all of them. Only this session's is
    ours to close.
    """
    try:
        import psutil
    except ImportError:
        return set()
    own = _session_id(os.getpid())
    found = set()
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info.get("name") or "").lower() != "explorer.exe":
                continue
        except Exception:
            continue
        if own is None or _session_id(proc.pid) == own:
            found.add(proc.pid)
    return found


def _wait_for_no_explorer(timeout, poll):
    deadline = time.monotonic() + timeout
    while True:
        if not session_explorer_pids():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def close_explorer(wait=8.0, poll=0.1):
    """Close this session's Explorer without Windows starting it again.

    The taskbar is sent its own "Exit Explorer" message first. Anything still
    running after `wait` seconds (a folder window in its own process, or a shell
    that ignored the message) is then ended by force; if that was the shell,
    Windows may start it again by itself, so a caller must look before assuming
    Explorer is still closed.

    "" once no explorer.exe is left in this session, else the reason.
    """
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        user32.FindWindowW.restype = wintypes.HWND
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                        wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        tray = user32.FindWindowW("Shell_TrayWnd", None)
        if tray:
            user32.PostMessageW(tray, _WM_EXIT_EXPLORER, 0, 0)
    except (AttributeError, OSError):
        pass
    if _wait_for_no_explorer(wait, poll):
        return ""
    try:
        import psutil
    except ImportError:
        return "Explorer did not close, and it cannot be ended without psutil"
    for pid in session_explorer_pids():
        try:
            psutil.Process(pid).kill()
        except Exception:
            pass
    if _wait_for_no_explorer(5.0, poll):
        return ""
    return "Explorer would not close"


# Explorer's caches: IconCache.db in local app data (Windows 7 and earlier, still
# found on upgraded PCs), and iconcache_*.db / thumbcache_*.db beside each other
# in ...\Microsoft\Windows\Explorer.
ICON_CACHE_PREFIXES = ("iconcache_", "thumbcache_")


def icon_cache_files(local_appdata):
    """Full paths of Explorer's icon and thumbnail cache files.

    `local_appdata` is the folder in safe_delete.final_path() form, and the
    paths come back in the same form, ready for safe_delete.remove_tree().
    """
    found = []
    legacy = local_appdata + "\\IconCache.db"
    if os.path.isfile(legacy):
        found.append(legacy)
    folder = local_appdata + "\\Microsoft\\Windows\\Explorer"
    try:
        names = sorted(os.listdir(folder), key=str.lower)
    except OSError:
        names = []
    for name in names:
        if name.lower().startswith(ICON_CACHE_PREFIXES):
            path = folder + "\\" + name
            if os.path.isfile(path):
                found.append(path)
    return found


# ---------------------------------------------------------------------------
# File Explorer: Quick Access jump lists and dead network links
#
# Quick Access is a jump list: an OLE compound file under
# %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations whose DestList
# stream holds one entry per pinned or frequent folder. It is the most common
# reason Explorer opens slowly, for two reasons. The file corrupts, and Explorer
# then sits at "Working on it..." every time the list is drawn; and it fills
# with folders on servers, NAS boxes and mapped drives that are no longer
# there, each of which Explorer waits on before it draws anything.
#
# The DestList is read here directly, through Structured Storage, and NOT by
# enumerating the Quick Access shell namespace -- that enumeration is the very
# thing that stalls on a dead network entry.
# ---------------------------------------------------------------------------

# AppIDs Explorer files its own jump lists under. The first is the one Quick
# Access draws its pinned and frequent folders from; the second is its recent
# files; the third is the Windows 7/8 layout, still present on upgraded PCs.
QUICK_ACCESS_APPID = "f01b4d95cf55d32a"


EXPLORER_JUMP_LISTS = (
    (QUICK_ACCESS_APPID, "Quick Access pinned and frequent folders"),
    ("5f7b5f1e01b83767", "Quick Access recent files"),
    ("1b4dd67f29cb1962", "Explorer taskbar jump list (Windows 7/8 layout)"),
)


# The keys behind Folder Options > Privacy > "Clear File Explorer history".
EXPLORER_HISTORY_KEYS = (
    (r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "address-bar history"),
    (r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", "search-box history"),
    (r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "recent-documents list"),
)


# Virtual known folders have no path of their own. "This PC\Desktop" is the one
# Explorer pins by default; pinning the real Desktop folder is the same pin.
KNOWN_FOLDER_ALIASES = {
    "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
}


_DESTLIST_HEADER = 32


_DESTLIST_ENTRY_FIXED = 130   # versions 3+; the UTF-16 path and 4 pad bytes follow


_DESTLIST_MIN_VERSION = 3     # Windows 10 1607 and later


def recent_items_dir():
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"


def network_shortcuts_dir():
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Network Shortcuts"


def jump_list_path(app_id, kind="automatic"):
    folder = "AutomaticDestinations" if kind == "automatic" else "CustomDestinations"
    return recent_items_dir() / folder / f"{app_id}.{kind}Destinations-ms"


def parse_destlist(data):
    """Entries of a jump list's DestList stream, or None for a layout this
    reader does not know.

    Layout (Windows 10 and 11, versions 3 and up): a 32-byte header holding
    the version, entry count and pinned count; then per entry a 130-byte fixed
    part -- the NetBIOS host name at 72, the entry number at 88, the pin index
    at 108 (-1 means not pinned; otherwise it is the display position), the
    access count at 116 and the path length in characters at 128 -- followed
    by the UTF-16 path and 4 bytes of padding.

    None, never an empty list, for anything unreadable: a list that could not
    be read must not be mistaken for a list with nothing in it, or a repair
    would report "nothing was pinned" about pins it never saw.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < _DESTLIST_HEADER:
        return None
    version, count = struct.unpack_from("<II", data, 0)
    if version < _DESTLIST_MIN_VERSION:
        return None
    entries = []
    offset = _DESTLIST_HEADER
    for _ in range(count):
        if offset + _DESTLIST_ENTRY_FIXED > len(data):
            return None
        host = data[offset + 72:offset + 88].split(b"\x00")[0].decode("ascii", "replace")
        entry_number, = struct.unpack_from("<I", data, offset + 88)
        pin_index, = struct.unpack_from("<i", data, offset + 108)
        access_count, = struct.unpack_from("<I", data, offset + 116)
        length, = struct.unpack_from("<H", data, offset + 128)
        start = offset + _DESTLIST_ENTRY_FIXED
        end = start + length * 2
        if end > len(data):
            return None
        entries.append({
            "path": data[start:end].decode("utf-16-le", "replace"),
            "pinned": pin_index >= 0,
            "pin_index": pin_index,
            "access_count": access_count,
            "host": host,
            "entry": entry_number,
        })
        offset = end + 4
    return entries


def read_destlist(path):
    """Raw DestList bytes of a jump list, via Structured Storage. None when the
    file is missing, locked, not an OLE file, or pythoncom is unavailable --
    the frozen build treats pythoncom as optional."""
    try:
        import pythoncom
        from win32com import storagecon
    except ImportError:
        return None
    try:
        pythoncom.CoInitialize()
    except Exception:
        pass
    try:
        storage = pythoncom.StgOpenStorage(
            str(path), None, storagecon.STGM_READ | storagecon.STGM_SHARE_DENY_WRITE, None, 0)
        stream = storage.OpenStream(
            "DestList", None, storagecon.STGM_READ | storagecon.STGM_SHARE_EXCLUSIVE, 0)
        chunks = []
        while True:
            chunk = stream.Read(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except Exception:
        return None


def read_jump_list(path):
    """Entries of one jump list file, or None if it could not be read."""
    data = read_destlist(path)
    return None if data is None else parse_destlist(data)


def quick_access_pins(entries):
    """Pinned paths in the order Quick Access shows them."""
    pinned = [e for e in (entries or ()) if e.get("pinned")]
    return [e["path"] for e in sorted(pinned, key=lambda e: e["pin_index"])]


def jump_list_kind(path):
    """Where a jump-list entry points: 'knownfolder', 'shell' (a ::{CLSID}
    virtual item such as the Recycle Bin), 'unc', 'drive' (a lettered path),
    or 'other'."""
    text = (path or "").strip()
    if text.lower().startswith("knownfolder:"):
        return "knownfolder"
    if text.startswith("::{"):
        return "shell"
    if text.startswith("\\\\"):
        return "unc"
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        return "drive"
    return "other"


def network_target_host(target):
    r"""Server name of a network target: \\server\share, http(s)://host/...,
    ftp://host. '' for anything local. '@SSL' and '@port' suffixes on WebDAV
    hosts are stripped."""
    text = (target or "").strip()
    if text.startswith("\\\\"):
        if text.lower().startswith("\\\\?\\unc\\"):
            text = "\\\\" + text[8:]
        host = text[2:].replace("/", "\\").split("\\", 1)[0]
        return host.split("@", 1)[0].strip()
    lowered = text.lower()
    for scheme in ("https://", "http://", "ftp://", "ftps://", "sftp://"):
        if lowered.startswith(scheme):
            rest = text[len(scheme):].split("/", 1)[0]
            rest = rest.rsplit("@", 1)[-1]          # user:pass@host
            if rest.startswith("["):                 # [ipv6]:port
                return rest[1:].split("]", 1)[0]
            return rest.split(":", 1)[0].strip()
    return ""


def network_target_port(target):
    """The port Explorer would have to reach for a target: 445 for SMB,
    443/80 for WebDAV and web locations, 21 for FTP."""
    text = (target or "").strip()
    lowered = text.lower()
    if lowered.startswith("https://") or "@ssl\\" in lowered:
        return 443
    if lowered.startswith("http://"):
        return 80
    if lowered.startswith(("ftp://", "ftps://")):
        return 21
    if lowered.startswith("sftp://"):
        return 22
    if text.startswith("\\\\"):
        host_part = text[2:].split("\\", 1)[0]
        if "@" in host_part:
            suffix = host_part.split("@", 1)[1]
            if suffix.isdigit():
                return int(suffix)
    return 445


def host_answers(host, timeout=5.0, port=445, cache=None):
    """Whether a server answers on `port` within `timeout` seconds.

    Name resolution is the slow part: a NetBIOS-style name that DNS does not
    know falls through LLMNR and mDNS and takes eight or nine seconds to give
    up, which is exactly the wait Explorer shows as "Working on it...".
    getaddrinfo cannot be interrupted, so the whole probe runs on a worker
    thread and the caller stops waiting at the deadline; the thread finishes
    on its own afterwards. `cache` (a dict) makes repeat hosts free.
    """
    key = ((host or "").strip().lower(), int(port))
    if not key[0]:
        return False
    if cache is not None and key in cache:
        return cache[key]
    verdict = {"ok": False}
    deadline = time.monotonic() + timeout

    def _probe():
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except OSError:
            return
        for family, kind, proto, _name, addr in infos[:2]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            sock = socket.socket(family, kind, proto)
            sock.settimeout(remaining)
            try:
                sock.connect(addr)
                verdict["ok"] = True
                return
            except OSError:
                continue
            finally:
                sock.close()

    worker = threading.Thread(target=_probe, daemon=True)
    worker.start()
    worker.join(timeout)
    if cache is not None:
        cache[key] = verdict["ok"]
    return verdict["ok"]


MAPPED_DRIVES_KEY = "Network"


def persistent_mapped_drives(subkey=MAPPED_DRIVES_KEY):
    """Drive letters Windows reconnects at sign-in, from HKCU\\Network -- the
    list Explorer waits on when it draws This PC.

    Read from the registry rather than `net use` on purpose: WinMend runs
    elevated, and an elevated process has its own drive table that does not
    show what the user's desktop session has mapped."""
    drives = []
    if winreg is None:
        return drives
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
    except OSError:
        return drives
    with key:
        try:
            count = winreg.QueryInfoKey(key)[0]
        except OSError:
            return drives
        for index in range(count):
            try:
                letter = winreg.EnumKey(key, index)
                with winreg.OpenKey(key, letter) as sub:
                    remote = str(winreg.QueryValueEx(sub, "RemotePath")[0]).strip()
            except OSError:
                continue
            if len(letter) != 1 or not remote:
                continue
            drives.append({
                "letter": letter.upper() + ":",
                "remote": remote,
                "host": network_target_host(remote),
                "subkey": subkey + "\\" + letter,
            })
    return drives


def network_shortcuts(folder=None):
    """The 'network locations' shown under This PC: each is a folder under
    Network Shortcuts holding a target.lnk. Targets are read out of the .lnk
    itself; nothing here touches the server."""
    items = []
    try:
        children = sorted(os.scandir(folder or network_shortcuts_dir()),
                          key=lambda c: c.name.lower())
    except OSError:
        return items
    for child in children:
        if child.name.lower() == "desktop.ini":
            continue
        if child.is_dir():
            link = os.path.join(child.path, "target.lnk")
            target = _resolve_lnk(link)[0] if os.path.isfile(link) else ""
        elif child.name.lower().endswith(".lnk"):
            target = _resolve_lnk(child.path)[0]
        else:
            continue
        items.append({
            "name": os.path.splitext(child.name)[0],
            "path": child.path,
            "target": target,
            "host": network_target_host(target),
            "port": network_target_port(target),
        })
    return items


def delete_registry_tree(root, subkey):
    """Delete a key and everything under it. True once it is gone, including
    when it was never there."""
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    with key:
        while True:
            try:
                child = winreg.EnumKey(key, 0)
            except OSError:
                break
            if not delete_registry_tree(key, child):
                return False
    try:
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def known_folder_path(guid_text):
    """Filesystem path of a KNOWNFOLDERID such as {374DE290-...} (Downloads),
    or "" for a virtual folder or a GUID Windows does not know. Pure ctypes so
    the frozen build does not need pywin32's shell module for it."""
    try:
        import ctypes

        class _GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

        guid = _GUID()
        if ctypes.windll.ole32.CLSIDFromString(str(guid_text), ctypes.byref(guid)) != 0:
            return ""
        out = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None,
                                                      ctypes.byref(out)) != 0:
            return ""
        try:
            return out.value or ""
        finally:
            ctypes.windll.ole32.CoTaskMemFree(out)
    except Exception:
        return ""


DRIVE_KINDS = {0: "unknown", 1: "absent", 2: "removable", 3: "fixed", 4: "network",
               5: "optical", 6: "ramdisk"}


def drive_kind(path):
    """What kind of volume a lettered path sits on, per GetDriveType: 'absent'
    is a letter nothing is behind any more -- a removed mapping or an unplugged
    disk. Answered from the local drive table; nothing is contacted."""
    text = (path or "").strip()
    if len(text) < 2 or text[1] != ":":
        return "unknown"
    try:
        import ctypes
        return DRIVE_KINDS.get(ctypes.windll.kernel32.GetDriveTypeW(text[:2] + "\\"), "unknown")
    except Exception:
        return "unknown"


def mapped_drive_target(letter):
    """UNC path behind a mapped drive letter ("Z:"), read from this session's
    drive table without contacting the server. "" when the letter is not a
    network mapping in this session."""
    try:
        import ctypes
        buffer = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_ulong(1024)
        if ctypes.windll.mpr.WNetGetConnectionW(str(letter)[:2], buffer, ctypes.byref(size)) == 0:
            return buffer.value or ""
    except Exception:
        pass
    return ""


# ---- shell extensions ------------------------------------------------------

_CONTEXT_MENU_ROOTS = (
    (r"*\shellex\ContextMenuHandlers", "files"),
    (r"AllFilesystemObjects\shellex\ContextMenuHandlers", "files and folders"),
    (r"Directory\shellex\ContextMenuHandlers", "folders"),
    (r"Directory\Background\shellex\ContextMenuHandlers", "folder background"),
    (r"Folder\shellex\ContextMenuHandlers", "folders"),
    (r"Drive\shellex\ContextMenuHandlers", "drives"),
)


_OVERLAY_ROOT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"


_BLOCKED_ROOT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"


_CLSID_RE = re.compile(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}")


OVERLAY_HANDLER_LIMIT = 15   # Windows loads the first 15 alphabetically and ignores the rest


def is_microsoft_company(company):
    return "microsoft" in (company or "").lower()


def _subkeys(root, subkey):
    try:
        key = winreg.OpenKey(root, subkey)
    except OSError:
        return []
    with key:
        names = []
        for index in range(winreg.QueryInfoKey(key)[0]):
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break
        return names


def _default_value(root, subkey):
    # QueryValueEx, not QueryValue: the legacy call raises "The data is
    # invalid" on REG_EXPAND_SZ, which is how every built-in handler's
    # InprocServer32 (%SystemRoot%\system32\shell32.dll) is stored.
    try:
        with winreg.OpenKey(root, subkey) as key:
            return str(winreg.QueryValueEx(key, "")[0] or "").strip()
    except OSError:
        return ""


def _clsid_dll(clsid):
    for server in ("InprocServer32", "LocalServer32"):
        value = _default_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{server}")
        if value:
            return os.path.expandvars(value.strip('"'))
    return ""


def _clsid_is_packaged(clsid):
    """MSIX-packaged extensions (Windows 11's own Share and Sync entries,
    packaged OneDrive) register under PackagedCom, not InprocServer32, and are
    not broken for lacking a DLL path."""
    try:
        winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"PackagedCom\ClassIndex\{clsid}").Close()
        return True
    except OSError:
        return False


def shell_extension_inventory(company_of=file_company):
    """Context-menu and icon-overlay handlers registered with Explorer, each
    resolved to its DLL and publisher. Read-only.

    Third-party handlers run inside Explorer on every right-click and every
    folder draw, so one slow or broken handler slows all of Explorer. This
    names them so the user can decide; WinMend does not disable any, because
    which of 7-Zip, OneDrive or the antivirus a person wants to keep is their
    call, and the answer is ShellExView or uninstalling the program.
    """
    result = {"handlers": [], "overlays": [], "overlay_limit": OVERLAY_HANDLER_LIMIT,
              "blocked": [], "available": winreg is not None}
    if winreg is None:
        return result
    blocked = {name.upper() for name in _subkeys(winreg.HKEY_LOCAL_MACHINE, _BLOCKED_ROOT)}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _BLOCKED_ROOT) as key:
            for index in range(winreg.QueryInfoKey(key)[1]):
                blocked.add(str(winreg.EnumValue(key, index)[0]).upper())
    except OSError:
        pass
    result["blocked"] = sorted(blocked)

    seen = {}
    for subkey, where in _CONTEXT_MENU_ROOTS:
        for name in _subkeys(winreg.HKEY_CLASSES_ROOT, subkey):
            if _CLSID_RE.fullmatch(name):
                clsid = name
            else:
                match = _CLSID_RE.search(_default_value(winreg.HKEY_CLASSES_ROOT, subkey + "\\" + name))
                clsid = match.group(0) if match else ""
            if not clsid:
                continue
            clsid = clsid.upper()
            if clsid in seen:
                if where not in seen[clsid]["where"]:
                    seen[clsid]["where"].append(where)
                continue
            dll = _clsid_dll(clsid)
            packaged = not dll and _clsid_is_packaged(clsid)
            company = company_of(dll) if dll else ""
            label = name
            if _CLSID_RE.fullmatch(name):
                label = _default_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}") or name
            seen[clsid] = {
                "name": label,
                "clsid": clsid,
                "dll": dll,
                "company": company,
                "microsoft": is_microsoft_company(company),
                # A packaged extension has no DLL path to read a publisher
                # from: neither third-party evidence nor a fault.
                "packaged": packaged,
                "dll_missing": bool(dll) and not os.path.isfile(dll),
                "unregistered": not dll and not packaged,
                "blocked": clsid in blocked,
                "where": [where],
            }
    result["handlers"] = sorted(seen.values(), key=lambda h: (h["microsoft"], h["name"].lower()))

    for name in _subkeys(winreg.HKEY_LOCAL_MACHINE, _OVERLAY_ROOT):
        match = _CLSID_RE.search(_default_value(winreg.HKEY_LOCAL_MACHINE, _OVERLAY_ROOT + "\\" + name))
        clsid = match.group(0).upper() if match else ""
        dll = _clsid_dll(clsid) if clsid else ""
        company = company_of(dll) if dll else ""
        result["overlays"].append({
            "name": name, "clsid": clsid, "dll": dll, "company": company,
            "microsoft": is_microsoft_company(company),
        })
    # Windows sorts overlay identifiers by name and stops after the limit --
    # which is why sync clients pad their names with spaces to sort first.
    result["overlays"].sort(key=lambda o: o["name"])
    return result
