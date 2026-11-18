"""WinMend features: storage: scanner."""

from __future__ import annotations

from winmend.core.processes import _no_console_startupinfo, wm_run
import ctypes
import json
import math
import os
import time


# ==================== STORAGESENSE MODULE ====================
# This module provides an advanced disk scanner UI, merged for single-EXE deployment.

# --- StorageSense Styling and Constants ---
SS_COLOR_LARGE = "#E74C3C"  # Red for very large


SS_COLOR_MEDIUM = "#F39C12"  # Orange for medium-large


SS_COLOR_CORE = "#3498DB"  # Blue for Windows core files


SS_THRESHOLD_GB = 1.0


SS_THRESHOLD_MB = 100.0


# --- StorageSense File Hints Database ---
SS_HINTS = {
    "pagefile.sys": "Windows Virtual Memory - Crucial for system stability.",
    "hiberfil.sys": "Hibernate Data - Saves state when sleeping.",
    "swapfile.sys": "Universal App Swap Space - Similar to pagefile.",
    "ntuser.dat": "User Settings Hive - Critical system registry file.",
    "dll": "System Library - Contains code used by multiple programs.",
    "sys": "System Driver - Hardware or software driver file.",
    "cab": "Windows Cabinet File - Used for updates and installations.",
    "log": "Log File - Recording of program activity. Often safe to delete.",
    "dmp": "Crash Dump - Data from a system crash. Safe to delete.",
    "vmdk": "Virtual Machine Drive - Contains a whole virtual computer.",
    "vhdx": "Virtual Machine Drive - Windows native virtual disk format.",
    "vhd": "Virtual Hard Disk - Older virtual machine drive format.",
    "iso": "Disk Image - Often an installer or backup of a physical disk.",
    "img": "Disk Image - Raw data from a disk or partition.",
    "pak": "Game Data Archive - Contains models, textures, and sounds.",
    "bundle": "Unity Data Bundle - Asset package for game engines.",
    "obb": "Android Expansion File - Large game data for mobile ports.",
    "unity3d": "Unity Engine Asset - 3D assets and game logic.",
    "rpf": "Rockstar Game File - Massive game asset container (GTA/RDR).",
    "workshop": "Steam Workshop - Downloaded mod or custom content.",
    "mp4": "Video File - High definition video data.",
    "mkv": "Video File - High quality video container.",
    "mov": "QuickTime Video - Apple media format.",
    "wav": "Uncompressed Audio - Large, high-quality sound file.",
    "flac": "Lossless Audio - High quality sound with some compression.",
    "tmp": "Temporary File - Usually safe to delete if not in use.",
    "node_modules": "Javascript Dependencies - Can be massive; safe to delete if you can 'npm install'.",
    ".git": "Version Control - Contains the history of a software project.",
    "py": "Python Script - Source code file.",
    "js": "Javascript File - Web or application logic.",
    "json": "Data File - Structured information used by apps.",
    "cpp": "C++ Source - Compiled programming code.",
    "target": "Build Output - Often found in Rust/Java projects. Safe to clean.",
    "msi": "Windows Installer - Can often be deleted after installation.",
    "exe": "Executable Program - The actual application file.",
    "zip": "Compressed Archive - Multiple files packed together.",
    "rar": "WinRAR Archive - Third-party compression format.",
    "7z": "7-Zip Archive - High efficiency compressed file.",
}


def ss_get_file_hint(path):
    name = os.path.basename(path).lower()
    ext = name.split(".")[-1] if "." in name else ""
    if name in SS_HINTS: return SS_HINTS[name]
    if ext in SS_HINTS: return SS_HINTS[ext]
    if "program files" in path.lower(): return "Installed Application data."
    if "users" in path.lower() and "appdata" not in path.lower(): return "User data (Documents, Downloads, etc)."
    return ""


def ss_format_size(size_bytes):
    if size_bytes == 0: return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def ss_send_to_recycle_bin(path):
    """Move a file/folder to Recycle Bin on Windows without extra dependencies."""
    if os.name != 'nt':
        return False
    try:
        from ctypes import wintypes
        FO_DELETE = 3
        FOF_SILENT = 0x0004
        FOF_NOCONFIRMATION = 0x0010
        FOF_ALLOWUNDO = 0x0040
        FOF_NOERRORUI = 0x0400

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", wintypes.WORD),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", wintypes.LPVOID),
                ("lpszProgressTitle", wintypes.LPCWSTR),
            ]

        target = os.path.normpath(path)
        if not os.path.exists(target):
            return False
        # SHFileOperation expects double-null terminated string.
        from_buffer = target + "\0\0"
        op = SHFILEOPSTRUCTW()
        op.hwnd = 0
        op.wFunc = FO_DELETE
        op.pFrom = from_buffer
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        return result == 0 and not bool(op.fAnyOperationsAborted)
    except Exception:
        return False


def ss_get_drive_health_info(path):
    if os.name != 'nt': return {"status": "N/A", "raw": "Non-Windows"}
    try:
        drive_letter = os.path.splitdrive(path)[0].replace(":", "")
        if not drive_letter: return {"status": "Unknown", "raw": "No Drive Letter"}
        ps_cmd = (
            f"Get-Volume -DriveLetter {drive_letter} | Get-Partition | Get-Disk | Get-PhysicalDisk | "
            "Select-Object HealthStatus, PredictFailure, MediaType, BusType, OperationalStatus, "
            "Size, AllocatedSize, FriendlyName, Usage, Manufacturer, Model, FirmwareRevision, SerialNumber | ConvertTo-Json"
        )
        process = wm_run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=10, startupinfo=_no_console_startupinfo())
        if not process.stdout.strip(): return {"status": "Unknown", "raw": "No Output"}
        data = json.loads(process.stdout)
        if isinstance(data, list): data = data[0]
        health = data.get("HealthStatus", "Unknown")
        predict_fail = data.get("PredictFailure", False)
        status = health
        if predict_fail or health.upper() != "HEALTHY":
            status = f"WARNING ({health})"
        return {"status": status, "data": data}
    except Exception as e:
        return {"status": "Unknown", "raw": str(e)}


def ss_get_drive_details(path, serial=None):
    """Get comprehensive drive reliability and performance stats."""
    if os.name != 'nt': return {}
    details = {}
    try:
        drive_letter = os.path.splitdrive(path)[0].replace(":", "")

        # Method 1: Get StorageReliabilityCounter (most detailed)
        ps_cmd = (
            f"Get-Volume -DriveLetter {drive_letter} | Get-Partition | Get-Disk | Get-PhysicalDisk | "
            "Get-StorageReliabilityCounter | Select-Object PowerOnHours, Temperature, ReadErrorsTotal, WriteErrorsTotal, "
            "ReadErrorsCorrected, ReadErrorsUncorrected, WriteErrorsCorrected, WriteErrorsUncorrected, "
            "Wearout, LoadUnloadCycleCount, StartStopCycleCount, RealizedCapacity, FlushErrorsTotal, FatalErrorsTotal, "
            "ReadLatencyMax, WriteLatencyMax, ReadIOPS, WriteIOPS | ConvertTo-Json"
        )
        process = wm_run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=15, startupinfo=_no_console_startupinfo())
        if process.returncode == 0 and process.stdout.strip():
            details = json.loads(process.stdout)
            if isinstance(details, list): details = details[0]

        # Method 2: Get additional physical disk info (manufacturer, speed, etc.)
        ps_phys = (
            f"Get-Volume -DriveLetter {drive_letter} | Get-Partition | Get-Disk | Get-PhysicalDisk | "
            "Select-Object Manufacturer, Model, FirmwareRevision, SerialNumber, MediaType, BusType, "
            "SpindleSpeed, Size, AllocatedSize, LogicalSectorSize, PhysicalSectorSize | ConvertTo-Json"
        )
        phys_proc = wm_run(["powershell", "-Command", ps_phys], capture_output=True, text=True, encoding='utf-8', errors='replace',
                                   timeout=10, startupinfo=_no_console_startupinfo())
        if phys_proc.returncode == 0 and phys_proc.stdout.strip():
            phys_data = json.loads(phys_proc.stdout)
            if isinstance(phys_data, list): phys_data = phys_data[0]
            details.update(phys_data)

        # Method 3: Get disk performance counters
        ps_perf = (
            f"Get-Counter '\\PhysicalDisk(*)\\Disk Reads/sec', '\\PhysicalDisk(*)\\Disk Writes/sec', "
            f"'\\PhysicalDisk(*)\\Avg. Disk sec/Read', '\\PhysicalDisk(*)\\Avg. Disk sec/Write' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty CounterSamples | Where-Object {{$_.InstanceName -like '*{drive_letter}*'}} | "
            "Select-Object Path, CookedValue | ConvertTo-Json"
        )
        try:
            perf_proc = wm_run(["powershell", "-Command", ps_perf], capture_output=True, text=True, encoding='utf-8', errors='replace',
                                       timeout=5, startupinfo=_no_console_startupinfo())
            if perf_proc.returncode == 0 and perf_proc.stdout.strip():
                perf_data = json.loads(perf_proc.stdout)
                if isinstance(perf_data, dict): perf_data = [perf_data]
                for counter in perf_data:
                    path_name = counter.get("Path", "")
                    value = counter.get("CookedValue", 0)
                    if "Reads/sec" in path_name:
                        details["CurrentReadIOPS"] = round(value, 2)
                    elif "Writes/sec" in path_name:
                        details["CurrentWriteIOPS"] = round(value, 2)
                    elif "sec/Read" in path_name:
                        details["AvgReadLatencyMs"] = round(value * 1000, 2)
                    elif "sec/Write" in path_name:
                        details["AvgWriteLatencyMs"] = round(value * 1000, 2)
        except Exception:
            pass

        return details
    except Exception:
        return {}


class SSScanner:
    def __init__(self, root_path, min_size_mb, update_callback, q):
        self.root_path = os.path.normpath(root_path)
        self.min_size_bytes = min_size_mb * 1024 * 1024
        self.update_callback = update_callback
        self.is_running = True
        self.queue = q
        self.total_size = 0
        self.total_files = 0
        self.total_folders = 0
        self.total_errors = 0
        self.entries_scanned = 0
        self.scanned_bytes = 0
        self.top_level_total = 0
        self.top_level_done = 0
        self.top_level_ema_sec = None
        self.excluded_dirs = {'System Volume Information', '$Recycle.Bin', 'Containers'}

    def stop(self):
        self.is_running = False

    def scan(self):
        start_time = time.time()
        try:
            with os.scandir(self.root_path) as it:
                self.top_level_total = sum(
                    1 for entry in it
                    if not entry.is_symlink()
                    and entry.name.lower() not in [ex.lower() for ex in self.excluded_dirs]
                )
        except Exception:
            self.top_level_total = 0

        size, files, folders = self._scan_and_sum(self.root_path, is_root=True)
        self.total_size = size
        duration = time.time() - start_time
        self.update_callback(self.root_path, {
            "size": size, "is_dir": True, "files": files, "folders": folders,
            "mtime": os.path.getmtime(self.root_path) if os.path.exists(self.root_path) else 0,
            "complete": True, "duration": duration
        })

    def _scan_and_sum(self, path, is_root=False):
        if not self.is_running: return 0, 0, 0
        if self.queue.qsize() > 1500: time.sleep(0.05)
        base_name = os.path.basename(path).lower()
        if base_name in [ex.lower() for ex in self.excluded_dirs]: return 0, 0, 0
        dir_size, dir_files, dir_folders = 0, 0, 0
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if not self.is_running: return 0, 0, 0
                    self.entries_scanned += 1
                    if entry.is_symlink(): continue
                    entry_started = time.time()
                    try:
                        if entry.is_file(follow_symlinks=False):
                            est = entry.stat(follow_symlinks=False)
                            size = est.st_size
                            dir_size += size
                            dir_files += 1
                            self.total_files += 1
                            self.scanned_bytes += size
                            if size >= self.min_size_bytes:
                                self.update_callback(entry.path,
                                                     {"size": size, "is_dir": False, "files": 0, "folders": 0,
                                                      "mtime": est.st_mtime})
                        elif entry.is_dir(follow_symlinks=False):
                            self.total_folders += 1
                            dstat = entry.stat(follow_symlinks=False)
                            s_size, s_files, s_folders = self._scan_and_sum(entry.path)
                            dir_size += s_size
                            dir_files += s_files
                            dir_folders += (1 + s_folders)
                            self.update_callback(entry.path, {"size": s_size, "is_dir": True, "files": s_files,
                                                              "folders": 1 + s_folders,
                                                              "mtime": dstat.st_mtime})
                    except (OSError, PermissionError):
                        self.total_errors += 1
                    finally:
                        if is_root:
                            self.top_level_done += 1
                            elapsed = max(time.time() - entry_started, 0.001)
                            if self.top_level_ema_sec is None:
                                self.top_level_ema_sec = elapsed
                            else:
                                # Exponential moving average for steadier ETA.
                                self.top_level_ema_sec = (self.top_level_ema_sec * 0.75) + (elapsed * 0.25)
            if self.entries_scanned % 1000 == 0: time.sleep(0.01)
        except (OSError, PermissionError):
            self.total_errors += 1
        return dir_size, dir_files, dir_folders


class SSSafetyRules:
    """The Storage Analyzer's safety classifier, lifted out of the old window.

    These rules decide what must never be auto-deleted: OS files, documents,
    cloud-synced folders, in-use databases, virtual disks, licence keys, game
    libraries, source trees and fresh downloads. They were methods on the
    customtkinter StorageSenseApp; that window is gone, but the rules are pure
    functions of a path, so they moved here unchanged rather than being
    rewritten. WMStoragePage borrows them from here.
    """

    def _is_system_path(self, path):
        lpath = os.path.normpath(path).lower()
        if any(core in lpath for core in [r"\windows", r"\program files", r"\programdata"]):
            return True
        base = os.path.basename(lpath)
        return base in {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}

    def _is_critical_system_path(self, path):
        """Files/paths that should never be shown in Top Hogs or deleted by cleanup actions."""
        lpath = os.path.normpath(path).lower()
        critical_exact = {
            "c:\\pagefile.sys",
            "c:\\hiberfil.sys",
            "c:\\swapfile.sys",
            "c:\\bootmgr",
        }
        if lpath in critical_exact:
            return True
        critical_prefixes = [
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\microsoft\\",
        ]
        return any(lpath.startswith(prefix) for prefix in critical_prefixes)

    def _is_protected_cleanup_path(self, path):
        return self._is_critical_system_path(path) or self._is_unsafe_to_auto_delete(path)

    def _is_windows_search_db(self, path):
        return os.path.normpath(path).lower() == r"c:\programdata\microsoft\search\data\applications\windows\windows.db"

    # --- Safety helpers: layered protection so Top Hogs / Quick Wins never auto-delete
    # user data, cloud-synced files, in-use databases, virtual disks, license keys,
    # game libraries, source-control roots, or recently downloaded items.

    # File extensions whose contents are typically irreplaceable user data.
    _HIGH_RISK_EXTS = frozenset({
        ".pst",                                # Outlook archive
        ".vhd", ".vhdx", ".vmdk",              # virtual disks
        ".bak", ".tib", ".img", ".bkf",        # backups
        ".mdf", ".ldf", ".sqlite", ".sqlite3", ".db",  # databases
        ".key", ".pem", ".pfx", ".p12", ".lic", ".kdbx",  # keys / password vaults
        ".one", ".onepkg",                     # OneNote notebooks
    })

    def _is_user_data_path(self, path):
        """Files under the current user's documents/media folders (never auto-delete)."""
        lpath = os.path.normpath(path).lower()
        try:
            user_home = os.path.normpath(os.path.expanduser("~")).lower()
        except Exception:
            return False
        if not lpath.startswith(user_home):
            return False
        rel = lpath[len(user_home):].lstrip("\\")
        # First path component
        first = rel.split("\\", 1)[0] if rel else ""
        protected_dirs = {
            "documents", "desktop", "pictures", "videos", "music",
            "favorites", "contacts", "links", "saved games",
        }
        return first in protected_dirs

    def _is_cloud_sync_path(self, path):
        """Files inside cloud-sync roots like OneDrive, Dropbox, Google Drive, iCloud."""
        lpath = os.path.normpath(path).lower()
        cloud_keywords = (
            "\\onedrive\\", "\\onedrive - ",
            "\\dropbox\\",
            "\\google drive\\", "\\googledrive\\",
            "\\icloud drive\\", "\\icloudphotos\\", "\\icloud\\",
            "\\box sync\\", "\\box\\",
            "\\sync.com\\", "\\pcloud\\", "\\mega\\",
        )
        return any(kw in lpath for kw in cloud_keywords)

    def _is_high_risk_extension(self, path):
        """File types that typically hold irreplaceable data."""
        return os.path.splitext(path.lower())[1] in self._HIGH_RISK_EXTS

    def _is_game_library_path(self, path):
        """Inside a game-store install/library folder."""
        lpath = os.path.normpath(path).lower()
        game_keywords = (
            "\\steamlibrary\\", "\\steamapps\\",
            "\\epic games\\", "\\epicgames\\",
            "\\gog games\\", "\\gog galaxy\\",
            "\\battle.net\\",
            "\\origin games\\", "\\ea games\\",
            "\\riot games\\",
            "\\xboxgames\\", "\\xbox games\\",
            "\\ubisoft\\", "\\ubisoft game launcher\\",
            "\\rockstar games\\",
        )
        return any(kw in lpath for kw in game_keywords)

    def _is_repo_or_project_path(self, path):
        """Inside a source-control working tree or active project folder."""
        lpath = os.path.normpath(path).lower()
        markers = (
            "\\.git\\", "\\.svn\\", "\\.hg\\",
            "\\node_modules\\", "\\.venv\\", "\\venv\\",
            "\\__pycache__\\",
        )
        return any(m in lpath for m in markers)

    def _is_recent_download(self, path, mtime):
        """Recently-modified Downloads file (<7 days) — likely still in use."""
        if "\\downloads\\" not in os.path.normpath(path).lower():
            return False
        if not mtime:
            return False
        try:
            return (time.time() - mtime) / 86400 < 7
        except Exception:
            return False

    def _is_unsafe_to_auto_delete(self, path, mtime=None):
        """Master safety check: never let Top Hogs / Quick Wins auto-delete these.

        Returns True if the path matches any of:
        - critical OS files / Windows / Program Files
        - user-profile documents/media folders
        - cloud-sync folders (OneDrive, Dropbox, etc.)
        - high-risk extensions (.pst, .vhd, .bak, .key, .sqlite, …)
        - game library folders (Steam, Epic, GOG, …)
        - source-control or project working trees
        - recently modified Downloads
        - the Windows Search DB
        """
        if self._is_critical_system_path(path):
            return True
        if self._is_user_data_path(path):
            return True
        if self._is_cloud_sync_path(path):
            return True
        if self._is_high_risk_extension(path):
            return True
        if self._is_game_library_path(path):
            return True
        if self._is_repo_or_project_path(path):
            return True
        if self._is_recent_download(path, mtime):
            return True
        if self._is_windows_search_db(path):
            return True
        return False

    def _classify_safety(self, path, mtime=None):
        """Return (severity, reason) for a path. severity in {'critical','user','risky','recent','safe'}."""
        if self._is_critical_system_path(path):
            return ("critical", "Critical OS / system path")
        if self._is_windows_search_db(path):
            return ("critical", "Windows Search index")
        if self._is_user_data_path(path):
            return ("user", "User documents / media folder")
        if self._is_cloud_sync_path(path):
            return ("user", "Cloud-synced folder")
        if self._is_high_risk_extension(path):
            return ("risky", f"High-risk file type ({os.path.splitext(path)[1] or 'unknown'})")
        if self._is_game_library_path(path):
            return ("risky", "Game library folder")
        if self._is_repo_or_project_path(path):
            return ("risky", "Source-control / project folder")
        if self._is_recent_download(path, mtime):
            return ("recent", "Recently downloaded (<7 days)")
        return ("safe", "")

    def _is_excluded_from_top_hogs(self, path):
        """Hide noisy/system/private/risky files from Insights Top Hogs list."""
        lpath = os.path.normpath(path).lower()
        if self._is_unsafe_to_auto_delete(lpath):
            return True
        if lpath.endswith(".ost"):
            return True
        return False
