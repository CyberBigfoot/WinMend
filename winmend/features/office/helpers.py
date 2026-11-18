"""WinMend features: office: helpers."""

from __future__ import annotations

from winmend.core.registry_values import _hive
from winmend.core.windows import pids_with_visible_windows
from winmend.features.cleanup_helpers import format_elapsed
from winmend.features.explorer.helpers import _default_value, _subkeys
import json
import os
import subprocess
import time
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ============================================================================
# Microsoft Office & Outlook repair
# ============================================================================
#
# Everything here measures first and repairs second. The inventory functions
# read the registry, the file system and the event log; the pure classifiers
# turn those readings into findings and into the repair options the handler
# offers -- each option carries the evidence that switched it on, so a repair
# is never proposed for a fault that was not observed.

OFFICE_C2R_KEY = r"SOFTWARE\Microsoft\Office\ClickToRun"


OFFICE_C2R_CONFIG_KEY = OFFICE_C2R_KEY + r"\Configuration"


OFFICE_APP_PATHS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"


OFFICE_COMMON_KEY = r"Software\Microsoft\Office\16.0\Common"


OUTLOOK_KEY = r"Software\Microsoft\Office\16.0\Outlook"


CLICKTORUN_SERVICE = "ClickToRunSvc"


NEW_OUTLOOK_PACKAGE = "Microsoft.OutlookForWindows"


NEW_OUTLOOK_STORE_ID = "9NRX63209R7B"


APPX_REPOSITORY_KEY = (r"Software\Classes\Local Settings\Software\Microsoft\Windows"
                       r"\CurrentVersion\AppModel\Repository\Packages")


# exe registered under App Paths -> friendly name
OFFICE_APPS = (
    ("OUTLOOK.EXE", "Outlook"), ("WINWORD.EXE", "Word"), ("EXCEL.EXE", "Excel"),
    ("POWERPNT.EXE", "PowerPoint"), ("ONENOTE.EXE", "OneNote"),
    ("MSACCESS.EXE", "Access"), ("MSPUB.EXE", "Publisher"),
)


OFFICE_PROCESS_NAMES = {
    "outlook.exe": "Outlook", "winword.exe": "Word", "excel.exe": "Excel",
    "powerpnt.exe": "PowerPoint", "onenote.exe": "OneNote", "onenoteim.exe": "OneNote",
    "msaccess.exe": "Access", "mspub.exe": "Publisher", "lync.exe": "Skype for Business",
    "olk.exe": "New Outlook",
}


# Processes whose window normally lives in the tray or nowhere; running without
# a window is not a fault for them.
OFFICE_BACKGROUND_OK = {"olk.exe", "onenoteim.exe"}


OUTLOOK_ADDIN_ROOTS = (
    ("user", r"Software\Microsoft\Office\Outlook\Addins", "HKCU"),
    ("machine", r"Software\Microsoft\Office\Outlook\Addins", "HKLM"),
    ("machine (32-bit)", r"Software\WOW6432Node\Microsoft\Office\Outlook\Addins", "HKLM"),
    ("user (16.0)", r"Software\Microsoft\Office\16.0\Outlook\Addins", "HKCU"),
)


LOAD_BEHAVIOR = {0: "off", 1: "loaded once", 2: "off (was on at startup)", 3: "on at startup",
                 8: "on demand", 9: "on demand", 16: "first time only"}


# Registry values that, at the given setting, stop Microsoft 365 accounts from
# signing in or connecting. Only values whose *harmful* setting is unambiguous
# belong here: ExcludeScpLookup=1, for example, is a standard tuning and stays
# out. Each row: (scope hive name, key, value, harmful value, consequence).
OFFICE_AUTH_WATCHLIST = (
    ("HKCU", OFFICE_COMMON_KEY + r"\Identity", "EnableADAL", 0,
     "modern authentication is switched off, so Microsoft 365 accounts cannot sign in "
     "and Outlook loops on the password prompt"),
    ("HKCU", r"Software\Policies\Microsoft\Office\16.0\Common\Identity", "EnableADAL", 0,
     "a policy switches modern authentication off, so Microsoft 365 accounts cannot sign in"),
    ("HKCU", OUTLOOK_KEY + r"\AutoDiscover", "ExcludeExplicitO365Endpoint", 1,
     "Outlook is told never to ask Microsoft 365 where a mailbox lives, so Exchange Online "
     "accounts cannot be added or connect"),
    ("HKCU", r"Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover",
     "ExcludeExplicitO365Endpoint", 1,
     "a policy stops Outlook asking Microsoft 365 where a mailbox lives"),
)


OFFICE_CREDENTIAL_PREFIXES = ("MicrosoftOffice16_Data:", "MicrosoftOffice_", "MicrosoftOfficeSSO")


OFFICE_LICENSE_FOLDERS = (r"Microsoft\Office\16.0\Licensing", r"Microsoft\Office\Licenses",
                          r"Microsoft\IdentityCache", r"Microsoft\OneAuth")


OFFICE_IDENTITY_KEYS = (OFFICE_COMMON_KEY + r"\Identity", OFFICE_COMMON_KEY + r"\Licensing")


# The Unicode PST/OST ceiling Outlook enforces (MaxLargeFileSize), in MB.
OUTLOOK_DEFAULT_SIZE_LIMIT_MB = 51200


GPU_MODULE_PREFIXES = ("nv", "ig", "atid", "atiu", "amd", "d3d", "dxgi", "igd", "igc")


WINDOWS_CORE_MODULES = {"ntdll.dll", "kernelbase.dll", "kernel32.dll", "combase.dll",
                        "ucrtbase.dll", "msvcrt.dll", "user32.dll", "gdi32.dll",
                        "gdi32full.dll", "rpcrt4.dll", "ole32.dll", "oleaut32.dll",
                        "shell32.dll", "windows.storage.dll", "msvcp140.dll",
                        "vcruntime140.dll", "clr.dll", "coreclr.dll", "mscorwks.dll"}


def _reg_value(hive, key, name, default=None):
    """One registry value or `default`; never raises."""
    if winreg is None:
        return default
    try:
        with winreg.OpenKey(_hive(hive) if isinstance(hive, str) else hive, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def office_client_paths():
    """(OfficeClickToRun.exe, OfficeC2RClient.exe) -- the repair and update
    front-ends of a Click-to-Run installation. Either may be "" if absent."""
    common = os.environ.get("CommonProgramFiles", r"C:\Program Files\Common Files")
    base = os.path.join(common, "Microsoft Shared", "ClickToRun")
    repair = os.path.join(base, "OfficeClickToRun.exe")
    update = os.path.join(base, "OfficeC2RClient.exe")
    return (repair if os.path.isfile(repair) else "", update if os.path.isfile(update) else "")


def appx_package_installed(prefix):
    """Version of an installed MSIX/AppX package for this user, by family name
    prefix (registry only -- no PowerShell), or ""."""
    for name in _subkeys(winreg.HKEY_CURRENT_USER, APPX_REPOSITORY_KEY) if winreg else []:
        if name.startswith(prefix + "_"):
            parts = name.split("_")
            return parts[1] if len(parts) > 1 else "installed"
    return ""


def office_installation():
    """What Office is on this PC, from the registry and file system alone.

    {"c2r": {platform, culture, version, products, path, repair_exe, update_exe} | None,
     "apps": {friendly: exe path that exists}, "missing": [(friendly, registered path)],
     "msi_roots": [install roots of a non-Click-to-Run Office],
     "new_outlook": version | ""}
    """
    info = {"c2r": None, "apps": {}, "missing": [], "msi_roots": [], "new_outlook": ""}
    if winreg is None:
        return info
    path = _reg_value("HKLM", OFFICE_C2R_CONFIG_KEY, "InstallationPath", "")
    version = _reg_value("HKLM", OFFICE_C2R_CONFIG_KEY, "ClientVersionToReport", "")
    if path or version:
        repair_exe, update_exe = office_client_paths()
        products = str(_reg_value("HKLM", OFFICE_C2R_CONFIG_KEY, "ProductReleaseIds", "") or "")
        info["c2r"] = {
            "platform": str(_reg_value("HKLM", OFFICE_C2R_CONFIG_KEY, "Platform", "x64") or "x64"),
            "culture": str(_reg_value("HKLM", OFFICE_C2R_CONFIG_KEY, "ClientCulture", "en-us") or "en-us"),
            "version": str(version or ""),
            "products": [p for p in products.split(",") if p],
            "path": str(path or ""),
            "repair_exe": repair_exe,
            "update_exe": update_exe,
        }
    for exe, friendly in OFFICE_APPS:
        registered = _default_value(winreg.HKEY_LOCAL_MACHINE, rf"{OFFICE_APP_PATHS_KEY}\{exe}")
        if not registered:
            continue
        registered = os.path.expandvars(registered.strip('"'))
        if os.path.isfile(registered):
            info["apps"][friendly] = registered
        else:
            info["missing"].append((friendly, registered))
    for ver in ("16.0", "15.0", "14.0"):
        root = _reg_value("HKLM", rf"SOFTWARE\Microsoft\Office\{ver}\Common\InstallRoot", "Path", "")
        if root and os.path.isdir(str(root)):
            c2r_path = (info["c2r"] or {}).get("path", "")
            if not c2r_path or not os.path.normcase(str(root)).startswith(os.path.normcase(c2r_path)):
                info["msi_roots"].append(str(root))
    info["new_outlook"] = appx_package_installed(NEW_OUTLOOK_PACKAGE)
    return info


def office_c2r_repair_command(repair_exe, kind, platform="x64", culture="en-us"):
    """argv for Office's own repair. 'quick' is offline and takes 2-10 minutes;
    'full' re-downloads Office and takes 20-60 minutes. forceappshutdown closes
    open Office apps (Office refuses to repair under them); DisplayLevel shows
    Office's own progress window."""
    repair = "QuickRepair" if kind == "quick" else "FullRepair"
    return [repair_exe, "scenario=Repair", f"platform={platform}", f"culture={culture}",
            f"RepairType={repair}", "forceappshutdown=True", "DisplayLevel=True"]


def office_c2r_update_command(update_exe):
    """argv that asks Click-to-Run to check for and install Office updates now."""
    return [update_exe, "/update", "user", "displaylevel=true", "forceappshutdown=false"]


def parse_ospp_status(text):
    """Product blocks from `cscript OSPP.VBS /dstatus`.

    Returns [{"name", "status", "error", "grace"}]. Empty for "<No installed
    product keys detected>", which is what a Microsoft 365 subscription reports
    -- subscriptions are licensed to the signed-in account, not to a key, so an
    empty list is not a fault by itself."""
    products = []
    current = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("LICENSE NAME:"):
            current = {"name": line.split(":", 1)[1].strip(), "status": "", "error": "",
                       "grace": "", "key_tail": ""}
            products.append(current)
        elif current is not None and line.startswith("LICENSE STATUS:"):
            current["status"] = line.split(":", 1)[1].strip().strip("-").strip()
        elif current is not None and line.startswith("ERROR CODE:"):
            current["error"] = line.split(":", 1)[1].strip()
        elif current is not None and line.startswith("ERROR DESCRIPTION:"):
            current["error"] = (current["error"] + " " + line.split(":", 1)[1].strip()).strip()
        elif current is not None and line.startswith("REMAINING GRACE:"):
            current["grace"] = line.split(":", 1)[1].strip()
        elif current is not None and line.lower().startswith("last 5 characters of installed product key:"):
            current["key_tail"] = line.split(":", 1)[1].strip()
    return products


def office_subscription_accounts():
    """Emails a Microsoft 365 subscription licence is mapped to on this account
    (LicensingNext\\LicenseIdToEmailMapping)."""
    if winreg is None:
        return []
    key = OFFICE_COMMON_KEY + r"\Licensing\LicensingNext\LicenseIdToEmailMapping"
    emails = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                try:
                    _n, value, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(value, str) and "@" in value and value not in emails:
                    emails.append(value)
    except OSError:
        pass
    return emails


def outlook_profiles(hive=None, key=OUTLOOK_KEY):
    """{"default": name, "profiles": [names]} for classic Outlook."""
    if winreg is None:
        return {"default": "", "profiles": []}
    hive = winreg.HKEY_CURRENT_USER if hive is None else hive
    default = _reg_value(hive, key, "DefaultProfile", "") or ""
    return {"default": str(default), "profiles": _subkeys(hive, key + r"\Profiles")}


# REG_BINARY, UTF-16LE store paths inside a profile: 001f6700 is a PST,
# 001f6610 the OST of an Exchange/Microsoft 365 account (measured on this PC).
OUTLOOK_STORE_PATH_VALUES = ("001f6700", "001f6610")


def decode_utf16_path(blob):
    """A UTF-16LE, NUL-terminated path from a MAPI property blob, or ""."""
    if not blob:
        return ""
    try:
        text = bytes(blob).decode("utf-16-le", errors="ignore")
    except Exception:
        return ""
    return text.split("\x00", 1)[0].strip()


def _walk_values(hive, key, wanted, depth=6):
    if depth < 0 or winreg is None:
        return
    try:
        k = winreg.OpenKey(hive, key)
    except OSError:
        return
    with k:
        for i in range(winreg.QueryInfoKey(k)[1]):
            try:
                name, value, _t = winreg.EnumValue(k, i)
            except OSError:
                break
            if name.lower() in wanted:
                yield value
        for child in _subkeys(hive, key):
            yield from _walk_values(hive, rf"{key}\{child}", wanted, depth - 1)


def outlook_store_paths(hive=None, key=OUTLOOK_KEY):
    """PST/OST paths declared inside the Outlook profiles (property 001f6700)."""
    if winreg is None:
        return []
    hive = winreg.HKEY_CURRENT_USER if hive is None else hive
    paths = []
    for blob in _walk_values(hive, key + r"\Profiles", set(OUTLOOK_STORE_PATH_VALUES)):
        path = decode_utf16_path(blob)
        if path and path.lower() not in {p.lower() for p in paths}:
            paths.append(os.path.expandvars(path))
    return paths


def outlook_data_files(extra_paths=()):
    """OST/NST/PST files Outlook uses: [{"path", "kind", "bytes"}], deduplicated."""
    folders = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Outlook"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "Outlook Files"),
    ]
    seen = set()
    files = []

    def _add(path):
        low = os.path.normcase(path)
        if low in seen or not os.path.isfile(path):
            return
        seen.add(low)
        ext = os.path.splitext(path)[1].lower().lstrip(".")
        if ext not in ("ost", "pst", "nst"):
            return
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        files.append({"path": path, "kind": ext, "bytes": size})

    for folder in folders:
        if folder and os.path.isdir(folder):
            try:
                for name in os.listdir(folder):
                    _add(os.path.join(folder, name))
            except OSError:
                pass
    for path in extra_paths:
        _add(path)
    return files


def outlook_size_limit_mb():
    """The ceiling Outlook enforces on a Unicode PST/OST, in MB. Policy wins,
    then the user preference, then Outlook's 50 GB default."""
    for key in (r"Software\Policies\Microsoft\Office\16.0\Outlook\PST", OUTLOOK_KEY + r"\PST"):
        value = _reg_value("HKCU", key, "MaxLargeFileSize", None)
        if isinstance(value, int) and value > 0:
            return int(value)
    return OUTLOOK_DEFAULT_SIZE_LIMIT_MB


def data_file_verdict(size_bytes, limit_mb):
    """('bad'|'warn'|'good', detail) for a data file against its size ceiling.
    Outlook stops receiving mail at the ceiling and slows well before it."""
    limit = max(1, int(limit_mb)) * 1024 * 1024
    ratio = size_bytes / limit
    size_gb = size_bytes / 1024 ** 3
    limit_gb = limit / 1024 ** 3
    if ratio >= 0.95:
        return "bad", (f"{size_gb:.1f} GB of a {limit_gb:.0f} GB ceiling -- at the limit, Outlook "
                       f"cannot add new items")
    if ratio >= 0.80:
        return "warn", f"{size_gb:.1f} GB of a {limit_gb:.0f} GB ceiling -- close to the limit"
    return "good", f"{size_gb:.1f} GB"


# Click-to-Run Office keeps its own COM registrations in a virtual registry
# hive; Office's built-in Outlook add-ins (OneNote, Social Connector, UM) are
# only resolvable through it.
C2R_VIRTUAL_CLASSES = OFFICE_C2R_KEY + r"\REGISTRY\MACHINE\Software\Classes"


def _file_url_to_path(value):
    path = str(value).split("|", 1)[0].strip().strip('"')
    if path.lower().startswith("file:///"):
        path = path[8:].replace("/", "\\")
    elif path.lower().startswith("file://"):
        path = "\\\\" + path[7:].replace("/", "\\")
    return os.path.expandvars(path)


def _progid_clsid(progid, depth=2):
    """ProgId -> CLSID through HKCR (following CurVer, as the Teams add-in
    needs) and then the Click-to-Run virtual registry."""
    if depth < 0 or not progid:
        return ""
    for root, base in ((winreg.HKEY_CLASSES_ROOT, ""),
                       (winreg.HKEY_LOCAL_MACHINE, C2R_VIRTUAL_CLASSES + "\\")):
        clsid = _default_value(root, rf"{base}{progid}\CLSID")
        if clsid:
            return clsid
        newer = _default_value(root, rf"{base}{progid}\CurVer")
        if newer and newer.lower() != progid.lower():
            clsid = _progid_clsid(newer, depth - 1)
            if clsid:
                return clsid
    return ""


def _clsid_code_path(clsid):
    """CLSID -> the file that implements it: a .NET CodeBase when present,
    else the InprocServer32/LocalServer32 path; HKCR first, then Click-to-Run's
    virtual registry."""
    for hive, base in (("HKCR", ""), ("HKLM", C2R_VIRTUAL_CLASSES + "\\")):
        codebase = _reg_value(hive, rf"{base}CLSID\{clsid}\InprocServer32", "CodeBase", "")
        if isinstance(codebase, str) and codebase:
            return _file_url_to_path(codebase)
        for server in ("InprocServer32", "LocalServer32"):
            value = _default_value(_hive(hive), rf"{base}CLSID\{clsid}\{server}")
            if value:
                return os.path.expandvars(value.strip('"'))
    return ""


def _addin_path(hive, key, progid):
    """Where an add-in's code lives: its VSTO manifest, the .NET CodeBase, or
    the COM server DLL, resolved through the ProgId's CLSID."""
    manifest = _reg_value(hive, key, "Manifest", "")
    if isinstance(manifest, str) and manifest:
        return _file_url_to_path(manifest)
    clsid = _progid_clsid(progid)
    return _clsid_code_path(clsid) if clsid else ""


def office_addins(roots=OUTLOOK_ADDIN_ROOTS):
    """COM add-ins registered for Outlook, each resolved to its code path:
    [{"scope", "hive", "key", "progid", "name", "load_behavior", "behavior", "path", "home"}]."""
    if winreg is None:
        return []
    addins = []
    for scope, root, hive_name in roots:
        hive = _hive(hive_name)
        for progid in _subkeys(hive, root):
            key = rf"{root}\{progid}"
            behavior = _reg_value(hive, key, "LoadBehavior", None)
            name = _reg_value(hive, key, "FriendlyName", "") or progid
            path = _addin_path(hive, key, progid)
            addins.append({
                "scope": scope, "hive": hive_name, "key": key, "progid": progid,
                "name": str(name), "load_behavior": behavior if isinstance(behavior, int) else None,
                "behavior": LOAD_BEHAVIOR.get(behavior, "unset") if isinstance(behavior, int) else "unset",
                "path": path, "home": os.path.dirname(path) if path else "",
            })
    return addins


def addin_for_module(module_path, addins, office_root=""):
    """The add-in whose code a crashing module belongs to, or None.

    A module is matched by exact file name, or by living inside the add-in's
    own folder. The folder rule is skipped for add-ins that live inside Office's
    install tree (Office ships several of its own), otherwise every crash in
    OUTLOOK.EXE would be pinned on whichever built-in add-in shares the folder."""
    if not module_path:
        return None
    module = os.path.normcase(module_path)
    base = os.path.basename(module)
    root = os.path.normcase(office_root or "").rstrip("\\")
    for addin in addins:
        path = os.path.normcase(addin.get("path") or "")
        if path and os.path.basename(path) == base:
            return addin
        home = os.path.normcase(addin.get("home") or "").rstrip("\\")
        if not home or len(home) <= 3:
            continue
        if root and home.startswith(root + "\\"):
            continue
        if module.startswith(home + "\\"):
            return addin
    return None


def classify_office_crash(module, module_path, addins, office_root, windows_root=None):
    """Where did a crash land? -> (category, addin | None) with category one of
    'addin', 'gpu', 'office', 'windows', 'other', 'unknown'. Each category maps
    to a different repair, which is why the module matters more than the app."""
    name = os.path.basename((module_path or module or "")).lower()
    if not name:
        return "unknown", None
    match = addin_for_module(module_path or module, addins, office_root)
    if match is not None:
        return "addin", match
    if name.startswith(GPU_MODULE_PREFIXES) and name.endswith(".dll"):
        return "gpu", None
    root = os.path.normcase(office_root or "")
    path = os.path.normcase(module_path or "")
    if root and path.startswith(root.rstrip("\\") + "\\"):
        return "office", None
    if name.startswith(("mso", "olmapi", "outlmime", "wwlib", "excel", "outlook", "riched20", "olk")):
        return "office", None
    windows_root = os.path.normcase(windows_root or os.environ.get("SystemRoot", r"C:\Windows"))
    if name in WINDOWS_CORE_MODULES or (windows_root and path.startswith(windows_root.rstrip("\\") + "\\")):
        return "windows", None
    return "other", None


def office_crash_events(days=14, runner=None):
    """Application Error (1000) and Application Hang (1002) events for Office
    executables: [{"time", "kind", "app", "module", "module_path", "exception"}].
    Event 1000's properties are 0=app, 3=module, 6=exception code, 11=module
    path (measured; the off-by-one is easy). Returns None if the log could not
    be read, which is different from "no crashes"."""
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        f"$ev = Get-WinEvent -FilterHashtable @{{LogName='Application'; "
        f"ProviderName='Application Error','Application Hang'; StartTime=(Get-Date).AddDays(-{int(days)})}} "
        "-MaxEvents 600; "
        "$rows = foreach ($e in $ev) { $p = $e.Properties; "
        "[pscustomobject]@{ time = $e.TimeCreated.ToString('s'); id = $e.Id; "
        "app = \"$($p[0].Value)\"; module = if ($e.Id -eq 1000) { \"$($p[3].Value)\" } else { '' }; "
        "exception = if ($e.Id -eq 1000) { \"$($p[6].Value)\" } else { '' }; "
        "module_path = if ($e.Id -eq 1000 -and $p.Count -gt 11) { \"$($p[11].Value)\" } else { '' } } }; "
        "Write-Output '[' ; if ($rows) { $rows | ConvertTo-Json -Compress -Depth 2 }; Write-Output ']'; "
        "Write-Output 'WINMEND-EVENTS-DONE'"
    )
    if runner is None:
        def runner(cmd):
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=120,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return proc.stdout or ""
    try:
        out = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    except Exception:
        return None
    return parse_office_crash_output(out)


def parse_office_crash_output(out):
    """JSON rows between the markers -> Office-only event list, or None when the
    completion marker is missing (Get-WinEvent exits non-zero on *no matches*,
    so the marker is what separates 'clean' from 'unreadable')."""
    if "WINMEND-EVENTS-DONE" not in (out or ""):
        return None
    body = out.split("WINMEND-EVENTS-DONE", 1)[0]
    start = body.find("[")
    end = body.rfind("]")
    rows = []
    if start != -1 and end > start:
        inner = body[start + 1:end].strip()
        if inner:
            try:
                parsed = json.loads(inner)
            except ValueError:
                # ConvertTo-Json emits an object for a single row, an array otherwise
                try:
                    parsed = json.loads("[" + inner + "]")
                except ValueError:
                    parsed = []
            rows = parsed if isinstance(parsed, list) else [parsed]
    events = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        app = str(row.get("app") or "").lower()
        if app not in OFFICE_PROCESS_NAMES:
            continue
        events.append({
            "time": str(row.get("time") or ""),
            "kind": "hang" if str(row.get("id")) == "1002" else "crash",
            "app": OFFICE_PROCESS_NAMES[app],
            "module": str(row.get("module") or ""),
            "module_path": str(row.get("module_path") or ""),
            "exception": str(row.get("exception") or ""),
        })
    return events


def summarize_office_crashes(events, addins, office_root):
    """Group crash events by what they point at.

    {"total", "hangs", "by_app": {app: n}, "by_category": {cat: n},
     "addins": {progid: {"addin", "count"}}, "gpu": n, "modules": {module: n}}"""
    summary = {"total": 0, "hangs": 0, "by_app": {}, "by_category": {}, "addins": {},
               "gpu": 0, "modules": {}}
    for event in events or []:
        summary["total"] += 1
        summary["by_app"][event["app"]] = summary["by_app"].get(event["app"], 0) + 1
        if event["kind"] == "hang":
            summary["hangs"] += 1
            summary["by_category"]["hang"] = summary["by_category"].get("hang", 0) + 1
            continue
        category, addin = classify_office_crash(event["module"], event["module_path"], addins, office_root)
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        module = os.path.basename(event["module_path"] or event["module"]).lower()
        if module:
            summary["modules"][module] = summary["modules"].get(module, 0) + 1
        if category == "addin" and addin is not None:
            entry = summary["addins"].setdefault(addin["progid"], {"addin": addin, "count": 0})
            entry["count"] += 1
        elif category == "gpu":
            summary["gpu"] += 1
    return summary


def office_auth_findings(read=None, watchlist=OFFICE_AUTH_WATCHLIST):
    """Watchlist rows whose value is currently at its harmful setting:
    [{"hive", "key", "value", "current", "harm"}]. `read(hive, key, value)`
    is injectable so the classifier can be tested without a registry."""
    read = read or (lambda hive, key, value: _reg_value(hive, key, value, None))
    findings = []
    for hive, key, value, harmful, harm in watchlist:
        current = read(hive, key, value)
        if current is not None and current == harmful:
            findings.append({"hive": hive, "key": key, "value": value, "current": current, "harm": harm})
    return findings


def office_hardware_acceleration_disabled():
    return _reg_value("HKCU", OFFICE_COMMON_KEY + r"\Graphics", "DisableHardwareAcceleration", 0) == 1


def outlook_minimizes_to_tray():
    return _reg_value("HKCU", OUTLOOK_KEY + r"\Preferences", "MinToTray", 0) == 1


def default_mail_client():
    return _default_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\Mail") if winreg else ""


def windowless_processes(names, min_age=60, now=None, procs=None, windowed=None):
    """Processes in `names` older than `min_age` seconds that own no visible
    window: [{"pid", "name", "friendly", "age"}]. An Outlook in this state is
    the most common reason "Outlook will not open" -- the last instance never
    exited and the new one hands off to it and quits."""
    try:
        import psutil
    except ImportError:
        return []
    wanted = {n.lower() for n in names}
    now = time.time() if now is None else now
    windowed = pids_with_visible_windows() if windowed is None else set(windowed)
    if procs is None:
        # Only this user's processes: another signed-in account's Outlook has
        # no window on this desktop and is not stuck, just elsewhere.
        try:
            me = psutil.Process().username()
        except Exception:
            me = None
        procs = []
        for proc in psutil.process_iter(["name", "pid", "create_time", "username"]):
            try:
                owner = proc.info.get("username")
                if me and owner and owner != me:
                    continue
                procs.append((proc.pid, (proc.info.get("name") or ""), proc.info.get("create_time") or now))
            except Exception:
                continue
    found = []
    for pid, name, created in procs:
        low = name.lower()
        if low not in wanted or low in OFFICE_BACKGROUND_OK or pid in windowed:
            continue
        age = now - created
        if age < min_age:
            continue
        found.append({"pid": pid, "name": name, "friendly": OFFICE_PROCESS_NAMES.get(low, name), "age": age})
    return found


def service_state(name):
    """{"status", "start"} for a Windows service, or None if it does not exist."""
    try:
        import psutil
        svc = psutil.win_service_get(name)
        return {"status": svc.status(), "start": svc.start_type()}
    except Exception:
        return None


def parse_cmdkey_list(text):
    """Target names from `cmdkey /list`. Generic credentials print as
    'LegacyGeneric:target=<name>'; <name> is what /delete: takes."""
    targets = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.lower().startswith("target:"):
            continue
        target = line.split(":", 1)[1].strip()
        if target.lower().startswith("legacygeneric:target="):
            target = target.split("=", 1)[1]
        targets.append(target)
    return targets


def office_credential_targets(targets, prefixes=OFFICE_CREDENTIAL_PREFIXES):
    return [t for t in targets if t.startswith(prefixes)]


def build_office_repair_options(report):
    """Turn the measured report into the checklist the user sees.

    Each option: {"key", "label", "detail", "checked", "evidence"}. `checked`
    is on only when a measurement points at the repair; options with no
    evidence are offered unchecked with a plain statement of what they cost.
    Pure, so the defaults can be tested against scripted reports."""
    opts = []
    c2r = report.get("c2r")
    apps = report.get("apps") or {}
    classic_outlook = "Outlook" in apps
    crashes = report.get("crashes") or {}
    total_crashes = crashes.get("total", 0)

    for proc in report.get("stuck") or []:
        opts.append({
            "key": f"end:{proc['pid']}",
            "label": f"End the {proc['friendly']} process running without a window (PID {proc['pid']})",
            "detail": f"Running for {format_elapsed(proc['age'])} with no window. A leftover instance "
                      f"like this is the most common reason {proc['friendly']} will not open.",
            "checked": proc["friendly"] == "Outlook", "evidence": "windowless process"})

    svc = report.get("clicktorun")
    if c2r and svc is not None and (svc["status"] != "running" or svc["start"] != "automatic"):
        opts.append({
            "key": "service:clicktorun",
            "label": "Start the Office Click-to-Run service and set it to Automatic",
            "detail": f"It is {svc['status']} / {svc['start']}. Every Office app needs it running; "
                      f"without it they fail to start or report 'something went wrong'.",
            "checked": True, "evidence": "service state"})
    spp = report.get("sppsvc")
    if spp is not None and spp["start"] == "disabled":
        opts.append({
            "key": "service:sppsvc",
            "label": "Re-enable the Software Protection service",
            "detail": "It is disabled. Office (and Windows) activation checks fail without it, "
                      "which shows up as 'Unlicensed Product'.",
            "checked": True, "evidence": "service state"})
    search = report.get("wsearch")
    if classic_outlook and search is not None and (search["start"] == "disabled" or search["status"] != "running"):
        opts.append({
            "key": "service:wsearch",
            "label": "Turn Windows Search back on so Outlook search works",
            "detail": f"Windows Search is {search['status']} / {search['start']}. Outlook's search box "
                      f"depends on it and shows 'Search results may be incomplete' without it. WinMend's "
                      f"RAM Optimizations task is one thing that turns it off; untick this to keep it off.",
            "checked": search["start"] == "disabled", "evidence": "service state"})

    for finding in report.get("auth") or []:
        opts.append({
            "key": f"auth:{finding['hive']}\\{finding['key']}\\{finding['value']}",
            "label": f"Remove {finding['value']} = {finding['current']} ({finding['hive']})",
            "detail": f"Reversible. {finding['harm'][0].upper()}{finding['harm'][1:]}.",
            "checked": True, "evidence": "registry value"})

    for progid, entry in (crashes.get("addins") or {}).items():
        addin = entry["addin"]
        if addin.get("load_behavior") in (None, 0, 2):
            continue
        opts.append({
            "key": f"addin:{addin['hive']}\\{addin['key']}",
            "label": f"Turn off the add-in '{addin['name']}'",
            "detail": f"Reversible. {entry['count']} crash(es) in the last two weeks landed inside "
                      f"{os.path.basename(addin['path']) or addin['progid']}, which belongs to this add-in.",
            "checked": True, "evidence": "crash module"})

    if crashes.get("gpu", 0) and not report.get("hw_accel_off"):
        opts.append({
            "key": "graphics:off",
            "label": "Turn off Office hardware graphics acceleration",
            "detail": f"Reversible. {crashes['gpu']} crash(es) landed inside a display-driver module; "
                      f"this is the standard fix for Office windows that flicker, go black, or crash on draw.",
            "checked": True, "evidence": "crash module"})

    if c2r and c2r.get("repair_exe"):
        reasons = []
        if total_crashes:
            reasons.append(f"{total_crashes} crash/hang event(s) in the last two weeks")
        if report.get("missing"):
            reasons.append(f"{len(report['missing'])} registered Office program(s) missing on disk")
        if crashes.get("by_category", {}).get("office"):
            reasons.append("crashes inside Office's own files")
        opts.append({
            "key": "repair:quick",
            "label": "Run Office Quick Repair (offline, 2-10 minutes, closes Office apps)",
            "detail": ("Microsoft's own repair: re-registers Office and replaces damaged files without "
                       "re-downloading. Documents and settings are kept. "
                       + (f"Recommended because of {'; '.join(reasons)}." if reasons
                          else "Nothing measured points at a damaged install, so this is unticked; "
                               "tick it if an Office app will not start or shows 'something went wrong'.")),
            "checked": bool(reasons), "evidence": "; ".join(reasons)})
        opts.append({
            "key": "repair:full",
            "label": "Run Office Online Repair instead (re-downloads Office, 20-60 minutes)",
            "detail": "For when Quick Repair did not help. Needs internet; reinstalls Office in place "
                      "and keeps documents and settings. Overrides Quick Repair if both are ticked.",
            "checked": False, "evidence": ""})
        if c2r.get("update_exe"):
            opts.append({
                "key": "update:office",
                "label": "Check for Office updates now",
                "detail": f"Installed build {c2r.get('version') or 'unknown'}. Runs Office's own updater "
                          f"(OfficeC2RClient /update user); its window shows progress.",
                "checked": False, "evidence": ""})

    if classic_outlook and report.get("profiles", {}).get("profiles"):
        opts.append({
            "key": "outlook:navpane",
            "label": "Reset the Outlook navigation pane (outlook.exe /resetnavpane)",
            "detail": "For 'Cannot start Microsoft Outlook. Cannot open the Outlook window' and 'the set "
                      "of folders cannot be opened'. Starts Outlook. Your Favorites list and folder-pane "
                      "customisations are cleared; mail, rules and accounts are untouched.",
            "checked": False, "evidence": ""})
    ost_files = [f for f in (report.get("data_files") or []) if f["kind"] in ("ost", "nst")]
    if ost_files:
        bad = [f for f in ost_files if f.get("verdict") == "bad"]
        opts.append({
            "key": "outlook:rebuild_ost",
            "label": f"Rebuild the Outlook offline cache ({len(ost_files)} .ost/.nst file(s))",
            "detail": ("The cache files are renamed, not deleted, and Outlook downloads a fresh copy "
                       "from the mail server on next start. Fixes a corrupted cache ('the file cannot be "
                       "accessed', stuck at Loading Profile, folders that never update). Anything written "
                       "while offline and not yet synced is lost; POP accounts' .pst files are never touched. "
                       "Outlook must be closed."
                       + (f" {len(bad)} file(s) are at the size ceiling." if bad else "")),
            "checked": bool(bad), "evidence": "size ceiling" if bad else ""})

    if c2r:
        licence_faults = [p for p in report.get("ospp") or [] if p["status"].upper() != "LICENSED"]
        opts.append({
            "key": "identity:reset",
            "label": "Reset Office sign-in and licence cache (you will sign in again)",
            "detail": ("Microsoft's 'reset activation state' procedure: cached Office identities, licence "
                       "tokens and Office credentials are removed (registry keys are exported to a backup "
                       "first). Fixes 'Unlicensed Product', 'We couldn't sign you in', endless password "
                       "prompts and 'Account error'. Office and Teams ask you to sign in again. "
                       + (f"{len(licence_faults)} licence(s) report a non-LICENSED state." if licence_faults
                          else "Nothing measured points at a licence fault, so this is unticked.")),
            "checked": bool(licence_faults), "evidence": "licence state" if licence_faults else ""})

    if not classic_outlook and not report.get("new_outlook"):
        opts.append({
            "key": "install:new_outlook",
            "label": "Install the new Outlook for Windows from the Microsoft Store",
            "detail": "No Outlook is installed for this account -- classic Outlook is not part of this "
                      "Office install and the Store app is absent (WinMend's debloat removes it). "
                      "Installs through winget from the Microsoft Store.",
            "checked": False, "evidence": "no Outlook installed"})
    return opts
