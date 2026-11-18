"""WinMend diagnostics: hardware: events."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from winmend.diagnostics.hardware.reference import _num
import os
import re
import struct
import time


class HardwareEventsMixin:
    """HardwareProbe methods grouped by responsibility."""

    # ---- the logs, read exhaustively --------------------------------------

    def event_log_sweep(self, days=14, budget=70):
        """Every enabled log on the machine, clustered by what keeps repeating.

        The System and Application logs are the two everybody reads, and they are
        maybe a fiftieth of what Windows records. The rest -- the per-component
        Operational logs -- are where storage, PnP, WHEA, disk diagnostics and
        driver framework failures actually land.

        Reading them raw would be useless: a busy machine produces thousands of
        errors, nearly all of them routine noise. What makes it diagnostic is
        clustering by provider and id, because a real fault repeats. One
        occurrence of an error is Tuesday; four hundred of the same one is the
        thing that is wrong.

        Self-limiting by design: it works through logs in descending size and
        stops at ``budget`` seconds, reporting how far it got, because on a
        machine with a thousand logs the alternative is an unbounded wait.
        """
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$sw=[Diagnostics.Stopwatch]::StartNew();"
            "$logs=Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | "
            "Where-Object { $_.RecordCount -gt 0 -and $_.IsEnabled } | "
            "Sort-Object RecordCount -Descending;"
            "$seen=0;"
            "foreach($l in $logs){"
            "  if($sw.Elapsed.TotalSeconds -gt %d){break};"
            "  $seen++;"
            "  try{"
            "    $e=Get-WinEvent -FilterHashtable @{LogName=$l.LogName;Level=1,2;StartTime=$t} "
            "-MaxEvents 400 -ErrorAction Stop;"
            "    $e | Group-Object ProviderName,Id | ForEach-Object {"
            "      $f=$_.Group[0];"
            "      Write-Output ('G|'+(([string]$l.LogName) -replace '\\|',' ')+'|'"
            "+(([string]$f.ProviderName) -replace '\\|',' ')+'|'+[string]$f.Id+'|'"
            "+[string]$_.Count+'|'+[string]$f.LevelDisplayName+'|'"
            "+$f.TimeCreated.ToString('s')+'|'"
            "+((([string]$f.Message) -replace '[\\r\\n\\|]',' ')))"
            "    }"
            "  }catch{}"
            "};"
            "Write-Output ('N|'+[string]$seen+'|'+[string]$logs.Count)"
        ) % (max(1, int(days)), max(10, int(budget)))
        ready, rows, err = self._ps_events(script, timeout=int(budget) + 40)
        if not ready:
            return {"available": False, "reason": (err or "")[:200]}

        clusters, scanned, total_logs = [], 0, 0
        for row in rows:
            if row[0] == "N" and len(row) >= 3:
                scanned, total_logs = _num(row[1], 0) or 0, _num(row[2], 0) or 0
                continue
            if row[0] != "G" or len(row) < 7:
                continue
            clusters.append({
                "log": row[1].strip(),
                "provider": row[2].strip(),
                "id": _num(row[3]),
                "count": _num(row[4], 0) or 0,
                "level": row[5].strip(),
                "newest": row[6],
                "message": (row[7][:240] if len(row) > 7 else ""),
            })
        clusters.sort(key=lambda c: -c["count"])
        critical = [c for c in clusters if c["level"].lower() == "critical"]
        # "Repeating" is the whole signal, and the threshold has to survive a
        # machine that has simply been on for a fortnight. Ten of the same error
        # in two weeks is a pattern; three is a bad afternoon.
        repeating = [c for c in clusters if c["count"] >= 10]
        return {
            "available": True,
            "clusters": clusters[:40],
            "cluster_count": len(clusters),
            "total_errors": sum(c["count"] for c in clusters),
            "critical": critical[:10],
            "critical_count": len(critical),
            "repeating": repeating[:15],
            "logs_scanned": scanned,
            "logs_total": total_logs,
            # An incomplete sweep must say so: "nothing found" in the half it
            # never opened is not a result.
            "complete": bool(total_logs and scanned >= total_logs),
            "days": int(days),
        }

    def wer_reports(self, days=45, limit=400):
        """Windows Error Reporting's archive: every crash, with what faulted.

        ``app_crashes`` counts crashes from the event log. The WER archive is the
        same events with the evidence still attached -- for each one, the
        faulting module and the exception code. That difference decides what to
        do about it: forty crashes across six unrelated applications that all
        fault inside the same DLL is one broken component, not six broken
        programs, and only the module name reveals that.

        Plain files on disk, so this needs no elevation and no event-log query.
        """
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / \
            "Microsoft" / "Windows" / "WER"
        cutoff = time.time() - max(1, int(days)) * 86400
        files = []
        for folder in ("ReportArchive", "ReportQueue"):
            directory = base / folder
            if not directory.is_dir():
                continue
            try:
                for report in directory.glob("*/Report.wer"):
                    try:
                        stat = report.stat()
                    except OSError:
                        continue
                    if stat.st_mtime >= cutoff:
                        files.append((stat.st_mtime, report))
            except OSError:
                continue
        if not files:
            return {"available": False, "reason": "no error reports in the archive"}
        files.sort(reverse=True)

        crashes, modules, applications, kinds = [], {}, {}, {}
        for mtime, report in files[:int(limit)]:
            fields = self._read_wer(report)
            if not fields:
                continue
            event_type = fields.get("EventType", "")
            application = fields.get("Application Name") or fields.get("AppName") or ""
            module = (fields.get("Fault Module Name")
                      or fields.get("ModName") or "")
            code = fields.get("Exception Code") or fields.get("ExceptionCode") or ""
            crashes.append({
                "time": datetime.fromtimestamp(
                    mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                "type": event_type,
                "application": application,
                "module": module,
                "module_version": fields.get("Fault Module Version", ""),
                "code": code,
            })
            kinds[event_type] = kinds.get(event_type, 0) + 1
            if module:
                modules[module] = modules.get(module, 0) + 1
            if application:
                applications[application] = applications.get(application, 0) + 1

        if not crashes:
            return {"available": False, "reason": "the reports could not be parsed"}
        ranked = sorted(modules.items(), key=lambda kv: -kv[1])
        top_module, top_count = ranked[0] if ranked else ("", 0)
        # A module is only interesting when it is faulting for more than one
        # program: a single app crashing in its own DLL is that app's bug.
        spread = len({c["application"] for c in crashes
                      if c["module"] == top_module and c["application"]})
        return {
            "available": True,
            "count": len(crashes),
            "crashes": crashes[:20],
            "modules": dict(ranked[:12]),
            "applications": dict(sorted(applications.items(), key=lambda kv: -kv[1])[:12]),
            "types": kinds,
            "top_module": top_module,
            "top_module_count": top_count,
            "top_module_apps": spread,
            "shared_fault": bool(top_module and spread >= 3 and top_count >= 4),
            "days": int(days),
        }

    @staticmethod
    def _read_wer(path):
        """Parse one Report.wer into a flat ``{name: value}`` dictionary.

        The format is INI-like but the interesting parts are indirect: numbered
        ``Sig[n].Name``/``Sig[n].Value`` pairs whose meaning is carried in the
        name rather than the key, so they are folded together here.
        """
        text = ""
        for encoding in ("utf-16", "utf-8-sig", "latin-1"):
            try:
                text = path.read_text(encoding=encoding, errors="strict")
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
            except OSError:
                return {}
        if not text:
            return {}
        fields, signature = {}, {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key, value = key.strip(), value.strip()
            match = re.fullmatch(r"Sig\[(\d+)\]\.(Name|Value)", key)
            if match:
                index, part = match.group(1), match.group(2)
                signature.setdefault(index, {})[part] = value
            elif key and key not in fields:
                fields[key] = value
        for pair in signature.values():
            name, value = pair.get("Name"), pair.get("Value")
            if name and value:
                fields.setdefault(name, value)
        return fields

    def minidump_details(self, days=90, limit=20):
        """Read the stop code straight out of each crash dump header.

        ``bugchecks`` gets its stop codes from the event log, which is fine until
        the event is missing -- and it very often is, because the entry is
        written on the *next* boot and is lost whenever the machine crashes
        again first, or the log wraps. The dump file itself always has it.

        No debugger is involved. The bugcheck code and its four parameters sit at
        fixed offsets in a documented header, which is a few dozen bytes to read.
        The parameters matter as much as the code: on a 0x124 hardware bugcheck
        the first one names the component that raised it, which is the difference
        between blaming the CPU and blaming a PCIe device.
        """
        folder = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Minidump"
        cutoff = time.time() - max(1, int(days)) * 86400
        entries = []
        try:
            if folder.is_dir():
                for dump in folder.glob("*.dmp"):
                    try:
                        stat = dump.stat()
                    except OSError:
                        continue
                    if stat.st_mtime >= cutoff:
                        entries.append((stat.st_mtime, dump))
        except OSError:
            return {"available": False, "reason": "the minidump folder is unreadable"}
        if not entries:
            return {"available": False, "reason": "no recent crash dumps"}
        entries.sort(reverse=True)

        dumps, codes = [], {}
        for mtime, dump in entries[:int(limit)]:
            parsed = self._read_dump_header(dump)
            if not parsed:
                continue
            parsed["file"] = dump.name
            parsed["time"] = datetime.fromtimestamp(
                mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            dumps.append(parsed)
            code = parsed["code_hex"]
            codes[code] = codes.get(code, 0) + 1
        if not dumps:
            return {"available": False, "reason": "the crash dumps could not be read"}
        return {
            "available": True,
            "count": len(dumps),
            "dumps": dumps,
            "codes": codes,
            "distinct_codes": len(codes),
            # The same stop code every time points at one cause; a scatter of
            # different ones is the signature of memory or power, where whatever
            # happens to be running is what dies.
            "repeating": max(codes.values()) if codes else 0,
            "newest": dumps[0]["time"],
            "days": int(days),
        }

    @staticmethod
    def _read_dump_header(path):
        """Pull the bugcheck code and parameters out of a crash dump header.

        Both header layouts are handled because the field offsets differ between
        them, and reading a 64-bit dump with the 32-bit offsets yields a
        plausible-looking wrong answer rather than an error.
        """
        try:
            with open(path, "rb") as handle:
                head = handle.read(0x60)
        except OSError:
            return None
        if len(head) < 0x60 or head[:4] != b"PAGE":
            return None
        valid = head[4:8]
        try:
            if valid == b"DU64":
                code = struct.unpack_from("<I", head, 0x38)[0]
                params = struct.unpack_from("<4Q", head, 0x40)
                bits = 64
            elif valid == b"DUMP":
                code = struct.unpack_from("<I", head, 0x28)[0]
                params = struct.unpack_from("<4I", head, 0x2C)
                bits = 32
            else:
                return None
        except struct.error:
            return None
        if not code:
            return None
        return {
            "code": code,
            "code_hex": f"0x{code:08X}",
            "parameters": [f"0x{p:X}" for p in params],
            "bits": bits,
        }
