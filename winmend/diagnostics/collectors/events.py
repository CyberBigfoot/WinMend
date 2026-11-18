"""WinMend diagnostics: collectors: events."""

from __future__ import annotations

from winmend.diagnostics.helpers import _days_ago
from winmend.diagnostics.reference import (
    EXCEPTION_CODES,
    describe_bugcheck,
    describe_wu_error,
    module_vendor,
)
import re


class ProbeEventsMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- error-code intelligence -----------------------------------------

    def bugchecks(self, days=30):
        """Recorded stop codes -- System/1001 BugCheck."""
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$t;"
            "ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001} "
            "-MaxEvents 25 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){$xml=[xml]$x.ToXml();$d=@{};foreach($n in $xml.Event.EventData.Data){$d[$n.Name]=$n.'#text'};"
            "$code=$d['param1'];if(-not $code){$code=$x.Message};"
            "Write-Output ('BC|'+$x.TimeCreated.ToUniversalTime().ToString('o')+'|'+"
            "($code -replace '[\\r\\n\\|]',' ')+'|'+[string]$d['param2'])}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=30)
        crashes = []
        for row in rows:
            if row[0] != "BC" or len(row) < 3:
                continue
            message = row[2]
            match = re.search(r"0x([0-9a-fA-F]{8})(?:\s*\(|\s*$)", message)
            code = int(match.group(1), 16) if match else None
            name, cause, tags = describe_bugcheck(code) if code is not None else ("UNKNOWN", "", ())
            dump = re.search(r"([A-Za-z]:\\[^\s|]+\.dmp)", message)
            crashes.append({
                "time": row[1],
                "code": f"0x{code:08X}" if code is not None else "",
                "name": name,
                "cause": cause,
                "tags": list(tags),
                "dump": row[3] if len(row) > 3 else dump.group(1) if dump else "",
            })
        return {"available": ready, "count": len(crashes), "crashes": crashes}

    def update_failures(self, days=30):
        """Windows Update install failures with their error codes."""
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{"
            "LogName='Microsoft-Windows-WindowsUpdateClient/Operational';"
            "StartTime=$t;Id=@(19,20,25)} -MaxEvents 80 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){$xml=[xml]$x.ToXml();$d=@{};foreach($n in $xml.Event.EventData.Data){$d[$n.Name]=$n.'#text'};"
            "$kind=if($x.Id -eq 19){'WUS'}else{'WUF'};"
            "Write-Output ($kind+'|'+$x.TimeCreated.ToUniversalTime().ToString('o')+'|'+[string]$d['errorCode']+'|'+"
            "([string]$d['updateTitle'] -replace '[\\r\\n\\|]',' ')+'|'+[string]$d['updateGuid']+'|'+[string]$d['updateRevisionNumber']+'|'+[string]$x.RecordId)}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=30)
        failures = []
        successes = {}
        success_records = {}
        max_record_id = 0
        for row in rows:
            try:
                record_id = int(row[6]) if len(row) > 6 else 0
            except ValueError:
                record_id = 0
            max_record_id = max(max_record_id, record_id)
            if row[0] == "WUS" and len(row) >= 5:
                identifier = (row[4] + ":" + (row[5] if len(row) > 5 else "")) if row[4] else row[3]
                if identifier:
                    successes[identifier] = max(successes.get(identifier, ""), row[1])
                    success_records[identifier] = max(success_records.get(identifier, 0), record_id)
        for row in rows:
            if row[0] not in ("WU", "WUF") or len(row) < 3:
                continue
            identifier = ""
            if row[0] == "WUF" and len(row) >= 5:
                identifier = (row[4] + ":" + (row[5] if len(row) > 5 else "")) if row[4] else row[3]
                try:
                    failed_record = int(row[6]) if len(row) > 6 else 0
                except ValueError:
                    failed_record = 0
                succeeded_record = success_records.get(identifier, 0)
                if identifier and ((failed_record > 0 and succeeded_record >= failed_record) or
                                   (not failed_record and successes.get(identifier, "") >= row[1])):
                    continue
            message = row[2]
            code_match = re.search(r"(0x[0-9A-Fa-f]{8})", message)
            code = code_match.group(1) if code_match else ""
            if not code and row[0] == "WUF":
                try:
                    code = f"0x{int(message) & 0xffffffff:08X}"
                except ValueError:
                    pass
            meaning, remedy = describe_wu_error(code)
            name_match = re.search(r"[:\-]\s*(.+?)(?:\.|$)", message)
            failures.append({
                "time": row[1],
                "identity": identifier,
                "record_id": int(row[6]) if len(row) > 6 and row[6].isdigit() else None,
                "code": code,
                "meaning": meaning or "",
                "remedy": remedy or "",
                "update": row[3] if row[0] == "WUF" and len(row) > 3 else (name_match.group(1).strip()[:90] if name_match else ""),
            })
        return {"available": ready, "count": len(failures), "failures": failures,
                "max_record_id": max_record_id,
                "successes": [{"identity": key, "time": stamp, "record_id": success_records.get(key)} for key, stamp in sorted(successes.items())]}

    def app_crashes(self, days=14, top=6):
        """Application-log crashes grouped by app and faulting module."""
        script = (
            "$t=(Get-Date).AddDays(-%d);"
            "$e=Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$t;Id=@(1000,1002)} "
            "-MaxEvents 200 -ErrorAction SilentlyContinue;"
            "foreach($x in $e){if($x.ProviderName -notin @('Application Error','Application Hang')){continue};"
            "$d=$x.Properties | ForEach-Object {$_.Value};"
            "Write-Output ('APP|'+$x.Id+'|'+$x.TimeCreated.ToUniversalTime().ToString('o')+'|'+($d -join '~'))}"
        ) % max(1, int(days))
        ready, rows, _ = self._ps_events(script, timeout=30)
        grouped = {}
        for row in rows:
            if row[0] != "APP" or len(row) < 4:
                continue
            fields = row[3].split("~")
            if not fields:
                continue
            app = (fields[0] or "").strip().lower()
            if not app:
                continue
            hang = row[1].strip() == "1002"
            module = ""
            exception = ""
            if not hang:
                # Application Error (1000) property order, verified against live
                # events: 0 app name, 1 app version, 2 app stamp, 3 MODULE NAME,
                # 4 module version, 5 module stamp, 6 EXCEPTION CODE, 7 offset.
                module = (fields[3] or "").strip().lower() if len(fields) > 3 else ""
                exception = (fields[6] or "").strip().lower() if len(fields) > 6 else ""
                exception = exception.replace("0x", "").lstrip("0").rjust(8, "0")
            key = (app, module)
            entry = grouped.setdefault(key, {
                "app": app, "module": module, "count": 0, "hangs": 0,
                "exception": exception, "last": row[2],
            })
            entry["count"] += 1
            if hang:
                entry["hangs"] += 1
            if exception and not entry["exception"]:
                entry["exception"] = exception
        crashes = sorted(grouped.values(), key=lambda item: item["count"], reverse=True)[:top]
        for crash in crashes:
            vendor, area = module_vendor(crash["module"])
            crash["vendor"] = vendor or ""
            crash["area"] = area or ""
            crash["exception_meaning"] = EXCEPTION_CODES.get(crash["exception"], "")
        return {"available": ready, "crashes": crashes}

    def reliability_history(self, days=45):
        """Windows' own stability score, by day.

        This is the closest thing Windows keeps to "when did this PC get worse",
        and it is the only source on the machine that can be lined up against
        the user's account of when the trouble started.
        """
        script = (
            "$m=Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue;"
            "if($m){foreach($g in ($m | Group-Object {$_.TimeGenerated.ToString('yyyy-MM-dd')})){"
            "Write-Output ('DAY|'+$g.Name+'|'+"
            "([math]::Round(($g.Group | Measure-Object SystemStabilityIndex -Minimum).Minimum,2)))}}"
        )
        ready, rows, _ = self._ps_events(script, timeout=30)
        if not ready:
            return {"available": False}
        series = []
        for row in rows:
            if row[0] != "DAY" or len(row) < 3:
                continue
            try:
                score = float(row[2])
            except (ValueError, TypeError):
                continue
            age = _days_ago(row[1])
            if age is None or age > days:
                continue
            series.append({"date": row[1], "index": score, "days_ago": round(age, 1)})
        if not series:
            return {"available": True, "days": 0, "series": []}
        series.sort(key=lambda item: item["date"])
        recent = series[-7:]
        earlier = series[:-7] or series
        recent_avg = sum(item["index"] for item in recent) / len(recent)
        base_avg = sum(item["index"] for item in earlier) / len(earlier)
        # The day the score fell and stayed down -- the date to line up against
        # what the user says they noticed.
        drop_day, drop_from, drop_to = "", None, None
        for older, newer in zip(series, series[1:]):
            if older["index"] - newer["index"] >= 2.0 and newer["index"] < base_avg:
                drop_day, drop_from, drop_to = newer["date"], older["index"], newer["index"]
        return {
            "available": True,
            "days": len(series),
            "series": series,
            "current": series[-1]["index"],
            "recent_avg": round(recent_avg, 2),
            "baseline_avg": round(base_avg, 2),
            # Needs a fortnight of history: a PC that has only been recorded for
            # three days has no baseline to have fallen away from.
            "degraded": bool(len(series) >= 14 and recent_avg + 1.5 < base_avg),
            "drop_date": drop_day,
            "drop_from": drop_from,
            "drop_to": drop_to,
            "drop_days_ago": _days_ago(drop_day) if drop_day else None,
        }
