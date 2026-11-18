"""WinMend diagnostics: collectors: security."""

from __future__ import annotations

from winmend.diagnostics.helpers import _days_ago, _scan_age, _tri_state
from winmend.diagnostics.reference import UNRESOLVED_THREAT_STATUS
import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeSecurityMixin:
    """DeepProbe methods grouped by responsibility."""

    def platform_security(self):
        """Secure Boot, TPM, BitLocker, and activation in one pass."""
        # Every value here stays tri-state. Without elevation these queries fail,
        # and reporting a failed read as "TPM: absent" or "Secure Boot: off"
        # would invent a security problem that does not exist.
        #
        # Secure Boot comes from the registry rather than Confirm-SecureBootUEFI:
        # the cmdlet needs elevation and answers "unknown" without it, while the
        # registry value is readable by anyone and answers instantly.
        secure_boot = "unknown"
        if winreg is not None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                ) as key:
                    secure_boot = "true" if winreg.QueryValueEx(
                        key, "UEFISecureBootEnabled")[0] else "false"
            except OSError:
                # No such key means a legacy BIOS/MBR machine, not a failed read.
                secure_boot = "unsupported"
        # The unfiltered SoftwareLicensingProduct enumeration takes ~11s because
        # it walks every licensable component; restricting it to the Windows
        # ApplicationID returns the same answer in well under a second.
        script = (
            "$tp='unknown'; try { $t=Get-CimInstance -Namespace root\\cimv2\\security\\microsofttpm "
            "-ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1; "
            "$tp=[string]$t.IsEnabled_InitialValue+','+[string]$t.IsActivated_InitialValue } catch {}; "
            "Write-Output ('tpm|'+$tp);"
            "$bl='unknown'; try { $v=Get-BitLockerVolume -MountPoint $env:SystemDrive "
            "-ErrorAction Stop; $bl=[string]$v.ProtectionStatus } catch {}; "
            "Write-Output ('bitlocker|'+$bl);"
            "$act='unknown'; try { $q=\"SELECT LicenseStatus FROM SoftwareLicensingProduct \" + "
            "\"WHERE PartialProductKey IS NOT NULL AND \" + "
            "\"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'\"; "
            "$p=Get-CimInstance -Query $q -ErrorAction Stop | Select-Object -First 1; "
            "$act=[string]$p.LicenseStatus } catch {}; "
            "Write-Output ('activation|'+$act)"
        )
        rc, rows, _ = self._ps_rows(script, timeout=45)
        data = {row[0]: row[1].strip() for row in rows if len(row) > 1}
        if not data and secure_boot == "unknown":
            return {"available": False}

        def _tri(text):
            lowered = str(text).strip().lower()
            if lowered in ("true", "1"):
                return True
            if lowered in ("false", "0"):
                return False
            return None

        tpm_present, _, tpm_ready = data.get("tpm", "").partition(",")
        activation = data.get("activation", "")
        return {
            "available": True,
            "secure_boot": secure_boot,
            "tpm_present": _tri(tpm_present),
            "tpm_ready": _tri(tpm_ready),
            "bitlocker": data.get("bitlocker", "unknown"),
            "activated": (activation == "1") if activation and activation != "unknown" else None,
        }

    def defender_exclusions(self):
        """Exclusions are legitimate -- and are also what malware adds first."""
        script = (
            "$p=Get-MpPreference -ErrorAction Stop;"
            "foreach($x in @($p.ExclusionPath)){ if($x){Write-Output ('path|'+$x)} };"
            "foreach($x in @($p.ExclusionProcess)){ if($x){Write-Output ('proc|'+$x)} };"
            "Write-Output ('tamper|'+[string]$p.DisableTamperProtection)"
        )
        rc, rows, _ = self._ps_rows(script, timeout=25)
        if rc != 0 and not rows:
            return {"available": False}
        paths = [row[1].strip() for row in rows if row[0] == "path" and len(row) > 1]
        procs = [row[1].strip() for row in rows if row[0] == "proc" and len(row) > 1]
        # Without elevation Get-MpPreference returns the refusal as the value
        # itself, which would otherwise be reported as a suspicious exclusion.
        if any(p.lower().startswith("n/a:") for p in paths + procs):
            return {"available": False, "reason": "needs administrator"}
        broad = [p for p in paths
                 if re.fullmatch(r"[A-Za-z]:\\?", p.strip())
                 or p.strip().lower() in (r"c:\users", r"c:\windows", r"c:\program files")]
        return {"available": True, "paths": paths, "processes": procs, "overly_broad": broad}

    # -- security posture --------------------------------------------------

    def uac_state(self):
        """User Account Control -- off means every program runs as administrator."""
        if winreg is None:
            return {"available": False}
        values = {}
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            ) as key:
                for name in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"):
                    try:
                        values[name] = int(winreg.QueryValueEx(key, name)[0])
                    except (OSError, ValueError, TypeError):
                        values[name] = None
        except OSError:
            return {"available": False}
        if values.get("EnableLUA") is None:
            return {"available": False}
        enabled = bool(values["EnableLUA"])
        consent = values.get("ConsentPromptBehaviorAdmin")
        return {
            "available": True,
            "enabled": enabled,
            "consent": consent,
            # 0 is "elevate silently": UAC is nominally on but never asks, which
            # is the setting malware and "make it stop nagging" guides both want.
            "never_notifies": enabled and consent == 0,
            "secure_desktop": bool(values.get("PromptOnSecureDesktop")),
        }

    def defender_threats(self, days=90):
        """What Defender has actually found, and whether it finished dealing with it.

        A threat Defender detected but could not remove is the single most
        important thing a full check can report, and it appears nowhere in the
        real-time-protection status the engine looked at before.
        """
        script = (
            "$s=$null; try { $s=Get-MpComputerStatus -ErrorAction Stop } catch {};"
            "Write-Output ('S|'+[string]$s.QuickScanAge+'|'+[string]$s.FullScanAge"
            "+'|'+[string]$s.IsTamperProtected);"
            "$t=@(); try { $t=@(Get-MpThreat -ErrorAction Stop) } catch {};"
            "Write-Output ('N|'+[string]$t.Count);"
            "foreach($x in ($t | Sort-Object LastThreatStatusChangeTime -Descending | "
            "Select-Object -First 15)) { Write-Output ('T|'+($x.ThreatName -replace '\\|',' ')"
            "+'|'+[string]$x.SeverityID+'|'+[string]$x.ThreatStatusID+'|'"
            "+[string]$x.LastThreatStatusChangeTime) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=40)
        threats = []
        quick_age = full_age = None
        tamper = None
        seen_count = None
        for row in rows:
            if row[0] == "S" and len(row) > 3:
                quick_age, full_age = _scan_age(row[1]), _scan_age(row[2])
                tamper = _tri_state(row[3])
            elif row[0] == "N" and len(row) > 1:
                try:
                    seen_count = int(row[1].strip())
                except ValueError:
                    seen_count = None
            elif row[0] == "T" and len(row) > 4:
                try:
                    status = int(row[3].strip())
                except (ValueError, TypeError):
                    status = 0
                age = _days_ago(row[4].strip())
                threats.append({
                    "name": row[1].strip(),
                    "severity": row[2].strip(),
                    "status": status,
                    "unresolved": status in UNRESOLVED_THREAT_STATUS,
                    "state": UNRESOLVED_THREAT_STATUS.get(status, "handled"),
                    "days_ago": round(age, 1) if age is not None else None,
                })
        if seen_count is None and not threats and rc != 0:
            return {"available": False, "reason": (err or "")[:200]}
        recent = [t for t in threats
                  if t["days_ago"] is None or t["days_ago"] <= max(1, int(days))]
        return {
            "available": True,
            "history": seen_count if seen_count is not None else len(threats),
            "threats": threats,
            "unresolved": [t for t in recent if t["unresolved"]],
            "quick_scan_age": quick_age,
            "full_scan_age": full_age,
            "tamper_protection": tamper,
        }

    def firewall_profiles(self):
        """Per-profile firewall state, so an off profile can be named."""
        script = (
            "Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { Write-Output "
            "('F|'+$_.Name+'|'+[string]$_.Enabled+'|'+[string]$_.DefaultInboundAction) }"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        profiles = []
        for row in rows:
            if row[0] != "F" or len(row) < 3:
                continue
            profiles.append({
                "name": row[1].strip(),
                "enabled": _tri_state(row[2]),
                "inbound": row[3].strip() if len(row) > 3 else "",
            })
        if not profiles:
            return {"available": False, "reason": (err or "")[:200]}
        return {
            "available": True,
            "profiles": profiles,
            "disabled": [p["name"] for p in profiles if p["enabled"] is False],
            # "Allow" as the default inbound action leaves the profile switched
            # on while letting everything in, which looks healthy and is not.
            "allow_inbound": [p["name"] for p in profiles
                              if p["inbound"].lower() == "allow"],
        }
