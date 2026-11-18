"""WinMend diagnostics: collectors: boot."""

from __future__ import annotations

import re
try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


class ProbeBootMixin:
    """DeepProbe methods grouped by responsibility."""

    # -- boot, power, and sleep --------------------------------------------

    def boot_config(self):
        """The boot loader's own settings -- including the two that strand a PC.

        A ``safeboot`` value left behind by msconfig is why a PC boots to Safe
        Mode over and over with no way out the user can find, and it is a
        one-line fix. ``testsigning`` and ``nointegritychecks`` mean unsigned
        drivers are being loaded, which is either a developer's deliberate
        choice or something that arranged it without asking.
        """
        # ACTIVE rather than {current}: bcdedit rejects the brace form outright
        # on Windows 11 ("the specified entry type is invalid") before it ever
        # looks at the store, while the type name parses and means the same
        # thing -- the entry this PC actually booted from.
        rc, out, err = self._run(["bcdedit", "/enum", "ACTIVE"], timeout=15)
        if rc != 0 or not out.strip():
            # Reading the BCD store needs elevation. WinMend self-elevates in
            # production; unelevated this is unknown, which is not healthy.
            return {"available": False, "reason": (
                err or out or "the boot configuration needs administrator rights"
            ).strip()[:160]}
        # ACTIVE returns the boot manager entry as well as the loader. Only the
        # loader carries the settings that matter here, and it is the one with
        # an osdevice, so the blocks are kept apart rather than merged.
        blocks = []
        current = {}
        for line in out.splitlines():
            if not line.strip() or set(line.strip()) == {"-"}:
                if current:
                    blocks.append(current)
                current = {}
                continue
            name, _, value = line.strip().partition(" ")
            if name and value.strip():
                current[name.strip().lower()] = value.strip()
        if current:
            blocks.append(current)
        settings = next((block for block in blocks if "osdevice" in block),
                        blocks[0] if blocks else {})
        safeboot = settings.get("safeboot", "")
        return {
            "available": True,
            "settings": settings,
            "safe_mode_forced": bool(safeboot),
            "safeboot": safeboot,
            "test_signing": settings.get("testsigning", "").lower() == "yes",
            "integrity_checks_off": settings.get("nointegritychecks", "").lower() == "yes",
            "recovery_enabled": settings.get("recoveryenabled", "yes").lower() != "no",
            "debug": settings.get("debug", "").lower() == "yes",
            "hypervisor": settings.get("hypervisorlaunchtype", ""),
        }

    def fast_startup(self):
        """Whether "Shut down" actually shuts this PC down.

        With fast startup on, a shutdown hibernates the kernel instead, so
        drivers and devices keep whatever state they were already in. It sits
        behind a whole family of complaints that share one tell: a *restart*
        fixes it and a *shutdown* does not.
        """
        if winreg is None:
            return {"available": False}
        enabled = hibernate = None
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            ) as key:
                for name, target in (("HiberbootEnabled", "enabled"),
                                     ("HibernateEnabled", "hibernate")):
                    try:
                        value = bool(int(winreg.QueryValueEx(key, name)[0]))
                    except (OSError, ValueError, TypeError):
                        value = None
                    if target == "enabled":
                        enabled = value
                    else:
                        hibernate = value
        except OSError:
            return {"available": False}
        if enabled is None:
            return {"available": False}
        return {"available": True, "enabled": enabled, "hibernate_enabled": hibernate}

    def wake_history(self):
        """What last woke this PC, and what is allowed to wake it again."""
        rc, out, _ = self._run(["powercfg", "/lastwake"], timeout=15)
        last = {"source": "", "kind": "", "detail": ""}
        if rc == 0 and out.strip():
            kind = re.search(r"Type:\s*(.+)", out)
            friendly = re.search(r"Friendly Name:\s*(.+)", out)
            owner = re.search(r"Owner:\s*(.+)", out)
            last = {
                "kind": (kind.group(1).strip() if kind else ""),
                "source": (friendly.group(1).strip() if friendly
                           else owner.group(1).strip() if owner else ""),
                "detail": out.strip()[:300],
            }
        timers_rc, timers_out, timers_err = self._run(["powercfg", "/waketimers"], timeout=15)
        readable = timers_rc == 0
        timers = []
        if readable:
            for line in timers_out.splitlines():
                line = line.strip()
                if line.lower().startswith("reason:"):
                    timers.append(line.split(":", 1)[1].strip()[:120])
                elif line.startswith("[") and "]" in line:
                    timers.append(line[:120])
        return {
            "available": bool(rc == 0 or readable),
            "last_wake": last,
            # Unelevated, powercfg refuses to list wake timers at all. Absent
            # evidence is not "no timers are set", and the difference decides
            # whether a rule may blame one for a PC that wakes up at night.
            "timers_readable": readable,
            "timers": timers[:8],
            "armed": len(timers),
            "reason": (timers_err or "").strip()[:120],
        }
