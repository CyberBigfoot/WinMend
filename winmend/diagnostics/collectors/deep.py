"""WinMend diagnostics: collectors: deep."""

from __future__ import annotations

from winmend.diagnostics.collectors.boot import ProbeBootMixin
from winmend.diagnostics.collectors.changes import ProbeChangesMixin
from winmend.diagnostics.collectors.desktop import ProbeDesktopMixin
from winmend.diagnostics.collectors.devices import ProbeDevicesMixin
from winmend.diagnostics.collectors.events import ProbeEventsMixin
from winmend.diagnostics.collectors.integrity import ProbeIntegrityMixin
from winmend.diagnostics.collectors.network import ProbeNetworkMixin
from winmend.diagnostics.collectors.performance import ProbePerformanceMixin
from winmend.diagnostics.collectors.security import ProbeSecurityMixin
from winmend.diagnostics.collectors.storage import ProbeStorageMixin
from winmend.diagnostics.collectors.updates import ProbeUpdatesMixin
from winmend.diagnostics.collectors.upkeep import ProbeUpkeepMixin
from winmend.diagnostics.collectors.windows import WindowsProbe, guard_event_query
from winmend.diagnostics.collectors.intelligence import ProbeIntelligenceMixin
from winmend.diagnostics.hardware.probe import HardwareProbe


class DeepProbe(
    ProbeIntelligenceMixin,
    ProbeChangesMixin,
    ProbeDevicesMixin,
    ProbeEventsMixin,
    ProbeIntegrityMixin,
    ProbeNetworkMixin,
    ProbeSecurityMixin,
    ProbeStorageMixin,
    ProbeUpkeepMixin,
    ProbePerformanceMixin,
    ProbeDesktopMixin,
    ProbeBootMixin,
    ProbeUpdatesMixin,
    HardwareProbe,
    WindowsProbe,
):
    """The evidence a technician gathers before touching anything.

    Every collector is individually bounded and returns ``{"available": False}``
    rather than raising, so one slow or admin-gated source never sinks the sweep.
    """

    def _ps(self, script, timeout=25):
        script = "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);" + script
        return self._run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
             "-NonInteractive", "-Command", script],
            timeout=timeout,
        )

    def _ps_rows(self, script, timeout=25, sep="|"):
        """Run a script that emits ``a|b|c`` lines; return them split."""
        rc, out, err = self._ps(script, timeout=timeout)
        rows = [line.strip().split(sep) for line in out.splitlines() if sep in line]
        return rc, rows, (err or "").strip()

    _READY = "__wmready__"

    def _ps_events(self, script, timeout=25):
        """Run an event-log query that ends by emitting a completion marker.

        Get-WinEvent exits non-zero when a filter simply matches nothing, so the
        process exit code cannot distinguish "the log is clean" from "the log
        could not be read". The marker can: if it arrives, the query ran.
        """
        # A completion marker after a suppressed error does not prove a log was
        # readable. Only NoMatchingEventsFound means a successfully empty query.
        full = guard_event_query(script, self._READY)
        rc, rows, err = self._ps_rows(full, timeout=timeout)
        ready = any(row and row[0] == self._READY for row in rows)
        data = [row for row in rows if not (row and row[0] == self._READY)]
        return ready, data, err
