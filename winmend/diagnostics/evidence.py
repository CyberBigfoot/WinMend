"""WinMend diagnostics: evidence."""

from __future__ import annotations

from winmend.diagnostics.catalog import COLLECTOR_ORIGINS, FINDING_SOURCES
from winmend.diagnostics.engine import CaseEngine


def finding_evidence(key):
    """Where a finding row was measured, for the UI's detail pane.

    Returns ``[(collector, label, origin), ...]``: the collector that produced
    the reading, the words the progress bar used while it ran, and the Windows
    facility it actually read. An empty list means the row is derived rather
    than collected, and the UI has to say so rather than invent a source.
    """
    labels = {}
    for group in (CaseEngine.FAST_COLLECTORS, CaseEngine.DEEP_COLLECTORS,
                  CaseEngine.HARDWARE_COLLECTORS):
        for name, label in group:
            labels[name] = label
    out = []
    for collector in FINDING_SOURCES.get(key, ()):
        out.append((collector, labels.get(collector, collector),
                    COLLECTOR_ORIGINS.get(collector, "")))
    return out
