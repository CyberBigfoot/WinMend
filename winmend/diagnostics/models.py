"""WinMend diagnostics: models."""

from __future__ import annotations

from winmend.diagnostics.reference import SEVERITY_RANK


class Hypothesis:
    """One explanation for the symptom, with the evidence it rests on."""

    __slots__ = ("id", "title", "explanation", "confidence", "severity",
                 "evidence_keys", "actions", "advice", "suppress", "suppress_reason",
                 "evidence_strength", "supporting", "contradictory", "missing", "rank_score", "decision")

    def __init__(self, id, title, explanation, confidence=50, severity="medium",
                 evidence_keys=(), actions=(), advice="", suppress=(), suppress_reason=""):
        self.id = id
        self.title = title
        self.explanation = explanation
        self.confidence = max(1, min(99, int(confidence)))
        self.severity = severity if severity in SEVERITY_RANK else "medium"
        self.evidence_keys = list(evidence_keys)
        self.actions = list(actions)
        self.advice = advice
        self.suppress = list(suppress)
        self.suppress_reason = suppress_reason
        self.evidence_strength = "limited"
        self.supporting = []
        self.contradictory = []
        self.missing = []
        self.rank_score = 0
        self.decision = "suspected"

    def as_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence_keys": list(self.evidence_keys),
            "actions": [dict(a) for a in self.actions],
            "advice": self.advice,
            "suppress": list(self.suppress),
            "suppress_reason": self.suppress_reason,
            "evidence_strength": self.evidence_strength,
            "confidence_method": "Uncalibrated evidence ranking; not a probability",
            "supporting": list(self.supporting),
            "contradictory": list(self.contradictory),
            "missing": list(self.missing),
            "rank_score": self.rank_score,
            "decision": self.decision,
        }


def _profile_names():
    """Every symptom area the classic engine knows about."""
    from winmend.diagnostics.profiles import DiagnosticEngine
    return tuple(DiagnosticEngine.PROFILE_TERMS)


def task_action(task_id, reason=""):
    return {"kind": "task", "task": task_id, "reason": reason}


def repair_action(action_id, params=None, title="", reason=""):
    return {"kind": "action", "action": action_id, "params": dict(params or {}),
            "title": title, "reason": reason}


def _default_task_lookup(task_id):
    """Metadata for a WinMend task, used when the caller supplies no lookup.

    The real lookup is injected by the desktop shell from ``WM_TASKS``; this
    fallback keeps the engine importable and testable on its own.
    """
    from winmend.diagnostics.profiles import DiagnosticEngine
    if task_id not in DiagnosticEngine.TASK_REASONS:
        return None
    return {
        "title": task_id.replace("_", " ").title(),
        "duration": DiagnosticEngine.TASK_DURATIONS.get(task_id, "varies"),
        "risk": "caution",
        "restore_point": False,
        "admin": True,
        "reboot": task_id == "restart_windows",
    }
