"""WinMend diagnostics: context."""

from __future__ import annotations

from winmend.diagnostics.interview import Interview
from winmend.diagnostics.models import _profile_names
from winmend.diagnostics.reference import AUDIT_PROFILE, HARDWARE_PROFILE
from winmend.diagnostics.timeline import ChangeTimeline


class Context:
    """Everything the rules are allowed to look at."""

    def __init__(self, problem, profile, answers, raw, evidence, history=None):
        self.problem = problem or ""
        self.query = self.problem.lower()
        from winmend.diagnostics.symptoms import interpret
        self.interpretation = interpret(self.problem)
        self.profile = profile or "general"
        self.audit = self.profile in (AUDIT_PROFILE, HARDWARE_PROFILE)
        # Rules that can only speak when the deep collectors have actually run
        # check this rather than sniffing for their evidence twice.
        self.deep = self.profile == HARDWARE_PROFILE
        # A full check is not "about" any one area, so every area's rules get a
        # look at the evidence.
        self.parts = (set(_profile_names()) if self.audit
                      else {p for p in str(self.profile).split("+") if p})
        self.answers = answers or {}
        self.raw = raw or {}
        self.evidence = {item["key"]: item for item in (evidence or [])}
        self.history = history or []
        self._timeline = None

    @property
    def timeline(self):
        """Every dated change and symptom, merged. Built once, on first use."""
        if self._timeline is None:
            self._timeline = ChangeTimeline(self.raw)
        return self._timeline

    # -- accessors --------------------------------------------------------

    def get(self, name, default=None):
        """A raw collector result, e.g. ctx.get('bugchecks')."""
        value = self.raw.get(name)
        return default if value is None else value

    def ok(self, name):
        """True when a collector actually produced usable data."""
        value = self.raw.get(name)
        return bool(isinstance(value, dict) and value.get("available"))

    def status(self, key):
        item = self.evidence.get(key)
        return item.get("status") if item else None

    def answer(self, question_id):
        return self.answers.get(question_id)

    def onset_days(self):
        return Interview.onset_days(self.answers)

    def mentions(self, *words):
        # Prevent explicitly denied performance/crash symptoms from steering
        # rules; the full text remains available to the decision trace.
        import re
        clauses = re.split(r"[,;.!?]|\b(?:but|however)\b", self.interpretation.normalized)
        return any(word in clause for clause in clauses for word in words
                   if not re.search(r"(?:not|isn't|never|no)\s+(?:\w+\s+){0,2}" + re.escape(word), clause))

    def near_onset(self, days_ago, slack=2.0):
        """Did something that happened ``days_ago`` plausibly precede the symptom?

        With no stated onset this is unknowable, so it returns False rather than
        guessing -- a timing correlation the user never confirmed is not evidence.
        """
        if days_ago is None:
            return False
        window = self.onset_days()
        if window is None:
            return False
        return days_ago <= window + slack
