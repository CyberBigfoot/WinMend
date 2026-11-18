"""WinMend diagnostics: planning."""

from __future__ import annotations

from winmend.core.findings import SEVERITY
from winmend.diagnostics.catalog import FINDING_SOURCES, PROTECTION_FIRST
from winmend.diagnostics.reference import SEVERITY_RANK
from winmend.diagnostics.repairs.catalog import REPAIR_ACTIONS
import json
from winmend.diagnostics.eligibility import eligible, decorate_step


class CasePlanningMixin:
    """CaseEngine methods grouped by responsibility."""

    # -- planning ---------------------------------------------------------

    # How long each action tends to take, and how disruptive it is. Cheap and
    # reversible things go first so the user is not asked to sit through a
    # 45-minute repair before a 20-second one has been tried.
    COST = {
        "under 1 min": 1, "1 min": 2, "1-2 min": 3, "2-5 min": 5, "1-3 min": 4,
        "3-10 min": 8, "2-10 min": 8, "5-15 min": 12, "5-20 min": 14, "5-30 min": 18,
        "10-45 min": 30, "5-60 min": 35, "10-60 min": 40, "1-4 hours": 90,
    }

    @classmethod
    def _cost(cls, duration):
        return cls.COST.get(str(duration), 10)

    def _plan(self, hypotheses, task_lookup, findings=(), context=None, attempts=()):
        """Order the repairs, and record what was withheld and why."""
        severity_now = {f["key"]: SEVERITY.get(f["status"], 0) for f in (findings or [])}
        suppressed = {}
        for hypothesis in hypotheses:
            for target in hypothesis.suppress:
                suppressed.setdefault(target, (hypothesis.title, hypothesis.suppress_reason))

        steps = []
        seen = {}
        withheld = []
        for hypothesis in hypotheses:
            for spec in hypothesis.actions:
                if spec["kind"] == "task":
                    key = ("task", spec["task"])
                    identifier = spec["task"]
                    meta = task_lookup(identifier)
                    if meta is None:
                        continue
                    title = meta["title"]
                    duration = meta["duration"]
                    risk = meta["risk"]
                    restore_point = meta["restore_point"]
                    admin = meta["admin"]
                    reboot = meta.get("reboot", False)
                    verify_keys = ()
                    confirm = risk == "destructive"
                    reversible = False  # checkpoint coverage is distinct from an exact undo
                else:
                    action = REPAIR_ACTIONS.get(spec["action"])
                    if action is None:
                        continue
                    identifier = spec["action"]
                    key = ("action", identifier, json.dumps(spec.get("params", {}), sort_keys=True))
                    title = spec.get("title") or action.title
                    duration = action.duration
                    risk = action.risk
                    restore_point = action.restore_point
                    admin = action.admin
                    reboot = action.reboot
                    verify_keys = action.verify_keys
                    confirm = action.confirm
                    reversible = action.reversible

                if identifier in suppressed:
                    continue
                proposal = {"id": identifier, "kind": spec["kind"], "params": spec.get("params", {})}
                allowed, prerequisite = eligible(proposal, findings, context, attempts)
                if not allowed:
                    withheld.append({"id": identifier, "title": title,
                                     "because": hypothesis.title, "reason": prerequisite})
                    continue
                if key in seen:
                    # Two hypotheses want the same repair. Running it twice
                    # helps nobody, but silently crediting it to whichever rule
                    # spoke first leaves the other on screen as a diagnosis with
                    # nothing underneath it. The step carries both instead.
                    owner = seen[key]
                    if hypothesis.id and hypothesis.id not in owner["also_for"]:
                        owner["also_for"].append(hypothesis.id)
                        owner["also_titles"].append(hypothesis.title)
                        for evidence_key in hypothesis.evidence_keys:
                            if evidence_key not in owner["verify_keys"]:
                                owner["verify_keys"].append(evidence_key)
                    continue
                step = {
                    "kind": spec["kind"],
                    "id": identifier,
                    "task": spec.get("task", ""),
                    "action": spec.get("action", ""),
                    "params": dict(spec.get("params", {})),
                    "title": title,
                    "reason": spec.get("reason") or hypothesis.explanation,
                    "duration": duration,
                    "risk": risk,
                    "restore_point": restore_point,
                    "reversible": reversible,
                    "admin": admin,
                    "reboot": reboot,
                    "confirm": confirm,
                    "hypothesis": hypothesis.id,
                    "hypothesis_title": hypothesis.title,
                    "severity": hypothesis.severity,
                    "confidence": hypothesis.confidence,
                    "verify_keys": list(verify_keys) or list(hypothesis.evidence_keys),
                    # Other hypotheses this same step also answers.
                    "also_for": [],
                    "also_titles": [],
                }
                seen[key] = step
                step["precondition_reason"] = prerequisite
                steps.append(decorate_step(step, findings))

        # Every suppression is reported, whether or not another rule happened to
        # propose that repair. Naming the obvious fix and explaining why it is
        # being withheld is the point -- a user who is not told that chkdsk was
        # deliberately skipped will simply go and run it themselves.
        for identifier, (blamed, reason) in suppressed.items():
            action = REPAIR_ACTIONS.get(identifier)
            if action is not None:
                title = action.title
            else:
                meta = task_lookup(identifier)
                title = meta["title"] if meta else identifier.replace("_", " ").title()
            withheld.append({
                "id": identifier, "title": title, "because": blamed, "reason": reason,
            })
        withheld.sort(key=lambda item: item["title"])

        # Within a severity band, run the cheap reversible things first: the
        # point of an adaptive plan is that the quick fix gets its chance before
        # the user is committed to a long one.
        steps.sort(key=lambda s: (
            0 if s.get("read_only") else 1,
            {"safe": 0, "caution": 1, "destructive": 2}.get(s["risk"], 1),
            0 if s["reversible"] else 1,
            self._cost(s["duration"]),
            -s["confidence"],
        ))
        # A restart is only ever useful last. Turning System Protection back on
        # is the mirror image: a checkpoint taken after the repairs protects
        # nothing, so it outranks even a critical finding.
        steps.sort(key=lambda s: 1 if s["id"] == "restart_windows" else 0)
        steps.sort(key=lambda s: 0 if s["id"] in PROTECTION_FIRST else 1)
        for index, step in enumerate(steps):
            step["index"] = index
            # Stopping early is only honest when this step targets a check that
            # is measurably wrong right now. Without that, "it cleared" would
            # mean nothing more than "the check was never failing".
            step["stop_if_clear"] = any(
                severity_now.get(key, 0) > 0
                for key in step["verify_keys"] if key in FINDING_SOURCES)
        return steps, withheld
