"""WinMend diagnostics: timeline."""

from __future__ import annotations

from winmend.diagnostics.helpers import _days_ago


class ChangeTimeline:
    """Everything dated that has happened to this PC, merged into one list.

    The engine already knew what changed recently. What it could not do was say
    whether a change was *related* to the trouble, so "recent" had to stand in
    for "responsible" -- and that is how an innocent VirtualBox package got
    blamed for general slowness once.

    A timeline fixes that by giving the reasoning something to correlate
    against. Changes go on one axis and *symptoms* go on the same axis: the
    first stop code, the first hardware error, the day Windows' own stability
    score fell. A change is only a suspect when it lands before symptoms that
    were not happening beforehand, which is a claim the evidence can support or
    refuse on its own -- with or without the user remembering a date.
    """

    # A change is only worth suspecting if it happened shortly before the
    # trouble did. Two days of slack covers the gap between something
    # installing and the user noticing it.
    WINDOW_DAYS = 4.0

    def __init__(self, raw=None):
        self.raw = raw or {}
        self.changes = []
        self.symptoms = []
        self._build()

    # -- construction ------------------------------------------------------

    def _add(self, bucket, when, kind, title, detail="", data=None, days_ago=None):
        """Place one dated event.

        Some collectors hand back a date and some have already worked out an
        age (the driver store is read by file time, not by a timestamp string),
        so both are accepted rather than making every caller reformat.
        """
        age = _days_ago(when) if days_ago is None else days_ago
        if age is None or age < -1:
            return
        bucket.append({
            "when": str(when or ""),
            "days_ago": round(max(0.0, float(age)), 2),
            "kind": kind,
            "title": title,
            "detail": detail,
            "data": dict(data or {}),
        })

    def _build(self):
        get = self.raw.get

        for update in ((get("installed_updates") or {}).get("updates") or []):
            self._add(self.changes, update.get("installed"), "update",
                      f"{update.get('kb') or 'An update'} installed",
                      update.get("kind", ""), update)

        for driver in ((get("third_party_drivers") or {}).get("recent") or []):
            name = driver.get("provider") or driver.get("original") or "A"
            self._add(self.changes, "", "driver", f"{name} driver installed",
                      " ".join(part for part in (driver.get("class", ""),
                                                 driver.get("original", "")) if part),
                      driver, days_ago=driver.get("days_ago"))

        for program in ((get("installed_programs") or {}).get("programs") or []):
            self._add(self.changes, program.get("installed"), "program",
                      f"{program.get('name') or 'A program'} installed",
                      program.get("publisher", ""), program,
                      days_ago=program.get("days_ago"))

        for point in ((get("restore_points") or {}).get("points") or []):
            self._add(self.changes, point.get("created"), "restore",
                      "Restore point created", point.get("description", ""), point,
                      days_ago=point.get("days_ago"))

        # -- the other axis: when things started going wrong ----------------

        for crash in ((get("bugchecks") or {}).get("crashes") or []):
            self._add(self.symptoms, crash.get("time"), "bugcheck",
                      f"Stop code {crash.get('code', '')} {crash.get('name', '')}".strip(),
                      crash.get("cause", ""), crash)

        for event in ((get("whea_errors") or {}).get("events") or []):
            self._add(self.symptoms, event.get("time"), "hardware_error",
                      "Hardware error recorded", event.get("meaning", ""), event)

        for reset in ((get("gpu_resets") or {}).get("events") or []):
            self._add(self.symptoms, reset.get("time"), "gpu_reset",
                      "Display driver reset", reset.get("driver", ""), reset)

        for failure in ((get("update_failures") or {}).get("failures") or []):
            self._add(self.symptoms, failure.get("time"), "update_failure",
                      f"Update failed {failure.get('code', '')}".strip(),
                      failure.get("meaning", ""), failure)

        stability = get("reliability_history") or {}
        if stability.get("drop_date"):
            self._add(self.symptoms, stability["drop_date"], "stability_drop",
                      "Windows' stability score fell",
                      f"from {stability.get('drop_from')} to {stability.get('drop_to')} out of 10",
                      stability)

        self.changes.sort(key=lambda item: item["days_ago"])
        self.symptoms.sort(key=lambda item: item["days_ago"])

    # -- reading it --------------------------------------------------------

    @property
    def events(self):
        """Changes and symptoms interleaved, newest first."""
        merged = ([dict(item, axis="change") for item in self.changes]
                  + [dict(item, axis="symptom") for item in self.symptoms])
        merged.sort(key=lambda item: item["days_ago"])
        return merged

    def onset(self, stated_days=None):
        """The best available estimate of when the trouble began.

        Three sources, in order of how much they are worth. What the user says
        is authoritative when they say it, because they were there. A measured
        stability drop is next: it is evidence rather than recall. A first
        symptom after a clean run is last, and only counts when there is enough
        history behind it to call the earlier period quiet.
        """
        if stated_days is not None:
            return {"days_ago": float(stated_days), "source": "stated",
                    "detail": "when you said it started"}

        stability = self.raw.get("reliability_history") or {}
        if stability.get("drop_days_ago") is not None:
            return {
                "days_ago": float(stability["drop_days_ago"]),
                "source": "stability",
                "detail": (f"Windows' own stability score fell on {stability.get('drop_date')}"),
            }

        # The oldest symptom in a run of them: the trouble started when the
        # first one landed, not when the most recent one did.
        if self.symptoms:
            oldest = self.symptoms[-1]
            return {"days_ago": oldest["days_ago"], "source": "first_symptom",
                    "detail": f"the first one recorded was: {oldest['title']}"}
        return None

    # A restore point is a marker that something was *about* to change, not a
    # change in itself -- Windows takes one before an update or a driver
    # install. Counting it as a suspect would inflate the field on exactly the
    # machines that keep good checkpoints, and there is nothing to uninstall.
    NOT_A_CAUSE = ("restore",)

    def suspects(self, stated_days=None, window=None, kinds=None):
        """Changes close enough in time to the onset to be worth suspecting.

        Returns them best-first. A change *after* the trouble began cannot have
        caused it, so the window is one-sided on purpose.
        """
        onset = self.onset(stated_days)
        if onset is None:
            return []
        span = self.WINDOW_DAYS if window is None else float(window)
        limit = float(onset["days_ago"])
        found = []
        for change in self.changes:
            if kinds and change["kind"] not in kinds:
                continue
            if not kinds and change["kind"] in self.NOT_A_CAUSE:
                continue
            # Slack on both sides: "it started Tuesday" is a memory, not a
            # timestamp, and an update that installs at 3am is dated the day
            # before the morning it is noticed.
            if change["days_ago"] < limit - 1.0:
                continue
            if change["days_ago"] > limit + span:
                continue
            found.append(dict(change, gap_days=round(change["days_ago"] - limit, 2),
                              onset_source=onset["source"]))
        found.sort(key=lambda item: abs(item["gap_days"]))
        return found

    def symptom_free_before(self, days_ago, kinds=None, quiet=7.0):
        """Was this PC quiet in the stretch before ``days_ago``?

        This is what separates "it started after the update" from "it has always
        done this". Without it, an update that happened to land in the middle of
        a months-long crash pattern still looks like the cause.
        """
        earlier = [s for s in self.symptoms
                   if s["days_ago"] > days_ago + 0.5 and (not kinds or s["kind"] in kinds)]
        if earlier:
            return False
        # Nothing earlier is only meaningful if we can see far enough back to
        # know that. With no history at all, this cannot be answered.
        return bool(self.symptoms or (self.raw.get("reliability_history") or {}).get("days", 0)
                    >= days_ago + quiet)

    def as_dict(self, limit=40, stated_days=None):
        # The stated onset has to be passed through, or the view reports a
        # measured start date while the rules reasoned from what the user
        # actually said -- two different answers to the same question, on the
        # same screen.
        onset = self.onset(stated_days)
        events = self.events
        return {
            "changes": len(self.changes),
            "symptoms": len(self.symptoms),
            "onset": onset,
            "events": events[:limit],
            # A PC that has installed sixty things this month produces a table
            # nobody reads. The count above stays honest about the total, so
            # the view has to be honest about how much of it is on screen.
            "shown": min(limit, len(events)),
            "total": len(events),
        }
