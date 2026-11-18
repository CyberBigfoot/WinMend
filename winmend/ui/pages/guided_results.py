"""WinMend ui: pages: guided results."""

from __future__ import annotations

from PySide6.QtCore import Qt as QtC
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QLabel, QTreeWidgetItem
from winmend.diagnostics.reference import (
    AUDIT_PROFILE as WM_AUDIT_PROFILE,
    HARDWARE_PROFILE as WM_HARDWARE_PROFILE,
)
from winmend.ui.widgets.hypothesis import WMHypothesisCard
import html as _html


class GuidedResultsMixin:
    """WMGuidedFixPage methods grouped by responsibility."""

    # ---- stage 3: present ------------------------------------------------

    def _clear_assessment(self, message):
        while self.assessment_box.count():
            item = self.assessment_box.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.assessment_empty = QLabel(message)
        self.assessment_empty.setWordWrap(True)
        self.assessment_empty.setStyleSheet(
            f"color:{self.T['text_3']};font-size:11.5px;background:transparent;")
        self.assessment_box.addWidget(self.assessment_empty)
        self.assessment_box.addStretch()

    def _render_findings(self, findings=None):
        """Paint the measurements table, honouring the attention-only filter.

        Called with rows to adopt them, and with nothing when only the filter
        changed -- so toggling it never needs the sweep to run again.
        """
        if findings is not None:
            self._findings_rows = list(findings)
        rows = getattr(self, "_findings_rows", [])
        attention = [f for f in rows if f.get("status") not in ("good", "info")]
        only_attention = self.findings_filter.isChecked()
        shown = attention if only_attention else rows

        # Toggling the filter must not throw away what the user was reading.
        selected = self.findings.currentItem()
        keep = (selected.data(0, QtC.UserRole) or {}).get("key") if selected else None

        self.findings.clear()
        colours = {"good": self.T['ok'], "warn": self.T['warn'],
                   "bad": self.T['danger'], "info": self.T['text_3']}
        words = {"good": "Healthy", "warn": "Attention", "bad": "Problem", "info": "Information"}
        words.update(inconclusive="Inconclusive", not_tested="Not tested", not_applicable="Not applicable",
                     unsupported="Unsupported", permission_denied="Permission denied",
                     collection_failed="Collection failed", cancelled="Cancelled")
        restore = None
        for finding in shown:
            state = finding.get("status", "info")
            item = QTreeWidgetItem([
                finding.get("label", "Check"),
                f"{words.get(state, state)} - {finding.get('value', '')}",
                finding.get("detail", ""),
            ])
            item.setData(0, QtC.UserRole, finding)
            item.setForeground(1, QColor(colours.get(state, self.T['text_3'])))
            for column in range(3):
                item.setToolTip(column, item.text(column))
            self.findings.addTopLevelItem(item)
            if keep and finding.get("key") == keep:
                restore = item
        if restore is not None:
            self.findings.setCurrentItem(restore)
        elif not shown:
            self._clear_finding_detail()

        if not rows:
            self.findings_count.setText("")
        elif only_attention and not attention:
            self.findings_count.setText(
                f"No warning or incomplete check in these {len(rows)} readings. Untick to see them.")
        else:
            self.findings_count.setText(
                f"Showing {len(shown)} of {len(rows)} readings; "
                f"{len(attention)} need attention. Click a row for the evidence.")

    # ---- drilling into one measurement -----------------------------------

    def _clear_finding_detail(self):
        self.finding_detail.setHtml(
            f"<p style='color:{self.T['text_3']}'>Select a reading above to see what was "
            f"measured, where on this PC it was read from, and what follows from it.</p>")

    @staticmethod
    def _readable(value):
        """One measured value, as a person would write it."""
        if value is None:
            return "not available"
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, float):
            return f"{value:.2f}".rstrip("0").rstrip(".")
        return str(value)

    @classmethod
    def _evidence_html(cls, value, depth=0):
        """The collector's own payload, rendered so it can be read.

        Deliberately generic: every collector shapes its result differently and
        there are over a hundred of them, so this shows what is actually there
        rather than a curated retelling that would drift out of date.
        """
        esc = _html.escape
        if isinstance(value, dict):
            rows = [(k, v) for k, v in value.items()
                    if v not in (None, "", [], {}) and k not in ("available",)]
            if not rows:
                return ""
            if depth >= 2:
                return esc(", ".join(f"{k.replace('_', ' ')}: {cls._readable(v)}"
                                     for k, v in rows[:6]))
            parts = []
            for key, item in rows[:24]:
                rendered = cls._evidence_html(item, depth + 1)
                if not rendered:
                    continue
                parts.append(f"<li><b>{esc(str(key).replace('_', ' '))}:</b> {rendered}</li>")
            return f"<ul>{''.join(parts)}</ul>" if parts else ""
        if isinstance(value, (list, tuple)):
            items = list(value)
            if not items:
                return ""
            if all(not isinstance(i, (dict, list, tuple)) for i in items):
                head = ", ".join(cls._readable(i) for i in items[:12])
                extra = f" (+{len(items) - 12} more)" if len(items) > 12 else ""
                return esc(head + extra)
            parts = []
            for item in items[:8]:
                rendered = cls._evidence_html(item, depth + 1)
                if rendered:
                    parts.append(f"<li>{rendered}</li>")
            if len(items) > 8:
                parts.append(f"<li>+{len(items) - 8} more</li>")
            return f"<ul>{''.join(parts)}</ul>" if parts else ""
        return esc(cls._readable(value))

    def _show_finding(self, item, _previous=None):
        """Everything behind one row: the reading, its source, and what cites it."""
        if item is None:
            self._clear_finding_detail()
            return
        finding = item.data(0, QtC.UserRole)
        if not isinstance(finding, dict):
            self._clear_finding_detail()
            return
        esc = _html.escape
        state = finding.get("status", "info")
        colour = {"good": self.T['ok'], "warn": self.T['warn'],
                  "bad": self.T['danger']}.get(state, self.T['text_3'])
        word = {"good": "Healthy", "warn": "Needs attention", "bad": "Problem",
                "info": "Information"}.get(state, state)
        parts = [f"<h3 style='margin:0'>{esc(finding.get('label', 'Check'))}</h3>",
                 f"<p><b style='color:{colour}'>{esc(word)}</b> &mdash; "
                 f"{esc(finding.get('value', ''))}</p>"]
        if finding.get("detail"):
            parts.append(f"<h4>What this means</h4><p>{esc(finding['detail'])}</p>")
        parts.append(f"<p>Collected: {esc(finding.get('collected_at', 'unknown'))}; "
                     f"scope: {'historical' if finding.get('historical') else 'current'}; "
                     f"state: {esc(finding.get('diagnostic_state', state))}</p>")

        try:
            from winmend.diagnostics.evidence import finding_evidence
            sources = finding_evidence(finding.get("key", ""))
        except Exception:
            sources = []
        if sources:
            lines = "".join(
                f"<li><b>{esc(label)}</b>"
                + (f"<br>{esc(origin)}" if origin else "")
                + f"<br><span style='color:{self.T['text_3']}'>collector: {esc(name)}</span></li>"
                for name, label, origin in sources)
            parts.append(f"<h4>Where this was read from</h4><ul>{lines}</ul>")
        else:
            parts.append(
                f"<h4>Where this was read from</h4><p style='color:{self.T['text_3']}'>"
                f"This row is derived from other readings rather than measured directly.</p>")

        evidence = self._evidence_html(finding.get("data") or {})
        if evidence:
            parts.append(f"<h4>What the check actually saw</h4>{evidence}")

        titles = [step.get("title", step["id"]) for step in (self.case or {}).get("plan", [])
                  if finding.get("key") in step.get("required_evidence", []) or finding.get("key") in step.get("verify_keys", [])]
        if titles:
            parts.append("<h4>Repairs that target this</h4><ul>"
                         + "".join(f"<li>{esc(t)}</li>" for t in titles) + "</ul>")

        key = finding.get("key")
        citing = [h for h in ((self.case or {}).get("hypotheses") or [])
                  if key in (h.get("evidence_keys") or [])]
        if citing:
            parts.append("<h4>Causes this reading supports</h4><ul>" + "".join(
                f"<li>{esc(h.get('title', ''))} "
                f"<span style='color:{self.T['text_3']}'>"
                f"({esc(h.get('evidence_strength', 'uncalibrated'))} evidence)</span></li>" for h in citing) + "</ul>")
        elif state in ("warn", "bad"):
            parts.append(
                f"<p style='color:{self.T['text_3']}'>No ranked cause rests on this reading; "
                f"it is flagged on its own.</p>")

        self.finding_detail.setHtml("".join(parts))
        self._open_finding_detail()

    def _open_finding_detail(self):
        """Reopen the detail pane if it was dragged shut.

        Clicking a row has to show something. Without this, a user who closed
        the pane once would click row after row and see nothing happen.
        """
        sizes = self.findings_split.sizes()
        if len(sizes) == 2 and sizes[1] <= 2:
            total = max(sum(sizes), 260)
            self.findings_split.setSizes([int(total * 0.55), int(total * 0.45)])

    def _add_attention_links(self, case):
        """List what was flagged, as links, when no ranked cause was produced.

        Without this, "9 readings are worth a look" points at a tab and leaves
        the user to find nine rows among eighty.
        """
        flagged = [f for f in case.get("findings", [])
                   if f.get("status") in ("warn", "bad")]
        if not flagged:
            return
        shown = flagged[:24]
        text = "Flagged:  " + " · ".join(
            f"<a href='{_html.escape(str(f.get('key', '')))}'>"
            f"{_html.escape(str(f.get('label', '')))}</a>" for f in shown)
        if len(flagged) > len(shown):
            text += f" and {len(flagged) - len(shown)} more on the Measurements tab"
        links = QLabel(text)
        links.setWordWrap(True)
        links.setTextFormat(QtC.RichText)
        links.setStyleSheet(f"color:{self.T['text_3']};font-size:11.5px;background:transparent;")
        palette = links.palette()
        palette.setColor(QPalette.Link, QColor(self.T['accent_hi']))
        links.setPalette(palette)
        links.setCursor(QtC.PointingHandCursor)
        links.setToolTip("Opens the reading, with what was measured and where it came from.")
        links.linkActivated.connect(self._focus_finding)
        self.assessment_box.insertWidget(1, links)

    def _focus_finding(self, key):
        """Open the measurement a card or link points at.

        The attention filter is honoured rather than fought: if the row the user
        asked for is hidden by it, it is turned off, because a link that lands
        on nothing is worse than no link.
        """
        self.tabs.setCurrentIndex(1)
        found = None
        for row in range(self.findings.topLevelItemCount()):
            item = self.findings.topLevelItem(row)
            if (item.data(0, QtC.UserRole) or {}).get("key") == key:
                found = item
                break
        if found is None and self.findings_filter.isChecked():
            self.findings_filter.setChecked(False)
            for row in range(self.findings.topLevelItemCount()):
                item = self.findings.topLevelItem(row)
                if (item.data(0, QtC.UserRole) or {}).get("key") == key:
                    found = item
                    break
        if found is not None:
            self.findings.setCurrentItem(found)
            self.findings.scrollToItem(found)

    def _render_timeline(self, case):
        """The dated view: what changed, and when things started going wrong."""
        self.timeline.clear()
        timeline = case.get("timeline") or {}
        events = timeline.get("events") or []
        marks = {"change": "changed", "symptom": "fault"}
        for event in events:
            days = event.get("days_ago", 0)
            when = ("today" if days < 1 else
                    "yesterday" if days < 2 else
                    f"{days:.0f} days ago")
            item = QTreeWidgetItem([
                when, marks.get(event.get("axis"), ""),
                event.get("title", ""), event.get("detail", ""),
            ])
            if event.get("axis") == "symptom":
                item.setForeground(1, QColor(self.T['danger']))
                item.setForeground(2, QColor(self.T['text']))
            else:
                item.setForeground(1, QColor(self.T['text_3']))
            if event.get("when"):
                item.setToolTip(0, event["when"])
            self.timeline.addTopLevelItem(item)

        onset = timeline.get("onset") or {}
        if not events:
            self.timeline_note.setText(
                "Nothing dated was found: no recent updates, drivers, programs, or recorded "
                "faults. That is normal on a PC that has been left alone, and it means timing "
                "cannot be used to explain anything here."
            )
            return
        source = {
            "stated": "what you said about when it started",
            "stability": "Windows' own stability record",
            "first_symptom": "the first fault recorded",
        }.get(onset.get("source", ""), "")
        if source and onset.get("days_ago") is not None:
            lead = (f"The trouble is placed at about {onset['days_ago']:.0f} days ago, from "
                    f"{source}. Only changes older than that point could have caused it.")
        else:
            lead = ("Nothing places the start of the trouble in time, so no change here is "
                    "being treated as a cause.")
        total, shown = timeline.get("total", len(events)), timeline.get("shown", len(events))
        capped = (f" Showing the {shown} most recent of {total}."
                  if total > shown else "")
        self.timeline_note.setText(
            f"{timeline.get('changes', 0)} change(s) and {timeline.get('symptoms', 0)} "
            f"recorded fault(s).{capped} {lead}"
        )

    def _show_case(self, case):
        self._busy = False
        self.case = case
        self.progress_row.setVisible(False)
        self._stage = "plan"
        self._render_findings(case.get("findings", []))
        self._render_timeline(case)
        self._render_components(case)

        hypotheses = case.get("hypotheses", [])
        if hypotheses:
            self._clear_assessment("")
            while self.assessment_box.count():
                item = self.assessment_box.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                    widget.deleteLater()
            labels = {f.get("key"): f.get("label", "") for f in case.get("findings", [])}
            for hypothesis in hypotheses:
                self.assessment_box.addWidget(
                    WMHypothesisCard(hypothesis, self.T, evidence=labels,
                                     on_evidence=self._focus_finding))
            self.assessment_box.addStretch()
            self.tabs.setCurrentIndex(0)
        elif case.get("profile") == WM_HARDWARE_PROFILE:
            self._clear_assessment(case.get("summary", "Review the hardware readings."))
            self.tabs.setCurrentIndex(3 if case.get("components") else 1)
        elif case.get("profile") == WM_AUDIT_PROFILE:
            attention = sum(1 for f in case.get("findings", [])
                            if f.get("status") in ("warn", "bad"))
            self._clear_assessment(
                (f"{case.get('summary', 'No actionable fault identified within completed coverage.')}\n\n"
                 f"All {len(case.get('findings', []))} readings are on the Measurements tab, "
                 f"and \"Save report\" keeps them as a dated record you can compare against later."
                 ) if not attention else
                (f"No single fault stands out, but {attention} reading(s) are worth a look. "
                 f"Open any of them to see what was measured and where it was read from.")
            )
            self._add_attention_links(case)
            self.tabs.setCurrentIndex(1)
        else:
            self._clear_assessment(
                "Nothing in the checks explains the symptom. The measurements are on the next "
                "tab, and the plan below captures a full report you can share."
            )
            self._add_attention_links(case)
            self.tabs.setCurrentIndex(1)

        self._render_plan(case)
        if case.get("components"):
            self.tabs.setCurrentIndex(3)

        if case.get("profile") == WM_AUDIT_PROFILE:
            self.status.setText(case.get("summary", ""))
        else:
            profile_label = str(case.get("profile", "general")).replace("+", " + ").title()
            self.status.setText(f"{case.get('summary', '')}  Profile: {profile_label}.")
        self.diagnose_btn.setEnabled(True)
        self.full_check_btn.setEnabled(True)
        self.deep_scan_btn.setEnabled(True)
        self.hardware_rescan_btn.setEnabled(True)
        self.report_btn.setEnabled(True)
        self._update_run_button()

    def _render_plan(self, case):
        self.plan.blockSignals(True)
        self.plan.clear()
        for step in case.get("plan", []):
            undo = ("Reversible" if step.get("reversible")
                    else "Restore point" if step.get("restore_point")
                    else "Read-only" if step.get("read_only") else "No undo")
            item = QTreeWidgetItem([
                "", step.get("title", ""), step.get("reason", ""),
                step.get("duration", "varies"), undo,
            ])
            item.setData(0, QtC.UserRole, step["index"])
            item.setFlags(item.flags() | QtC.ItemIsUserCheckable)
            item.setCheckState(0, QtC.Checked)
            item.setForeground(3, QColor(self.T['text_3']))
            item.setToolTip(2, "\n".join((step.get("reason", ""),
                f"Risk: {step.get('risk', 'unknown')}; permission: {'administrator' if step.get('admin') else 'current user'}",
                f"Restart: {'required' if step.get('reboot') else 'not normally required'}",
                step.get("side_effects", ""), step.get("expected_effect", ""))))
            if step.get("risk") == "destructive":
                item.setForeground(4, QColor(self.T['danger']))
            elif step.get("reversible"):
                item.setForeground(4, QColor(self.T['ok']))
            because = [step.get("hypothesis_title", "")]
            because += [title for title in (step.get("also_titles") or [])]
            because = [title for title in because if title]
            if because:
                item.setToolTip(1, "Because:\n  - " + "\n  - ".join(because))
            if step.get("also_for"):
                extra = len(step["also_for"])
                item.setText(2, f"{step.get('reason', '')} "
                                f"(also covers {extra} other finding"
                                f"{'s' if extra != 1 else ''})")
            self.plan.addTopLevelItem(item)
        self.plan.blockSignals(False)

        withheld = case.get("withheld", [])
        if withheld:
            lines = ["Deliberately not doing:"]
            for entry in withheld:
                lines.append(f"  •  {entry['title']} — {entry['reason']}")
            self.withheld_label.setText("\n".join(lines))
            self.withheld_label.setVisible(True)
        else:
            self.withheld_label.setVisible(False)

        if not case.get("plan"):
            self.plan_note.setText(
                "No automatic repair is supported by these readings. Review incomplete checks and any remaining symptoms."
                if case.get("profile") == WM_AUDIT_PROFILE else "Review Hardware for manual fixes and diagnostic tools." if case.get("components") else "No automatic repairs were identified.")
            return
        stops = sum(1 for s in case.get("plan", []) if s.get("stop_if_clear"))
        note = ("WinMend journals the run, creates one restore point when a step needs it, "
                "and repeats these checks afterward.")
        if stops and case.get("profile") == WM_AUDIT_PROFILE:
            faults = len({s.get("hypothesis") for s in case.get("plan", [])})
            note += (f" Steps run one at a time. This plan covers "
                     f"{faults} separate finding{'s' if faults != 1 else ''}: when one is "
                     f"measured healthy again its remaining steps are skipped, and the others "
                     f"still get their turn.")
        elif stops:
            note += (" Steps run one at a time: when a targeted fault measures healthy, "
                     "remaining repairs for that same fault are skipped.")
        self.plan_note.setText(note)
