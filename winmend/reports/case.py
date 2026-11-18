"""WinMend reports: case."""

from __future__ import annotations




def render_case_report_html(case, verification=None, log=()):
    """A self-contained handoff document for the case.

    This is the thing a technician leaves behind: what was reported, what was
    measured, what it was judged to be, what was done, and what was deliberately
    not done. It is written to be readable by someone who was not present.
    """
    import html as _html
    from winmend.diagnostics.privacy import redact
    case = redact(case)
    verification = redact(verification)
    log = redact(log)

    def esc(value):
        return _html.escape(str(value if value is not None else ""))

    severity_colour = {"critical": "#c0392b", "high": "#e67e22",
                       "medium": "#f1c40f", "low": "#7f8c8d"}
    status_colour = {"good": "#27ae60", "warn": "#e67e22",
                     "bad": "#c0392b", "info": "#7f8c8d"}

    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>WinMend case report - {esc(case.get('problem', 'diagnosis'))}</title>",
        "<style>",
        "body{font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:32px;",
        "background:#f5f6f8;color:#1c2430;line-height:1.55;}",
        ".wrap{max-width:960px;margin:0 auto;}",
        "h1{font-size:22px;margin:0 0 4px;} h2{font-size:15px;margin:28px 0 10px;",
        "text-transform:uppercase;letter-spacing:.08em;color:#5a6572;}",
        ".card{background:#fff;border:1px solid #e1e5ea;border-radius:10px;padding:18px 20px;margin-bottom:14px;}",
        "table{width:100%;border-collapse:collapse;font-size:13px;}",
        "th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;",
        "color:#7a838f;border-bottom:1px solid #e1e5ea;padding:7px 8px;}",
        "td{padding:7px 8px;border-bottom:1px solid #f0f2f5;vertical-align:top;}",
        ".pill{display:inline-block;padding:1px 9px;border-radius:11px;font-size:11px;",
        "font-weight:600;color:#fff;}",
        ".muted{color:#7a838f;font-size:12px;}",
        ".advice{background:#f2f7fd;border-left:3px solid #3b82c4;padding:9px 13px;",
        "margin-top:9px;border-radius:0 6px 6px 0;font-size:13px;}",
        ".withheld{background:#fdf4f2;border-left:3px solid #c0392b;padding:9px 13px;",
        "margin-bottom:9px;border-radius:0 6px 6px 0;font-size:13px;}",
        "</style></head><body><div class='wrap'>",
        f"<h1>Case report: {esc(case.get('problem') or 'System diagnosis')}</h1>",
        f"<div class='muted'>Opened {esc(case.get('created_at', ''))} &middot; "
        f"profile {esc(str(case.get('profile', 'general')).replace('+', ' + '))} &middot; "
        f"case {esc(case.get('id', '')[:8])}</div>",
        f"<div class='card'><strong>{esc(case.get('summary', ''))}</strong></div>",
    ]

    answers = case.get("answer_summary") or []
    if answers:
        parts.append("<h2>What was reported</h2><div class='card'><table>")
        for line in answers:
            question, _, answer = str(line).rpartition("? ")
            parts.append(f"<tr><td style='width:55%'>{esc(question)}?</td>"
                         f"<td><strong>{esc(answer)}</strong></td></tr>")
        parts.append("</table></div>")

    hypotheses = case.get("hypotheses") or []
    if hypotheses:
        parts.append("<h2>Assessment</h2>")
        for item in hypotheses:
            colour = severity_colour.get(item.get("severity"), "#7f8c8d")
            parts.append(
                "<div class='card'>"
                f"<span class='pill' style='background:{colour}'>"
                f"{esc(item.get('severity', '').upper())}</span> "
                f"<strong style='margin-left:7px'>{esc(item.get('title'))}</strong>"
                f"<span class='muted'> &middot; {esc(item.get('evidence_strength', 'uncalibrated'))} evidence</span>"
                f"<p>{esc(item.get('explanation'))}</p>")
            if item.get("advice"):
                parts.append(f"<div class='advice'><strong>What to do:</strong> "
                             f"{esc(item['advice'])}</div>")
            for field, label in (("supporting", "Supporting observations"), ("contradictory", "Contradictory observations"), ("missing", "Missing evidence")):
                if item.get(field):
                    parts.append(f"<p class='muted'>{label}: {esc(', '.join(item[field]))}</p>")
            parts.append("</div>")

    withheld = case.get("withheld") or []
    if withheld:
        parts.append("<h2>Deliberately not done</h2><div class='card'>")
        for item in withheld:
            parts.append(f"<div class='withheld'><strong>{esc(item.get('title'))}</strong> "
                         f"&mdash; {esc(item.get('reason'))}</div>")
        parts.append("</div>")

    plan = case.get("plan") or []
    if plan:
        parts.append("<h2>Plan</h2><div class='card'><table>"
                     "<tr><th>#</th><th>Step</th><th>Why</th><th>Time</th><th>Reversible</th></tr>")
        for step in plan:
            reason = esc(step.get("reason"))
            # A step that answers more than one finding says so here too, or the
            # plan reads as one item short against the assessment above it.
            for title in (step.get("also_titles") or []):
                reason += f"<br><span class='muted'>Also covers: {esc(title)}</span>"
            parts.append(
                f"<tr><td>{esc(step.get('index', 0) + 1)}</td>"
                f"<td><strong>{esc(step.get('title'))}</strong></td>"
                f"<td class='muted'>{reason}<br>Risk: {esc(step.get('risk'))}; "
                f"permission: {'administrator' if step.get('admin') else 'current user'}; "
                f"restart: {'required' if step.get('reboot') else 'not normally required'}"
                f"<br>{esc(step.get('side_effects', ''))}</td>"
                f"<td>{esc(step.get('duration'))}</td>"
                f"<td>{'yes' if step.get('reversible') else 'restore point' if step.get('restore_point') else 'no'}</td></tr>")
        parts.append("</table></div>")

    components = case.get("components") or []
    if components:
        parts.append("<h2>Hardware coverage &amp; next steps</h2>")
        for component in components:
            parts.append(f"<div class='card'><h3>{esc(component.get('name'))}</h3>"
                         f"<strong>{esc(component.get('status_label'))}</strong>"
                         f"<p>{esc(component.get('summary'))}</p>")
            for title, lines in (("What to do", component.get("next_steps", [])),
                                 ("Evidence", component.get("evidence", [])),
                                 ("Missing checks", component.get("missing", []))):
                if lines:
                    parts.append(f"<h4>{title}</h4><ul>" + "".join(
                        f"<li>{esc(line)}</li>" for line in lines) + "</ul>")
            parts.append(f"<p class='muted'>{esc(component.get('limitation'))}</p></div>")

    timeline = case.get("timeline") or {}
    events = timeline.get("events") or []
    if events:
        onset = timeline.get("onset") or {}
        source = {
            "stated": "what the user said about when it started",
            "stability": "Windows' own stability record",
            "first_symptom": "the first fault recorded",
        }.get(onset.get("source", ""), "")
        if source and onset.get("days_ago") is not None:
            placed = (f"The start of the trouble is placed at about "
                      f"{onset['days_ago']:.0f} days ago, from {source}. Only changes older "
                      f"than that point could have caused it.")
        else:
            placed = ("Nothing places the start of the trouble in time, so no change here is "
                      "treated as a cause.")
        total, shown = timeline.get("total", len(events)), timeline.get("shown", len(events))
        if total > shown:
            placed = f"Showing the {shown} most recent of {total} dated events. " + placed
        parts.append(
            "<h2>Timeline</h2><div class='card'>"
            f"<p class='muted'>{esc(placed)}</p><table>"
            "<tr><th>When</th><th></th><th>What happened</th><th>Detail</th></tr>")
        for event in events:
            days = event.get("days_ago", 0)
            when = ("today" if days < 1 else "yesterday" if days < 2
                    else f"{days:.0f} days ago")
            symptom = event.get("axis") == "symptom"
            colour = "#c0392b" if symptom else "#7a838f"
            parts.append(
                f"<tr><td class='muted' title='{esc(event.get('when'))}'>{esc(when)}</td>"
                f"<td><span style='color:{colour};font-weight:600'>"
                f"{'fault' if symptom else 'changed'}</span></td>"
                f"<td>{esc(event.get('title'))}</td>"
                f"<td class='muted'>{esc(event.get('detail'))}</td></tr>")
        parts.append("</table></div>")

    if log:
        parts.append("<h2>What was done</h2><div class='card'><table>")
        for entry in log:
            parts.append(f"<tr><td style='width:26%'>{esc(entry.get('title', ''))}</td>"
                         f"<td>{esc(entry.get('result', ''))}</td></tr>")
        parts.append("</table></div>")

    if verification:
        outcome = str(verification.get("outcome", "")).replace("_", " ").title()
        parts.append(f"<h2>Verification</h2><div class='card'><strong>{esc(outcome)}</strong>"
                     f"<p>{esc(verification.get('summary', ''))}</p>")
        changes = verification.get("changes") or []
        if changes:
            parts.append("<table><tr><th>Check</th><th>Before</th><th>After</th><th>Result</th></tr>")
            for change in changes:
                parts.append(f"<tr><td>{esc(change.get('label'))}</td>"
                             f"<td class='muted'>{esc(change.get('before'))}</td>"
                             f"<td>{esc(change.get('after'))}</td>"
                             f"<td>{esc(change.get('result'))}</td></tr>")
            parts.append("</table>")
        parts.append("</div>")

    findings = case.get("findings") or []
    if findings:
        parts.append("<h2>Measurements</h2><div class='card'><table>"
                     "<tr><th>Check</th><th>Result</th><th>What it means</th></tr>")
        for finding in findings:
            colour = status_colour.get(finding.get("status"), "#7f8c8d")
            parts.append(
                f"<tr><td>{esc(finding.get('label'))}</td>"
                f"<td><span style='color:{colour};font-weight:600'>"
                f"{esc(finding.get('value'))}</span></td>"
                f"<td class='muted'>{esc(finding.get('detail'))}</td></tr>")
        parts.append("</table></div>")

    parts.append("<p class='muted'>Produced by WinMend. Measurements are point-in-time "
                 "readings from this PC; no command output or file contents are included.</p>")
    trace = case.get("trace")
    if trace:
        import json
        parts.append("<details><summary>Diagnostic decision trace</summary><pre>" +
                     esc(json.dumps(trace, indent=2, ensure_ascii=False)) + "</pre></details>")
    parts.append("</div></body></html>")
    return "".join(parts)
