"""WinMend diagnostics: engine."""

from __future__ import annotations

from winmend.core.findings import SEVERITY, utc_now
from winmend.diagnostics.assessment import CaseAssessmentMixin
from winmend.diagnostics.catalog import Cancelled, FINDING_SOURCES, collectors_for
from winmend.diagnostics.collectors.deep import DeepProbe
from winmend.diagnostics.components import build_component_report
from winmend.diagnostics.context import Context
from winmend.diagnostics.hardware_assessment import CaseHardwareAssessmentMixin
from winmend.diagnostics.helpers import _plural
from winmend.diagnostics.interview import Interview
from winmend.diagnostics.models import Hypothesis, _default_task_lookup, task_action
from winmend.diagnostics.planning import CasePlanningMixin
from winmend.diagnostics.reference import AUDIT_PROFILE, HARDWARE_PROFILE, SEVERITY_RANK
from winmend.diagnostics.rules import RULES
import uuid
import time
from winmend.diagnostics.observations import split_results, attach_provenance, failure_state, UNKNOWN, usable
from winmend.diagnostics.reasoning import evaluate
from winmend.diagnostics.investigation import select_collectors
from winmend.diagnostics.symptoms import interpret


class CaseEngine(
    CaseAssessmentMixin,
    CaseHardwareAssessmentMixin,
    CasePlanningMixin,
):
    """Runs the whole workflow: interview, evidence, reasoning, plan.

    The output dict keeps ``findings``, ``recommended_tasks``, ``profile`` and
    ``severity_score`` with the shapes ``DiagnosticEngine`` already produced, so
    the Safety Journal, the verification compare(), and the existing Guided Fix
    plumbing continue to work against a case without changes.
    """

    # Collectors that make up the fast first pass. Everything here is either a
    # direct API call or a single short subprocess, so the user sees findings
    # within a few seconds rather than staring at an empty panel.
    FAST_COLLECTORS = (
        ("system_context", "Reading Windows capabilities and repair safety context"),
        ("disk", "Checking disk space"),
        ("memory", "Reading memory pressure"),
        ("uptime_days", "Checking uptime"),
        ("startup_count", "Counting startup programs"),
        ("startup_entries", "Listing startup programs"),
        ("pending_reboot", "Checking for a pending restart"),
        ("restart_pending", "Checking what a restart is waiting for"),
        ("windows_version", "Identifying the Windows version"),
        ("proxy_settings", "Reading proxy configuration"),
        ("hosts_file", "Reading the hosts file"),
        ("network", "Testing network reachability"),
        # Registry- and file-only, so they cost nothing and are worth having in
        # the first panel the user sees.
        ("uac_state", "Reading User Account Control"),
        ("update_state", "Checking Windows Update availability"),
        ("power_config", "Reading the power plan"),
        ("user_profile", "Checking the user profile"),
        ("filesystem_health", "Checking for a scheduled disk check"),
        ("dump_files", "Looking for crash dumps"),
        ("adapter_health", "Reading network adapter counters"),
        # Registry, file, and single-syscall reads added with the wider sweep.
        # None costs more than a fraction of a second, so they belong in the
        # panel the user sees first rather than behind a progress bar.
        ("boot_config", "Reading the boot configuration"),
        ("fast_startup", "Checking fast startup"),
        ("wake_history", "Checking what wakes this PC"),
        ("update_policy", "Checking where updates come from"),
        ("update_cache", "Measuring the update download folder"),
        ("policy_health", "Looking for features switched off by policy"),
        ("environment_health", "Checking the system PATH"),
        ("known_folders", "Checking where your files are stored"),
        ("integrity_history", "Reading the last file-integrity check"),
        ("shell_health", "Checking the desktop and Start menu"),
        ("dns_resolution", "Resolving names"),
        ("winsock_health", "Inspecting the network stack"),
        ("interface_mtu", "Reading packet sizes"),
    )

    # The deep sweep. These are subprocess- and WMI-bound, so they are run
    # concurrently -- serially they add up to well over a minute.
    DEEP_COLLECTORS = (
        ("layered_network", "Testing two public TCP, DNS and HTTPS endpoints with timeouts"),
        ("performance_samples", "Repeating resource measurements after the other checks"),
        ("temp_size", "Measuring temporary data"),
        ("smart_health", "Reading drive health (SMART)"),
        ("event_log_errors", "Scanning the system event log"),
        ("bugchecks", "Looking for recorded stop codes"),
        ("app_crashes", "Scanning application crashes"),
        ("update_failures", "Reading Windows Update history"),
        ("installed_updates", "Listing recently installed updates"),
        ("installed_programs", "Listing recently installed programs"),
        ("third_party_drivers", "Listing recently installed drivers"),
        ("problem_devices", "Checking Device Manager"),
        ("gpu_resets", "Checking for display driver resets"),
        ("thermal_events", "Checking for thermal throttling"),
        ("storage_removals", "Checking for storage faults"),
        ("memory_config", "Reading memory configuration"),
        ("top_memory_processes", "Finding the largest memory users"),
        ("pagefile", "Checking virtual memory"),
        ("dns_servers", "Reading DNS configuration"),
        ("battery_wear", "Measuring battery wear"),
        ("wifi_link", "Measuring the Wi-Fi link"),
        ("defender", "Checking Microsoft Defender"),
        ("firewall_enabled", "Checking the firewall"),
        ("defender_exclusions", "Reading scan exclusions"),
        ("platform_security", "Reading platform security state"),
        ("component_store_health", "Checking Windows component health"),
        ("boot_history", "Reading boot performance history"),
        ("restore_points", "Listing restore points"),
        ("disk_latency", "Sampling disk responsiveness"),
        ("ping_quality", "Measuring connection quality"),
        ("volumes", "Measuring every fixed drive"),
        ("disk_reliability", "Reading drive wear and error counters"),
        ("service_health", "Checking Windows services"),
        ("scheduled_tasks", "Checking scheduled tasks"),
        ("search_index", "Checking the search index"),
        ("defender_threats", "Reading Defender's detection history"),
        ("firewall_profiles", "Reading firewall profiles"),
        ("network_config", "Reading addresses and gateway"),
        ("time_sync", "Checking the system clock"),
        ("printers", "Checking printers"),
        ("cpu_load", "Sampling processor load"),
        ("whea_errors", "Reading hardware error reports"),
        ("memory_diagnostic", "Checking for a memory test result"),
        ("cpu_throttle", "Measuring processor speed"),
        ("reliability_history", "Reading Windows' stability history"),
        ("disk_optimization", "Checking drive maintenance"),
        ("bitlocker_state", "Checking drive encryption"),
        ("top_disk_processes", "Finding what is using the disk"),
        ("network_profile", "Reading the connection profile"),
        ("activation_state", "Checking Windows activation"),
        ("appx_health", "Checking Store apps"),
        ("audio_health", "Checking sound"),
        ("bluetooth_health", "Checking Bluetooth"),
        ("display_config", "Checking graphics"),
    )

    # The component-level scan. Everything here is either expensive, gated on
    # elevation, or an active test, which is why none of it runs in the sweep
    # the ordinary paths use -- and why it is offered as its own deliberate
    # choice rather than folded into "check for issues".
    #
    # Ordered cheapest-first. The pool takes them in this order as workers free
    # up, so the slow and active ones start last -- by which point the user can
    # already see everything that was merely read.
    HARDWARE_COLLECTORS = (
        ("component_devices", "Checking motherboard controllers and connected devices"),
        ("firmware_info", "Identifying the motherboard and BIOS"),
        ("cpu_details", "Reading the processor and its microcode"),
        ("memory_modules", "Reading each memory module"),
        ("gpu_hardware", "Reading the graphics adapter"),
        ("display_links", "Checking connected displays"),
        ("tpm_state", "Checking the security chip"),
        ("pool_usage", "Measuring kernel memory"),
        ("disk_geometry", "Reading drive layout and firmware"),
        ("minidump_details", "Reading stop codes out of crash dumps"),
        ("wer_reports", "Reading the crash report archive"),
        ("live_kernel_events", "Looking for faults caught without a crash"),
        ("gpu_vendor_telemetry", "Asking the graphics card directly"),
        ("sensor_readings", "Reading fans, temperatures and voltages"),
        ("smart_attributes", "Reading raw drive error counters"),
        ("power_events", "Checking for unexpected power loss"),
        ("firmware_errors", "Looking for firmware faults"),
        ("storage_bus_errors", "Reading storage errors from the log"),
        ("event_log_sweep", "Scanning every event log"),
        ("memory_pattern_test", "Testing memory with known patterns"),
        ("disk_read_sweep", "Reading blocks across every drive"),
    )

    # Raised with the sweep: the collectors are overwhelmingly waiting on
    # subprocesses and WMI rather than computing, so more of them in flight is
    # what keeps a much wider check inside the same wall-clock budget. Raised
    # again for the second widening -- the slowest single collector now costs
    # more than five seconds on its own, so the pool has to be deep enough that
    # it overlaps the rest rather than extending the run.
    MAX_WORKERS = 12
    CHECK_TIMEOUTS = {"system_context": 25, "layered_network": 45, "performance_samples": 20,
                      "memory_pattern_test": 45, "disk_read_sweep": 60}

    def __init__(self, probe=None, engine=None, allow_external_probes=True):
        self.probe = probe or DeepProbe()
        from winmend.diagnostics.profiles import DiagnosticEngine
        self.classic = engine or DiagnosticEngine(probe=self.probe)
        self.interview = Interview(self.classic)
        self._collection_metadata = {}
        self._rule_errors = []
        self.allow_external_probes = bool(allow_external_probes)

    # -- evidence ---------------------------------------------------------

    def _collect(self, names, progress=None, cancel=None, parallel=True):
        """Run collectors, returning ``{name: result}``.

        A collector that raises is recorded as unavailable rather than being
        allowed to abort the sweep -- partial evidence still diagnoses.
        """
        results = {}
        total = len(names)
        done = [0]
        starts = {}

        def report(label):
            done[0] += 1
            if progress:
                progress(done[0], total, label)

        def call(name):
            if cancel is not None and cancel():
                raise Cancelled()
            started = time.perf_counter()
            starts[name] = time.monotonic()
            try:
                if not self.allow_external_probes and name in ("network", "layered_network", "dns_resolution", "ping_quality", "time_sync"):
                    return {"available": False, "diagnostic_state": "not_tested", "reason": "External connectivity probes disabled"}
                return getattr(self.probe, name)()
            except Cancelled:
                raise
            except Exception as exc:
                return {"available": False, "reason": str(exc)[:200],
                        "diagnostic_state": failure_state(str(exc))}
            finally:
                self._collection_metadata[name] = {"collected_at": utc_now(),
                    "duration_ms": round((time.perf_counter() - started)*1000, 2)}

        if not parallel:
            for name, label in names:
                if cancel is not None and cancel():
                    raise Cancelled()
                results[name] = call(name)
                report(label)
            return results

        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
        pool = ThreadPoolExecutor(max_workers=self.MAX_WORKERS)
        try:
            futures = {pool.submit(call, name): (name, label) for name, label in names}
            # as_completed so progress reflects work actually finishing rather
            # than the order the collectors happen to be declared in.
            remaining = set(futures)
            while remaining:
                if cancel is not None and cancel():
                    for future in remaining:
                        future.cancel()
                    raise Cancelled()
                ready, _ = wait(remaining, timeout=.1, return_when=FIRST_COMPLETED)
                for future in list(remaining):
                    name, label = futures[future]
                    timed_out = name in starts and time.monotonic()-starts[name] > self.CHECK_TIMEOUTS.get(name, 60)
                    if future not in ready and not timed_out:
                        continue
                    if timed_out and future not in ready:
                        future.cancel()
                        results[name] = {"available": False, "diagnostic_state": "collection_failed", "reason": "Diagnostic check timed out; no result is accepted"}
                    else:
                        try:
                            results[name] = future.result()
                        except Cancelled:
                            results[name] = {"available": False, "diagnostic_state": "cancelled", "reason": "cancelled"}
                        except Exception as exc:
                            results[name] = {"available": False, "reason": str(exc)[:200]}
                    remaining.remove(future)
                    report(label)
        finally:
            # Python cannot interrupt a blocked native call. Its eventual
            # result is discarded; subprocess providers have their own limits.
            pool.shutdown(wait=False, cancel_futures=True)
        if cancel is not None and cancel():
            raise Cancelled()
        return {name: results[name] for name, _label in names}

    # -- reasoning --------------------------------------------------------

    @staticmethod
    def _unexplained(findings, hypotheses):
        """Cover measurements that are unhealthy but that no rule spoke for.

        A full check promises to report everything wrong, so a flagged reading
        with nothing offered against it is a broken promise. These rank below
        every reasoned hypothesis because a finding on its own is an
        observation, not an explanation.
        """
        covered = set()
        for hypothesis in hypotheses:
            covered.update(hypothesis.evidence_keys)
        extra = []
        for finding in findings:
            severity = SEVERITY.get(finding.get("status"), 0)
            if not severity or finding["key"] in covered:
                continue
            tasks = [t for t in finding.get("task_ids", ())]
            if not tasks:
                continue
            extra.append(Hypothesis(
                f"finding_{finding['key']}",
                finding.get("label", finding["key"]),
                f"{finding.get('label')}: {finding.get('value')}. "
                f"{finding.get('detail', '')}".strip(),
                confidence=70,
                severity="medium" if severity > 1 else "low",
                evidence_keys=[finding["key"]],
                actions=[task_action(task_id) for task_id in tasks],
            ))
        return extra

    def _reason(self, ctx):
        hypotheses = []
        self._rule_errors = []
        for rule_fn in RULES:
            try:
                produced = rule_fn(ctx)
            except Exception as exc:
                # A rule that throws must not take the diagnosis down with it.
                self._rule_errors.append({"rule": rule_fn.__name__, "error": type(exc).__name__})
                continue
            if produced is None:
                continue
            if isinstance(produced, Hypothesis):
                hypotheses.append(produced)
            else:
                hypotheses.extend(h for h in produced if isinstance(h, Hypothesis))
        hypotheses.sort(
            key=lambda h: (-SEVERITY_RANK.get(h.severity, 1), -h.confidence, h.id))
        return hypotheses

    # -- the whole workflow ------------------------------------------------

    def questions(self, problem, answers=None, observations=None):
        profile, score = self.interview.profile_for(problem)
        return {
            "profile": profile,
            "low_confidence": score == 0,
            "questions": self.interview.select(problem, profile, answers=answers, observations=observations),
            "interpretation": interpret(problem).as_dict(),
        }

    def triage(self, problem, answers=None, profile=None, cancel=None):
        """The fast pass: real findings within a few seconds."""
        detected_score = None
        if profile is None:
            profile, detected_score = self.interview.profile_for(problem)
        wanted = select_collectors(profile, self.FAST_COLLECTORS, (), answers=answers)
        raw = self._collect(wanted, parallel=True, cancel=cancel)
        findings = self._findings(raw)
        return {
            "stage": "triage",
            "profile": profile,
            "raw": raw,
            "findings": findings,
            "low_confidence": detected_score == 0,
        }

    def build_case(self, problem, answers=None, profile=None, history=None,
                   progress=None, cancel=None, task_lookup=None, raw=None,
                   deep=False):
        """Run the deep sweep and produce the full case.

        ``deep`` adds the component-level hardware collectors on top of the
        usual sweep. It is a parameter rather than a separate path so that the
        findings, the rules, the plan and the verification re-run all continue
        to work against one case shape.
        """
        detected_score = None
        if profile is None:
            profile, detected_score = self.interview.profile_for(problem)
        audit = profile in (AUDIT_PROFILE, HARDWARE_PROFILE)
        answers = Interview.normalise(answers)

        session_id = uuid.uuid4().hex
        collected = dict(raw or {})
        wanted = select_collectors(profile, self.FAST_COLLECTORS, self.DEEP_COLLECTORS,
                                  self.HARDWARE_COLLECTORS if deep or profile == HARDWARE_PROFILE else (), answers,
                                  temporal=bool(interpret(problem).temporal))
        pending = [pair for pair in wanted if pair[0] not in collected]
        # Active drive samples wait for passive health evidence; repeated load
        # waits for the subprocess sweep so it does not primarily measure us.
        deferred = [pair for pair in pending if pair[0] in ("disk_read_sweep", "memory_pattern_test", "performance_samples")]
        progress_count = [0]
        def stage_progress(_done, _total, label):
            progress_count[0] += 1
            if progress:
                progress(progress_count[0], len(pending), label)
        collected.update(self._collect([pair for pair in pending if pair not in deferred], progress=stage_progress, cancel=cancel))
        for pair in deferred:
            unsafe = (pair[0] == "disk_read_sweep" and (
                (collected.get("smart_health") or {}).get("unhealthy") or
                any((d.get("read_errors") or d.get("write_errors") or 0) for d in
                    (collected.get("disk_reliability") or {}).get("disks", [])) or
                any(d.get("predict_failure") or d.get("pending_sectors") or d.get("uncorrectable") for d in
                    (collected.get("smart_attributes") or {}).get("drives", []))))
            if unsafe:
                collected[pair[0]] = {"available": False, "diagnostic_state": "not_tested",
                                      "reason": "Drive health evidence warrants backup first; active read samples withheld."}
                stage_progress(1, 1, pair[1])
            else:
                collected.update(self._collect([pair], progress=stage_progress, cancel=cancel))

        findings = self._findings(collected)
        observations = attach_provenance(findings, collected, session_id, self._collection_metadata, problem)
        usable_raw, _ = split_results(collected)
        for finding in findings:
            if finding.get("status") == "collection_failed" and finding.get("detail") == "Provider returned a malformed measurement":
                for source in FINDING_SOURCES.get(finding["key"], ()):
                    usable_raw.pop(source, None)
        ctx = Context(problem, profile, answers, usable_raw, findings, history)
        hypotheses = self._reason(ctx)
        safety_proposals = []
        for h in hypotheses:
            if h.suppress:
                safeguard = Hypothesis(h.id, h.title, h.explanation, evidence_keys=h.evidence_keys,
                                       suppress=h.suppress, suppress_reason=h.suppress_reason)
                safety_proposals.append(safeguard)
        if audit:
            hypotheses.extend(self._unexplained(findings, hypotheses))
        original_actions = {h.id: [dict(a) for a in h.actions] for h in hypotheses}
        hypotheses, decision_trace = evaluate(ctx, hypotheses)
        for observation in observations:
            observation["supports"] = [d["id"] for d in decision_trace if observation["check_id"] in d["supporting"]]
            observation["contradicts"] = [d["id"] for d in decision_trace if observation["check_id"] in d["contradictory"]]

        lookup = task_lookup or _default_task_lookup
        attempts = [a for session in (history or [])
                    if not session.get("problem") or session.get("problem", "").strip() == (problem or "").strip()
                    for a in session.get("verification", {}).get("attempts", session.get("attempts", []))]
        steps, withheld = self._plan(hypotheses + safety_proposals, lookup, findings, usable_raw.get("system_context"), attempts)
        from winmend.diagnostics.eligibility import READ_ONLY
        represented = {s["id"] for s in steps} | {w["id"] for w in withheld}
        for decision in decision_trace:
            if decision["disposition"] == "included" or decision["id"].startswith("baseline_") or not decision["symptom_relevant"]:
                continue
            for action in original_actions.get(decision["id"], []):
                identifier = action.get("action") or action.get("task")
                if not identifier or identifier in represented or identifier in READ_ONLY:
                    continue
                withheld.append({"id": identifier, "title": action.get("title") or identifier.replace("_", " ").title(),
                    "because": decision["title"], "reason": "The proposed explanation lacks sufficient relevant, uncontradicted evidence. Configuration or timing alone does not justify this change."})
                represented.add(identifier)

        # Nothing conclusive still deserves an answer: a read-only report gives
        # the user something to act on rather than an empty plan. A full check
        # is the exception -- "nothing is wrong" is the useful result there, and
        # offering busywork would undercut it.
        if not steps and not audit:
            meta = lookup("pc_report")
            if meta:
                steps = [{
                    "kind": "task", "id": "pc_report", "task": "pc_report", "action": "",
                    "params": {}, "title": meta["title"],
                    "reason": "Capture the evidence and missing coverage before choosing another repair.",
                    "duration": meta["duration"], "risk": meta["risk"],
                    "restore_point": meta["restore_point"], "reversible": False,
                    "admin": meta["admin"], "reboot": False, "confirm": False,
                    "hypothesis": "", "hypothesis_title": "", "severity": "low",
                    "confidence": 0, "verify_keys": [], "index": 0, "stop_if_clear": False,
                    "read_only": True, "required_evidence": [],
                }]

        attention = sum(1 for f in findings if f["status"] in ("warn", "bad"))
        score = sum(SEVERITY.get(f["status"], 0) for f in findings)
        checked = len(findings)
        if audit:
            label = ("Hardware scan complete" if profile == HARDWARE_PROFILE
                     else "Full check complete")
            if hypotheses:
                lead = hypotheses[0]
                summary = (f"{label}: {_plural(len(hypotheses), 'issue')} found "
                           f"across {checked} checks. Most serious: {lead.title}.")
            elif attention:
                summary = (f"{label}: {checked} checks run. "
                           f"{_plural(attention, 'reading')} worth a look, but nothing adds up "
                           f"to a specific fault.")
            elif profile == HARDWARE_PROFILE:
                # Worth saying plainly what a clean hardware pass does and does
                # not prove. "Nothing is wrong with your hardware" is a promise
                # no sampled test can make, and making it is how someone ends up
                # ignoring a fault that only shows under load.
                summary = (f"{label}: no issues found in the available readings. "
                           "Review Hardware for missing checks and component-specific limits. "
                           "This scan cannot exclude physical faults or problems under sustained load.")
            else:
                incomplete = sum(f.get("diagnostic_state") in UNKNOWN for f in findings)
                summary = (f"{label}: no actionable fault identified within the completed checks. "
                           f"{incomplete} reading(s) inconclusive or unavailable; review coverage.")
        elif hypotheses:
            lead = hypotheses[0]
            summary = f"Leading explanation: {lead.title} ({lead.evidence_strength} evidence)."
            if len(hypotheses) > 1:
                summary += f" {len(hypotheses) - 1} other explanation(s) considered."
        elif attention:
            summary = f"Found {_plural(attention, 'item')} needing attention, but no single cause stands out."
        else:
            summary = "The checks did not find a fault. Nothing here explains the symptom."

        return {
            "id": session_id,
            "schema_version": 2,
            "created_at": utc_now(),
            "problem": (problem or "").strip(),
            "profile": profile,
            "answers": answers,
            "answer_summary": Interview.summarise(answers),
            "summary": summary,
            "severity_score": score,
            "components": build_component_report(collected, findings)
                          if deep or profile == HARDWARE_PROFILE else [],
            "findings": findings,
            "hypotheses": [h.as_dict() for h in hypotheses],
            "plan": steps,
            "withheld": withheld,
            # Kept so the existing Guided Fix plumbing and the Safety Journal
            # continue to understand a case without any changes.
            "recommended_tasks": [
                {"id": s["id"], "reason": s["reason"], "duration": s["duration"]}
                for s in steps if s["kind"] == "task"
            ],
            "low_confidence": detected_score == 0,
            "escalated": False,
            "stage": "case",
            # The dated view of the same evidence. Carried on the case so the
            # page can show it and the journal keeps it with everything else.
            "timeline": ctx.timeline.as_dict(stated_days=ctx.onset_days()),
            "system_context": collected.get("system_context") or {},
            "interpretation": interpret(problem).as_dict(),
            "observations": observations,
            "root_cause_assessment": {"leading_hypothesis": hypotheses[0].id if hypotheses else None,
                "strength": hypotheses[0].evidence_strength if hypotheses else "insufficient",
                "status": "suspected" if hypotheses else "not_identified",
                "alternatives": [h.id for h in hypotheses[1:]], "original_symptom_verified": False},
            "attempts": attempts,
            "trace": {"selected_checks": [name for name, _ in wanted],
                      "proposals": decision_trace, "rule_errors": list(self._rule_errors),
                      "repair_decisions": [{"id": s["id"], "reason": s.get("precondition_reason")} for s in steps],
                      "excluded_repairs": withheld},
            "provider_results": [{"check_id": name, "collection_status": "collected" if usable(name, value) else "unavailable",
                                  "reason": value.get("reason") if isinstance(value, dict) else None}
                                 for name, value in collected.items()],
            "coverage": {"attempted": len(collected), "usable": len(usable_raw),
                         "incomplete": len(collected)-len(usable_raw)},
        }

    def audit(self, progress=None, cancel=None, task_lookup=None, raw=None, history=None):
        """A proactive full check: no complaint, no interview, every rule.

        This answers "is anything wrong with this PC" rather than "why is this
        happening". The difference matters: with no symptom and no stated onset,
        the rules that depend on the user's account of events stay silent by
        design, so everything reported here rests purely on measurement.
        """
        return self.build_case(
            "Full system check", answers={}, profile=AUDIT_PROFILE, history=history,
            progress=progress, cancel=cancel, task_lookup=task_lookup, raw=raw,
        )

    def hardware_scan(self, progress=None, cancel=None, task_lookup=None,
                      raw=None, history=None):
        """The component-level deep dive: every source, plus the active tests.

        This is the widest sweep the engine can run. It answers a question the
        other paths cannot: not "what is Windows unhappy about" but "is any part
        of this machine failing" -- which needs raw drive counters, the crash
        dump headers, every event log, and memory that is actually written to
        and read back rather than merely asked about.

        It reuses ``build_case`` wholesale so a hardware case is the same shape
        as every other one, and so the Safety Journal, the verification compare
        and the report renderer keep working against it untouched.
        """
        return self.build_case(
            "Hardware deep scan", answers={}, profile=HARDWARE_PROFILE,
            history=history, progress=progress, cancel=cancel,
            task_lookup=task_lookup, raw=raw, deep=True,
        )

    def remeasure(self, finding_keys, cancel=None):
        """Re-run only the collectors behind ``finding_keys``.

        This is what makes the plan adaptive: after a step, only the handful of
        checks that step could plausibly have changed are repeated, which takes
        a second or two rather than another full sweep.
        """
        wanted = set(collectors_for(finding_keys))
        names = [pair for pair in (self.FAST_COLLECTORS + self.DEEP_COLLECTORS
                                   + self.HARDWARE_COLLECTORS)
                 if pair[0] in wanted]
        if not names:
            return {}
        return self._collect(names, cancel=cancel)

    def step_cleared(self, step, raw, before_findings):
        """Did this step clear the specific problems it was chosen to fix?

        The test is deliberately against the baseline rather than against zero.
        Most finding rows are informational and always score zero, so "every
        check I looked at is fine" would report success for a step that changed
        nothing. Asking "were these warn or bad before, and are they good now"
        can only be answered yes by an actual improvement.
        """
        keys = [k for k in step.get("verify_keys", []) if k in FINDING_SOURCES]
        if not keys:
            return False, []
        baseline = {f["key"]: f for f in (before_findings or [])}
        broken = [k for k in keys if SEVERITY.get(baseline.get(k, {}).get("status"), 0) > 0]
        if not broken:
            return False, []
        measured = {f["key"]: f for f in self.measure_findings(raw)}
        checked = [measured[k] for k in broken if k in measured]
        if len(checked) != len(broken):
            return False, checked
        # Explicitly good, fresh, comparable measurements only; unknown/info
        # and historical counts cannot satisfy a fault-cleared predicate.
        from winmend.diagnostics.verification import historical
        return all(f["status"] == "good" and not historical(f)
                   and (not k.startswith("resource_") or f.get("repeatable"))
                   for k, f in zip(broken, checked)), checked

    def measure_findings(self, raw):
        return self._findings(raw)
