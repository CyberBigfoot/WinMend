"""WinMend diagnostics: assessment."""

from __future__ import annotations

from winmend.diagnostics.helpers import _evidence, _plural
import os
from winmend.diagnostics.observations import split_results, unknown_findings
from winmend.diagnostics.measurements import conservative_legacy, resource_findings, network_findings


class CaseAssessmentMixin:
    """CaseEngine methods grouped by responsibility."""

    # -- evidence -> findings ---------------------------------------------

    def _findings(self, raw):
        clean, _unavailable = split_results(raw)
        normalized_raw = dict(raw)
        try:
            legacy = self._legacy_findings(clean)
        except (TypeError, ValueError, KeyError, IndexError, AttributeError):
            # Isolate malformed provider payloads; preserve the other results.
            malformed = []
            for name, value in clean.items():
                try:
                    self._legacy_findings({name: value})
                except (TypeError, ValueError, KeyError, IndexError, AttributeError):
                    malformed.append(name)
            if not malformed:
                malformed = list(clean)
            for name in malformed:
                clean.pop(name, None)
                normalized_raw[name] = {"available": False, "diagnostic_state": "collection_failed",
                                        "reason": "Provider returned a malformed measurement"}
            legacy = self._legacy_findings(clean)
        out = conservative_legacy(legacy, clean)
        out.extend(resource_findings(clean.get("performance_samples", {})))
        out.extend(network_findings(clean.get("layered_network", {})))
        out.extend(unknown_findings(normalized_raw, out))
        return out

    def _legacy_findings(self, raw):
        """Turn raw collector output into the finding rows the UI shows.

        Deliberately not scoped by profile: every collector that produced data
        gets a row. What the user complained about steers which *rules* run and
        what gets planned, never what gets reported as measured.

        Only measurements get warn/bad. Anything that is context rather than a
        measurement is info, so that verification never reports a successful
        repair as unresolved.
        """
        out = []

        disk = raw.get("disk") or {}
        if disk:
            free_pct = disk.get("free_pct", 0)
            status = "bad" if free_pct < 8 else "warn" if free_pct < 18 else "good"
            out.append(_evidence(
                "disk_free", "System drive free space", status,
                f"{disk.get('free_gb', 0):.1f} GB ({free_pct:.0f}%)",
                "Windows needs working room for updates, caches, and virtual memory.",
                data=disk, task_ids=("clean_temp", "disk_cleanup")))

        others = (raw.get("volumes") or {}).get("others")
        if (raw.get("volumes") or {}).get("available"):
            if others:
                worst = min(others, key=lambda v: v["free_pct"])
                status = ("bad" if worst["free_pct"] < 5 else
                          "warn" if worst["free_pct"] < 12 else "good")
                label = f"{worst['drive']} {worst['label']}".strip()
                value = (f"{label} is the fullest: {worst['free_gb']:.0f} GB free "
                         f"({worst['free_pct']:.0f}%)")
            else:
                status, value = "info", "none -- this PC has one fixed drive"
            out.append(_evidence(
                "volumes", "Other fixed drives", status, value,
                "Every fixed drive is measured, not only the one Windows is installed on.",
                data=raw["volumes"], task_ids=("disk_cleanup",)))

        filesystem = raw.get("filesystem_health") or {}
        dirty = [v["drive"] for v in ((raw.get("volumes") or {}).get("volumes") or [])
                 if v.get("dirty")]
        if filesystem.get("available"):
            scheduled = filesystem.get("scheduled") or []
            flagged = sorted(set(scheduled) | set(dirty))
            out.append(_evidence(
                "filesystem", "File system consistency",
                "bad" if flagged else "good",
                (", ".join(flagged) + " flagged for a disk check" if flagged
                 else "no volume is flagged"),
                "Windows marks a volume when it finds structural damage it has not repaired yet.",
                data={"scheduled": scheduled, "dirty": dirty,
                      "boot_execute": filesystem.get("boot_execute", "")},
                task_ids=("chk_dsk",)))

        temp = raw.get("temp_size") or {}
        if temp:
            temp_gb = temp.get("bytes", 0) / 1024 ** 3
            out.append(_evidence(
                "temp_size", "Temporary data", "warn" if temp_gb >= 0.5 else "good",
                f"at least {temp_gb:.2f} GB" if temp.get("partial") else f"{temp_gb:.2f} GB",
                "Only Windows and user temporary folders were measured.",
                data={"gb": temp_gb}, task_ids=("clean_temp",)))

        memory = raw.get("memory") or {}
        if memory:
            used = memory.get("used_pct", 0)
            status = "bad" if used >= 93 else "warn" if used >= 82 else "good"
            out.append(_evidence(
                "memory", "Current memory pressure", status, f"{used:.0f}% used",
                "A snapshot identifies pressure, not the program responsible.",
                data=memory, task_ids=("pc_report",)))

        cpu = raw.get("cpu_load") or {}
        if cpu.get("available"):
            hog = cpu.get("hog")
            listing = ", ".join(f"{p['name']} {p['pct']:.0f}%" for p in (cpu.get("top") or [])
                                if not p.get("ours")) or "nothing significant"
            # Deliberately informational. This sweep runs a couple of dozen
            # queries at once, so a high reading here is as likely to be the
            # check itself as a fault, and a one-second sample cannot tell the
            # difference between a runaway process and a busy one.
            out.append(_evidence(
                "cpu_load", "Processor load right now", "info",
                f"{cpu.get('used_pct', 0):.0f}% across {_plural(cpu.get('cores', 1), 'core')}",
                (f"Busiest: {listing}. A single snapshot -- a program that is meant to be "
                 f"working will look the same as one that is stuck."
                 if hog else f"Busiest: {listing}."),
                data=cpu, task_ids=()))

        entries = raw.get("startup_entries") or {}
        if entries.get("available") or "startup_count" in raw:
            # Count what actually launches. The raw registry count includes
            # entries Windows has flagged as disabled, so after a successful
            # "disable startup apps" it would still report the old number and
            # verification would call a working repair a failure.
            if entries.get("available"):
                enabled = entries.get("enabled") or []
                count = len(enabled)
                total = len(entries.get("entries") or [])
                value = (f"{count} enabled" + (f" of {total}" if total != count else ""))
                detail = ("Too many automatic programs slow sign-in and keep memory busy. "
                          "Disabled entries are not counted.")
                data = {"count": count, "total": total,
                        "names": [e.get("name", "") for e in enabled][:12]}
            else:
                count = raw.get("startup_count") or 0
                value = str(count)
                detail = "Too many automatic programs slow sign-in and keep memory busy."
                data = {"count": count}
            status = "bad" if count >= 18 else "warn" if count >= 9 else "good"
            out.append(_evidence("startup", "Startup entries", status, value, detail,
                                 data=data, task_ids=("disable_startup_apps",)))

        if "uptime_days" in raw:
            days = raw.get("uptime_days") or 0
            out.append(_evidence(
                "uptime", "Time since a full restart", "warn" if days >= 7 else "good",
                f"{days:.1f} days",
                "A restart clears stuck services and completes pending maintenance.",
                data={"days": days}, task_ids=("restart_windows",)))

        restart = raw.get("restart_pending") or {}
        if restart.get("available") or "pending_reboot" in raw:
            # The detailed collector is preferred when it ran, because "restart
            # pending" on its own invites the reasonable question "pending for
            # what?", and the answer changes whether it matters.
            if restart.get("available"):
                reasons = restart.get("reasons") or []
                pending = bool(restart.get("pending"))
                value = "; ".join(reasons) if reasons else "no"
                detail = ("Some updates cannot finish until Windows restarts."
                          if pending else
                          f"Nothing is waiting on a restart. "
                          f"({_plural(restart.get('queued_renames', 0), 'file')} queued to be "
                          f"replaced at the next boot, which is normal.)")
                data = restart
            else:
                pending = bool(raw.get("pending_reboot"))
                value = "yes" if pending else "no"
                detail = "Some updates cannot finish until Windows restarts."
                data = {"pending": pending}
            out.append(_evidence(
                "pending_reboot", "Pending restart", "warn" if pending else "good",
                value, detail, data=data, task_ids=("restart_windows",)))

        version = raw.get("windows_version") or {}
        if version.get("available"):
            supported = version.get("supported")
            out.append(_evidence(
                "windows_version", "Windows version",
                "bad" if supported is False else "good" if supported else "info",
                f"{version['label']}" + (f", supported until {version['eol']}" if version.get("eol") else ""),
                "Out-of-service versions stop receiving security fixes.",
                data=version, task_ids=("windows_updates",)))

        smart = raw.get("smart_health") or {}
        if smart.get("available"):
            unhealthy = smart.get("unhealthy") or []
            out.append(_evidence(
                "smart", "Drive hardware health (SMART)", "bad" if unhealthy else "good",
                "; ".join(unhealthy) if unhealthy else f"{smart.get('disks', 0)} drive(s) healthy",
                "A failing drive explains slowness, freezes, and crashes better than software.",
                data=smart, task_ids=("disk_smart_check",)))

        reliability = raw.get("disk_reliability") or {}
        if reliability.get("available"):
            disks = reliability.get("disks") or []
            worn = [d for d in disks if (d.get("wear_pct") or 0) >= 80]
            erroring = [d for d in disks if (d.get("read_errors") or 0)
                        or (d.get("write_errors") or 0)]
            unhealthy = [d for d in disks if d.get("health")
                         and d["health"].lower() not in ("healthy", "")]
            if not reliability.get("counters_readable"):
                # Without elevation the drive list reads but its counters do
                # not, and "0% worn" would be an invention rather than a
                # measurement.
                status = "bad" if unhealthy else "info"
                value = (f"{unhealthy[0]['name']}: {unhealthy[0]['health']}" if unhealthy
                         else f"{_plural(len(disks), 'drive')}, wear needs administrator")
            elif worn or erroring or unhealthy:
                status = "bad"
                target = (worn or erroring or unhealthy)[0]
                value = (f"{target['name']}: "
                         + (f"{target['wear_pct']}% of rated life used" if target.get("wear_pct")
                            else f"{(target.get('read_errors') or 0) + (target.get('write_errors') or 0)} "
                                 f"uncorrected errors"))
            else:
                status = "good"
                hottest = max((d for d in disks if d.get("temperature_c")),
                              key=lambda d: d["temperature_c"], default=None)
                value = (f"{_plural(len(disks), 'drive')} within limits"
                         + (f", hottest {hottest['temperature_c']} C" if hottest else ""))
            out.append(_evidence(
                "drive_wear", "Drive wear and error counters", status, value,
                "The numbers behind the SMART pass/fail flag, which is often the last thing to change.",
                data=reliability, task_ids=("disk_smart_check",)))

        removals = raw.get("storage_removals") or {}
        if removals.get("available"):
            count = removals.get("events", 0)
            # Collected since the first version of this engine and used by
            # rule_failing_drive, but never shown until now -- the user could
            # not see the evidence a critical verdict rested on.
            out.append(_evidence(
                "storage_faults", "Drive resets and surprise removals (14 days)",
                "bad" if count >= 3 else "warn" if count else "good", str(count),
                "A drive that drops off the bus and comes back is failing, loose, or losing power.",
                data=removals, task_ids=("disk_smart_check",)))

        events = raw.get("event_log_errors") or {}
        if events.get("available"):
            for key, label, field, detail, tasks in (
                ("evt_shutdowns", "Unexpected shutdowns (7 days)", "unexpected_shutdowns",
                 "Kernel-Power 41: the PC crashed or lost power without a clean shutdown.",
                 ("bsod_triage",)),
                ("evt_hardware", "Hardware error events (7 days)", "hardware_errors",
                 "WHEA events are CPU, memory, or bus faults reported by the hardware itself.",
                 ("ram_quick_test",)),
                ("evt_disk", "Disk error events (7 days)", "disk_errors",
                 "Bad blocks or failed IO logged by the storage driver.",
                 ("disk_smart_check",)),
            ):
                count = events.get(field, 0)
                out.append(_evidence(key, label, "bad" if count else "good", str(count),
                                     detail, data={"count": count}, task_ids=tasks))
            crashes = events.get("service_crashes", 0)
            out.append(_evidence(
                "evt_services", "Service crashes (7 days)", "warn" if crashes else "good",
                str(crashes), "Windows services that terminated unexpectedly.",
                data={"count": crashes}, task_ids=("service_dependency_repair",)))

        bugchecks = raw.get("bugchecks") or {}
        if bugchecks.get("available"):
            crashes = bugchecks.get("crashes") or []
            top = crashes[0] if crashes else None
            out.append(_evidence(
                "bugchecks", "Recorded stop codes (30 days)", "bad" if crashes else "good",
                (f"{len(crashes)} -- most recent {top['code']} {top['name']}" if top
                 else "none"),
                (top["cause"] if top else "No blue-screen stop codes were recorded."),
                data=bugchecks, task_ids=("bsod_triage", "minidump_analyzer")))

        dumps = raw.get("dump_files") or {}
        if dumps.get("available"):
            count = dumps.get("count", 0)
            newest = (dumps.get("dumps") or [None])[0]
            out.append(_evidence(
                "crash_dumps", "Crash dump files on disk", "warn" if count else "good",
                (f"{count}, newest {newest['days_ago']:.0f} days ago" if newest else "none"),
                ("A dump file names the driver that crashed, which the event log entry does not."
                 if count else "Windows writes one of these every time it stops unexpectedly."),
                data=dumps, task_ids=("minidump_analyzer",)))

        services = raw.get("service_health") or {}
        if services.get("available"):
            broken = services.get("critical_stopped") or []
            idle = services.get("stopped_auto") or []
            out.append(_evidence(
                "services", "Essential Windows services",
                "bad" if broken else "good",
                (f"{broken[0]['display']} is stopped"
                 + (f" and {len(broken) - 1} more" if len(broken) > 1 else "")
                 if broken else f"all running, of {services.get('total', 0)} installed"),
                (f"{_plural(len(idle), 'other automatic service')} not running, which is normal "
                 f"-- Windows starts most of those only when something needs them."),
                data=services, task_ids=("service_dependency_repair",)))

        tasks = raw.get("scheduled_tasks") or {}
        if tasks.get("available"):
            failures = tasks.get("failures") or []
            maintenance = tasks.get("maintenance_failures") or []
            # Only Windows' own maintenance tasks can raise this above info. A
            # leftover updater from an uninstalled program fails forever and
            # tells the user nothing.
            out.append(_evidence(
                "scheduled_tasks", "Scheduled tasks",
                "warn" if maintenance else "info",
                (f"{maintenance[0]['task'].rsplit(chr(92), 1)[-1]} last failed with "
                 f"{maintenance[0]['code']}" if maintenance
                 else f"{len(failures)} failed at their last run" if failures
                 else "none failing"),
                ("A Windows maintenance task that cannot run means the upkeep it does "
                 "silently stopped happening." if maintenance else
                 "Most of these are leftovers from uninstalled software and are harmless."),
                data=tasks, task_ids=("scheduled_task_audit",) if maintenance else ()))

        gpu = raw.get("gpu_resets") or {}
        if gpu.get("available"):
            count = gpu.get("count", 0)
            out.append(_evidence(
                "gpu_resets", "Display driver resets (14 days)",
                "bad" if count >= 3 else "warn" if count else "good", str(count),
                "The display driver stopped responding and Windows restarted it.",
                data=gpu, task_ids=("gpu_diagnostic",)))

        crashes = raw.get("app_crashes") or {}
        if crashes.get("available"):
            items = crashes.get("crashes") or []
            worst = items[0] if items else None
            out.append(_evidence(
                "app_crashes", "Application crashes (14 days)",
                "warn" if worst and worst.get("count", 0) >= 2 else "good",
                (f"{worst['app']} x{worst['count']}" + (f" in {worst['module']}" if worst.get("module") else "")
                 if worst else "none"),
                "Windows records which component an application died inside.",
                data=crashes, task_ids=("reliability_monitor",)))

        devices = raw.get("problem_devices") or {}
        if devices.get("available"):
            broken = devices.get("devices") or []
            serious = [d for d in broken if d.get("problem_code") in (10, 31, 43, 39, 19, 1, 3, 18, 52, 54)]
            out.append(_evidence(
                "problem_devices", "Devices Windows has flagged",
                "bad" if serious else "warn" if broken else "good",
                (f"{serious[0]['name']} (code {serious[0]['problem_code']})" if serious
                 else f"{len(broken)} minor" if broken else "none"),
                "Device Manager problem codes name the exact hardware Windows cannot use.",
                data=devices, task_ids=()))

        thermal = raw.get("thermal_events") or {}
        if thermal.get("available"):
            count = thermal.get("throttle_events", 0)
            out.append(_evidence(
                "thermal", "Thermal throttling (14 days)",
                "bad" if count >= 10 else "warn" if count >= 3 else "good", str(count),
                "The CPU slowed itself down to stay within its temperature limit.",
                data=thermal, task_ids=()))

        updates = raw.get("update_failures") or {}
        if updates.get("available"):
            failures = updates.get("failures") or []
            top = failures[0] if failures else None
            out.append(_evidence(
                "update_failures", "Windows Update failures (30 days)",
                "bad" if failures else "good",
                (f"{len(failures)}, most recent {top['code']}" if top else "none"),
                (top.get("meaning") or "Update install failures recorded by Windows." if top
                 else "No update failures were recorded."),
                data=updates, task_ids=("windows_update_forensic",)))

        recent = raw.get("installed_updates") or {}
        if recent.get("available"):
            items = recent.get("updates") or []
            out.append(_evidence(
                "recent_updates", "Updates installed recently", "info",
                (", ".join(f"{u['kb']} ({u['days_ago']:.0f}d ago)" for u in items[:3])
                 if items else "none in the last 45 days"),
                "Anything installed just before the symptom started is a suspect.",
                data=recent, task_ids=()))

        update_state = raw.get("update_state") or {}
        if update_state.get("available"):
            policies = update_state.get("policies") or []
            paused = update_state.get("paused_until")
            disabled = [name for name, entry in (update_state.get("services") or {}).items()
                        if entry.get("disabled")]
            if policies or disabled:
                status = "bad"
                value = (policies[0]["meaning"] if policies
                         else f"the {disabled[0]} service is disabled")
            elif paused:
                status, value = "warn", f"paused until {paused[:10]}"
            else:
                status, value = "good", "able to run"
            out.append(_evidence(
                "update_state", "Windows Update availability", status, value,
                ("A PC that cannot fetch updates stops receiving security fixes, and nothing "
                 "in Windows says so plainly."),
                data=update_state, task_ids=("reset_win_update", "windows_updates")))

        drivers = raw.get("third_party_drivers") or {}
        if drivers.get("available"):
            items = drivers.get("recent") or []
            out.append(_evidence(
                "recent_drivers", "Drivers installed recently", "info",
                (", ".join(f"{d.get('original') or d['published']} ({d['days_ago']:.0f}d ago)"
                           for d in items[:3]) if items else "none in the last 45 days"),
                f"{drivers.get('total', 0)} third-party driver packages are installed in total.",
                data=drivers, task_ids=()))

        programs = raw.get("installed_programs") or {}
        if programs.get("available"):
            items = programs.get("programs") or []
            out.append(_evidence(
                "recent_programs", "Programs installed recently", "info",
                (", ".join(p["name"] for p in items[:3]) if items else "none in the last 45 days"),
                "New software is the most common cause of a PC that changed behaviour.",
                data=programs, task_ids=()))

        store = raw.get("component_store_health") or {}
        if store.get("available"):
            state = store.get("state", "unknown")
            out.append(_evidence(
                "component_store", "Windows component store",
                "bad" if state in ("repairable", "unrepairable") else "good" if state == "clean" else "info",
                state, "Component corruption breaks updates and Windows features.",
                data=store, task_ids=("repair_system",)))

        pagefile = raw.get("pagefile") or {}
        if pagefile.get("available"):
            disabled = pagefile.get("disabled")
            out.append(_evidence(
                "pagefile", "Virtual memory (page file)", "bad" if disabled else "good",
                "disabled" if disabled else f"{pagefile.get('size_mb', 0):,} MB",
                "Windows expects a page file even on a PC with plenty of RAM.",
                data=pagefile, task_ids=()))

        proxy = raw.get("proxy_settings") or {}
        if proxy.get("available"):
            active = proxy.get("pac_or_proxy")
            out.append(_evidence(
                "proxy", "Proxy configuration", "warn" if active else "good",
                (proxy.get("server") or proxy.get("autoconfig") or "set") if active else "none",
                "A proxy nobody configured deliberately is a common cause of broken browsing.",
                data=proxy, task_ids=()))

        hosts = raw.get("hosts_file") or {}
        if hosts.get("available"):
            blocked = hosts.get("blocked") or []
            out.append(_evidence(
                "hosts", "Hosts file", "bad" if blocked else "good",
                (f"{len(blocked)} security/update domains redirected" if blocked
                 else f"{hosts.get('entries', 0)} entries"),
                "The hosts file can silently redirect any website name.",
                data=hosts, task_ids=()))

        dns = raw.get("dns_servers") or {}
        if dns.get("available"):
            unknown = dns.get("unrecognised") or []
            names = []
            for entry in dns.get("interfaces", []):
                for server in entry.get("servers", []):
                    names.append(server["known"] or server["address"])
            detail = "DNS decides which server every website name points at."
            if unknown:
                detail += " Some were set on this PC and are not a known public resolver."
            elif dns.get("from_network"):
                detail += (" Some unfamiliar ones come from the network itself -- usually "
                           "your internet provider's own resolvers, handed out by the router.")
            out.append(_evidence(
                "dns_config", "DNS servers", "warn" if unknown else "good",
                ", ".join(dict.fromkeys(names))[:80] or "automatic",
                detail, data=dns, task_ids=("flush_dns",)))

        network = raw.get("network") or {}
        if network:
            out.extend((
                _evidence("adapters", "Active network adapters",
                          "good" if network.get("adapters") else "bad", str(network.get("adapters", 0)),
                          "At least one non-loopback adapter should be active.",
                          data=network, task_ids=("network_adapter_reset",)),
                _evidence("dns", "DNS name lookup", "good" if network.get("dns") else "bad",
                          "working" if network.get("dns") else "failed",
                          "Tests whether a website name resolves to an address.",
                          data=network, task_ids=("flush_dns",)),
                _evidence("reachability", "Direct internet reachability",
                          "good" if network.get("reachable") else "bad",
                          "working" if network.get("reachable") else "failed",
                          "Tests a direct connection without relying on DNS.",
                          data=network, task_ids=("network_diagnostic_bundle",)),
            ))

        quality = raw.get("ping_quality") or {}
        if quality.get("avg_ms") is not None or quality.get("failures"):
            avg = quality.get("avg_ms")
            failures = quality.get("failures", 0)
            status = ("bad" if failures >= 2 else
                      "warn" if failures or (avg is not None and avg >= 150) else "good")
            out.append(_evidence(
                "net_quality", "Connection quality", status,
                (f"{avg:.0f} ms average, {failures}/{quality.get('attempts', 0)} failed"
                 if avg is not None else f"{failures}/{quality.get('attempts', 0)} failed"),
                "Round-trip time and failure rate over repeated direct connections.",
                data=quality, task_ids=("network_diagnostic_bundle",)))

        ip = raw.get("network_config") or {}
        if ip.get("available"):
            interfaces = ip.get("interfaces") or []
            stranded = [i for i in interfaces if i["self_assigned"]]
            if ip.get("self_assigned_only"):
                status = "bad"
                value = "no address from the router (self-assigned only)"
            elif not ip.get("has_route") and interfaces:
                status, value = "bad", "an address, but no way out of this network"
            else:
                status = "good"
                routed = [i for i in interfaces if i["gateway"]]
                value = (f"{routed[0]['address']} via {routed[0]['gateway']}"
                         if routed else "configured")
            out.append(_evidence(
                "ip_config", "Network addressing", status, value,
                ("A 169.254 address means the router never answered. "
                 f"({_plural(len(stranded), 'other adapter')} sitting unused, which is normal "
                 f"for an unplugged port.)" if stranded else
                 "The address and default gateway decide whether anything can be reached."),
                data=ip, task_ids=("ipconfig_all", "reset_network")))

        link = raw.get("adapter_health") or {}
        if link.get("available"):
            adapters = link.get("adapters") or []
            degraded = link.get("degraded") or []
            fastest = max(adapters, key=lambda a: a["speed_mbps"], default=None)
            out.append(_evidence(
                "link_health", "Network adapter errors",
                "warn" if degraded else "good",
                (f"{degraded[0]['name']}: {degraded[0]['error_pct']}% of packets dropped or errored"
                 if degraded else
                 f"clean" + (f", {fastest['name']} linked at {fastest['speed_mbps']} Mbps"
                             if fastest and fastest["speed_mbps"] else "")),
                "Counted since the last restart. A bad cable or port shows up here and nowhere else.",
                data=link, task_ids=("network_adapter_reset",)))

        clock = raw.get("time_sync") or {}
        if clock.get("available"):
            offset = clock.get("offset_seconds", 0)
            drift = abs(offset)
            # HTTPS certificate validation starts failing within a few minutes
            # of drift, which presents as "the internet is broken", not as a
            # clock problem.
            status = "bad" if drift >= 300 else "warn" if drift >= 60 else "good"
            out.append(_evidence(
                "time_sync", "System clock accuracy", status,
                (f"{'ahead' if offset < 0 else 'behind'} by {drift:.0f} seconds"
                 if drift >= 1 else "correct to within a second"),
                f"Measured against {clock.get('source', 'an internet time server')}. "
                f"A wrong clock breaks secure websites, updates, and sign-in.",
                data=clock, task_ids=("time_sync_fix",)))

        wifi = raw.get("wifi_link") or {}
        if wifi.get("available"):
            signal = wifi.get("signal_pct")
            status = ("bad" if signal is not None and signal < 30
                      else "warn" if signal is not None and signal < 45 else "good")
            out.append(_evidence(
                "wifi_link", "Wi-Fi signal", status,
                f"{signal}% on {wifi.get('band') or 'unknown band'}" if signal is not None else "connected",
                f"Connected to {wifi.get('ssid', 'a network')} at {wifi.get('rx_mbps', '?')} Mbps.",
                data=wifi, task_ids=("wlan_report",)))

        defender = raw.get("defender") or {}
        if defender.get("available"):
            healthy = defender.get("enabled") and defender.get("realtime")
            age = defender.get("signature_age")
            out.append(_evidence(
                "defender", "Microsoft Defender protection", "good" if healthy else "bad",
                f"real-time {'on' if defender.get('realtime') else 'off'}, "
                f"signatures {age if age is not None else '?'} day(s) old",
                "Real-time protection and current signatures reduce exposure.",
                data=defender, task_ids=("defender_scan",)))
        elif "defender" in raw:
            out.append(_evidence("defender", "Microsoft Defender protection", "info",
                                 "not available",
                                 "Another antivirus product may be registered on this PC.",
                                 data={}, task_ids=("defender_scan",)))

        threats = raw.get("defender_threats") or {}
        if threats.get("available"):
            unresolved = threats.get("unresolved") or []
            history = threats.get("history", 0)
            quick = threats.get("quick_scan_age")
            if unresolved:
                status = "bad"
                value = f"{unresolved[0]['name']} -- {unresolved[0]['state']}"
            elif quick is None or quick > 14:
                status = "warn"
                value = ("never scanned" if quick is None
                         else f"last scan {_plural(quick, 'day')} ago")
            else:
                status = "good"
                value = (f"nothing outstanding, last scan {_plural(quick, 'day')} ago"
                         if quick else "nothing outstanding, scanned today")
            out.append(_evidence(
                "threats", "Malware detections", status, value,
                (f"{_plural(history, 'item')} in Defender's history. Something detected but "
                 f"not removed is still on this PC." if history else
                 "Defender has not recorded any detection on this PC."),
                data=threats, task_ids=("defender_scan", "msrt_scan")))

        profiles = raw.get("firewall_profiles") or {}
        if profiles.get("available") or "firewall_enabled" in raw:
            if profiles.get("available"):
                off = profiles.get("disabled") or []
                allow = profiles.get("allow_inbound") or []
                status = "bad" if off or allow else "good"
                value = (", ".join(off) + " turned off" if off
                         else ", ".join(allow) + " allows all inbound" if allow
                         else f"all {len(profiles.get('profiles', []))} profiles on")
                detail = ("Naming the profile matters: the Public one is what protects this PC "
                          "on someone else's network.")
                data = profiles
            else:
                firewall = raw.get("firewall_enabled")
                status = ("good" if firewall is True else
                          "bad" if firewall is False else "info")
                value = ("enabled" if firewall is True else
                         "disabled" if firewall is False else "unavailable")
                detail = "All active profiles should normally have a firewall enabled."
                data = {"enabled": firewall}
            out.append(_evidence("firewall", "Windows Firewall profiles", status, value,
                                 detail, data=data, task_ids=("firewall_audit",)))

        uac = raw.get("uac_state") or {}
        if uac.get("available"):
            if not uac.get("enabled"):
                status, value = "bad", "turned off"
            elif uac.get("never_notifies"):
                status, value = "warn", "on, but set never to ask"
            else:
                status, value = "good", "on"
            out.append(_evidence(
                "uac", "User Account Control", status, value,
                ("With UAC off, every program you run has full administrator rights without "
                 "asking. It is the single setting that most changes what malware can do."),
                data=uac, task_ids=("security_posture_report",)))

        exclusions = raw.get("defender_exclusions") or {}
        if exclusions.get("available"):
            broad = exclusions.get("overly_broad") or []
            out.append(_evidence(
                "defender_exclusions", "Defender scan exclusions",
                "bad" if broad else "good",
                (f"{len(broad)} very broad" if broad
                 else f"{len(exclusions.get('paths', []))} paths"),
                "Broad exclusions hide whatever is inside them from every scan.",
                data=exclusions, task_ids=("security_posture_report",)))

        platform = raw.get("platform_security") or {}
        if platform.get("available"):
            bits = []
            if platform.get("secure_boot") in ("true", "false"):
                bits.append(f"Secure Boot {'on' if platform['secure_boot'] == 'true' else 'off'}")
            if platform.get("tpm_present") is not None:
                bits.append(f"TPM {'present' if platform['tpm_present'] else 'absent'}")
            if platform.get("activated") is not None:
                bits.append("activated" if platform["activated"] else "not activated")
            if bits:
                out.append(_evidence(
                    "platform", "Platform security",
                    "warn" if platform.get("activated") is False else "info",
                    ", ".join(bits),
                    "Secure Boot, TPM, and activation state for this PC.",
                    data=platform, task_ids=("security_posture_report",)))

        battery = raw.get("battery_wear") or {}
        if battery.get("available"):
            wear = battery.get("wear_pct", 0)
            out.append(_evidence(
                "battery_wear", "Battery capacity remaining",
                "bad" if wear >= 40 else "warn" if wear >= 25 else "good",
                f"{100 - wear:.0f}% of original",
                "Batteries lose capacity with age; below ~70% the runtime drop is obvious.",
                data=battery, task_ids=("battery_health_report",)))

        config = raw.get("memory_config") or {}
        if config.get("available"):
            out.append(_evidence(
                "memory_config", "Installed memory", "info",
                f"{config['total_gb']:.0f} GB in {_plural(config['count'], 'module')}"
                + (f" at {config['actual_mhz']} MHz" if config.get("actual_mhz") else ""),
                ("Single-channel: a second matching module would roughly double bandwidth."
                 if config.get("single_channel") else
                 f"Running below the rated {config['rated_mhz']} MHz."
                 if config.get("underclocked") else "Running in its normal configuration."),
                data=config, task_ids=()))

        top = raw.get("top_memory_processes") or []
        if top:
            listing = ", ".join(
                f"{p['name']} {p['mb'] / 1024:.1f} GB" if p["mb"] >= 1024
                else f"{p['name']} {p['mb']:.0f} MB" for p in top)
            out.append(_evidence("top_memory", "Largest memory users", "info", listing,
                                 "The programs holding the most memory right now.",
                                 data={"processes": top}, task_ids=()))

        boot = raw.get("boot_history") or {}
        if boot.get("available"):
            boots = boot.get("boots") or []
            if boots:
                latest = boots[0]
                seconds = latest.get("desktop_s", 0)
                out.append(_evidence(
                    "boot_time", "Last measured startup time",
                    "bad" if seconds > 120 else "warn" if seconds > 60 else "good",
                    f"{seconds:.0f} seconds to the desktop",
                    "Windows measures this itself on every boot.",
                    data=boot, task_ids=("boot_time_analyzer",)))

        latency = raw.get("disk_latency") or {}
        if latency.get("available") and not latency.get("idle") and latency.get("avg_ms") is not None:
            avg = latency["avg_ms"]
            out.append(_evidence(
                "disk_latency", "Disk responsiveness",
                "bad" if avg >= 40 else "warn" if avg >= 15 else "good",
                f"{avg:.1f} ms per operation",
                "Sampled live. Sustained high service times mean the drive is the bottleneck.",
                data=latency, task_ids=()))

        points = raw.get("restore_points") or {}
        if points.get("available"):
            items = points.get("points") or []
            newest = items[0] if items else None
            protection = points.get("protection")
            out.append(_evidence(
                "restore_points", "System Restore points",
                "warn" if not items or protection is False else "info",
                ("turned off" if protection is False and not items else
                 f"turned off, {len(items)} old point(s) remain" if protection is False else
                 f"{len(items)}, newest {newest['days_ago']:.0f} days ago" if newest
                 else "none available"),
                ("System Protection is switched off, so Windows is not keeping checkpoints."
                 if protection is False else
                 "No restore point exists, so there is nothing to roll back to."
                 if not items else "Restore points available to roll back to."),
                data=points, task_ids=("create_restore_point_guardrail",)))

        power = raw.get("power_config") or {}
        if power.get("available"):
            # Power saver is only a fault when there is no battery reason for
            # it. On a laptop running on battery it is the correct setting, and
            # flagging it would be arguing with the user about their own choice.
            saver = bool(power.get("power_saver")) and not power.get("on_battery")
            out.append(_evidence(
                "power_plan", "Power plan", "warn" if saver else "info",
                power.get("name") or "unknown",
                (("Power saver caps the processor. On a desktop it is almost always a mistake, "
                  "and nothing in Windows tells you it is on.") if saver else
                 "Power saver is on while running on battery, which is what it is for."
                 if power.get("power_saver") else
                 "Fast startup is "
                 + ("on, so a shutdown does not fully restart Windows."
                    if power.get("fast_startup") else "off, so shutdown fully restarts Windows.")),
                data=power, task_ids=("power_plan_switcher",)))

        search = raw.get("search_index") or {}
        if search.get("available"):
            if search.get("disabled") and not search.get("healthy"):
                # A setting, not a failure: say what it is without a warning.
                out.append(_evidence(
                    "search_index", "Windows Search index", "info",
                    "switched off (the service is set to Disabled)",
                    "Start-menu and File Explorer search read from this index. Some tools "
                    "switch it off to save memory; searches still work, only more slowly "
                    "and less completely.",
                    data=search, task_ids=("reset_search_index",)))
            else:
                out.append(_evidence(
                    "search_index", "Windows Search index",
                    "good" if search.get("healthy") else "warn",
                    ("working" if search.get("healthy") else
                     f"the service is {search.get('service', 'unknown')}"
                     if search.get("service") != "running" else "the index was never built"),
                    "Start-menu and File Explorer search both read from this index.",
                    data=search, task_ids=("reset_search_index",)))

        printers = raw.get("printers") or {}
        if printers.get("available"):
            offline = printers.get("default_offline") or []
            stuck = printers.get("jobs", 0)
            spooler = printers.get("spooler", "unknown")
            installed = printers.get("printers") or []
            if spooler == "stopped" and installed:
                status, value = "bad", "the print spooler is stopped"
            elif offline:
                status, value = "warn", f"the default printer ({offline[0]['name']}) is offline"
            else:
                status = "good"
                value = (f"{_plural(len(installed), 'printer')}, "
                         f"{_plural(stuck, 'job')} queued" if installed else "none installed")
            out.append(_evidence(
                "printers", "Printing", status, value,
                "Only the default printer is judged -- one used once at an old address stays offline.",
                data=printers, task_ids=("clear_print_spooler",)))

        profile = raw.get("user_profile") or {}
        if profile.get("available"):
            temporary = profile.get("temporary")
            folders = profile.get("onedrive_folders") or []
            out.append(_evidence(
                "user_profile", "Windows user profile",
                "bad" if temporary else "info",
                ("signed in to a temporary profile" if temporary
                 else os.path.basename(str(profile.get("path", "")).rstrip("\\")) or "normal"),
                ("Windows could not load the real profile and made a blank one. Files saved in "
                 "this session are discarded at sign-out, and the real files are still there."
                 if temporary else
                 (", ".join(folders) + " are stored in OneDrive." if folders
                  else "A normal local profile.")),
                data=profile, task_ids=()))

        whea = raw.get("whea_errors") or {}
        if whea.get("available"):
            uncorrected = whea.get("uncorrected", 0)
            total = whea.get("count", 0)
            area = whea.get("worst_area", "")
            status = "bad" if uncorrected else "warn" if total >= 5 else "good"
            if total:
                spread = ", ".join(f"{name}: {count}" for name, count
                                   in sorted(whea.get("areas", {}).items()))
                value = f"{_plural(total, 'error')} ({spread})"
            else:
                value = "none recorded"
            out.append(_evidence(
                "hardware_errors", "Hardware errors reported by the machine", status, value,
                ("These come from the hardware itself, not from Windows. An uncorrected one "
                 "means a component failed and could not recover."
                 if uncorrected else
                 "Corrected errors mean the hardware caught the fault and carried on. A few "
                 "over a month is normal; a steady stream is a component going."
                 if total else
                 "The processor, memory, and PCI Express slots have reported no faults."),
                data=whea, task_ids=("pc_report", "memory_diagnostic")))

        memtest = raw.get("memory_diagnostic") or {}
        if memtest.get("available"):
            if memtest.get("failed"):
                status, value = "bad", "Windows' memory test found faulty memory"
            elif memtest.get("ever_run"):
                status = "good"
                value = f"last run passed ({_plural(memtest.get('runs', 0), 'run')} on record)"
            else:
                status, value = "info", "never run on this PC"
            out.append(_evidence(
                "memory_test", "Windows memory diagnostic", status, value,
                ("A failed memory test is as definite as diagnosis gets. Faulty memory has to "
                 "be replaced -- no software change repairs it."
                 if memtest.get("failed") else
                 "Windows can test the memory during a restart. Nothing has run it here, so "
                 "the memory is unproven rather than proven good."
                 if not memtest.get("ever_run") else
                 "The built-in test found no faults the last time it ran."),
                data=memtest, task_ids=("memory_diagnostic",)))

        throttle = raw.get("cpu_throttle") or {}
        if throttle.get("available") and throttle.get("processors"):
            processor = throttle["processors"][0]
            ratio = throttle.get("ratio")
            # Snapshot, and every modern CPU idles far below its rated clock on
            # purpose, so this can never carry a warning by itself. The rule
            # that reads it pairs the ratio with the load before it speaks.
            out.append(_evidence(
                "cpu_clock", "Processor speed", "info",
                (f"{processor.get('current_mhz')} MHz of {processor.get('max_mhz')} MHz rated"
                 + (f" ({ratio * 100:.0f}%)" if ratio else "")),
                (f"{processor.get('name', 'The processor')}. Idling low is normal and healthy; "
                 f"staying low while the PC is busy is not."),
                data=throttle, task_ids=("cpu_stress_test",)))

        stability = raw.get("reliability_history") or {}
        if stability.get("available") and stability.get("days"):
            drop = stability.get("drop_date")
            # Informational on purpose. The score falls for ordinary things --
            # an app crashing once, an update installing -- so a low reading is
            # a place to look rather than a fault in itself.
            out.append(_evidence(
                "stability", "Windows stability score", "info",
                (f"{stability.get('current')} out of 10 "
                 f"(averaged {stability.get('recent_avg')} this week "
                 f"against {stability.get('baseline_avg')} before)"),
                (f"Windows' own record of how well this PC has been running. It fell on "
                 f"{drop}, from {stability.get('drop_from')} to {stability.get('drop_to')}, "
                 f"which is a date worth lining up against when the trouble started."
                 if drop else
                 f"Windows' own record of how well this PC has been running, over "
                 f"{_plural(stability.get('days', 0), 'day')}."),
                data={k: v for k, v in stability.items() if k != "series"},
                task_ids=("reliability_monitor",)))

        boot = raw.get("boot_config") or {}
        if boot.get("available"):
            if boot.get("safe_mode_forced"):
                status = "bad"
                value = f"forced into Safe Mode ({boot.get('safeboot')})"
            elif boot.get("integrity_checks_off") or boot.get("test_signing"):
                status = "warn"
                value = "driver signature enforcement is switched off"
            else:
                status, value = "good", "normal"
            out.append(_evidence(
                "boot_config", "Boot configuration", status, value,
                ("Something set this PC to boot into Safe Mode every time. It will keep doing "
                 "that until the setting is removed, no matter how often it is restarted."
                 if boot.get("safe_mode_forced") else
                 "Unsigned drivers are allowed to load. That is deliberate on a developer's "
                 "machine and a serious problem anywhere else."
                 if status == "warn" else
                 "The boot loader is set up normally."),
                data=boot, task_ids=("boot_advanced_options",)))

        fast = raw.get("fast_startup") or {}
        if fast.get("available"):
            # Fast startup is on by default on most PCs that shipped with
            # Windows, so flagging it outright would put a warning on almost
            # every machine. It only matters paired with a symptom.
            out.append(_evidence(
                "fast_startup", "Fast startup", "info",
                "on" if fast.get("enabled") else "off",
                ("Shutting down hibernates the kernel instead of stopping it, so drivers and "
                 "devices keep their state. It is why a restart can fix something that a "
                 "shutdown does not."
                 if fast.get("enabled") else
                 "Shutting down really does stop everything, which is the behaviour most "
                 "troubleshooting assumes."),
                data=fast, task_ids=("disable_fast_startup",)))

        wake = raw.get("wake_history") or {}
        if wake.get("available"):
            source = (wake.get("last_wake") or {}).get("source", "")
            out.append(_evidence(
                "wake_sources", "What last woke this PC", "info",
                source or "nothing recorded",
                ((f"{_plural(wake.get('armed', 0), 'wake timer')} armed."
                  if wake.get("timers_readable") else
                  "Scheduled wake timers cannot be listed without administrator rights.")),
                data=wake, task_ids=("power_plan_switcher",)))

        optimize = raw.get("disk_optimization") or {}
        if optimize.get("available"):
            unhealthy = optimize.get("unhealthy") or []
            trim = optimize.get("trim")
            if unhealthy:
                status = "bad"
                value = ", ".join(f"{v['drive']} {v['health']}" for v in unhealthy)
            elif trim is False:
                status, value = "warn", "TRIM is switched off"
            else:
                status = "good"
                value = (f"{_plural(len(optimize.get('volumes') or []), 'volume')} healthy"
                         + (", TRIM on" if trim else ""))
            out.append(_evidence(
                "disk_optimization", "Drive maintenance", status, value,
                ("Windows reports a volume as not healthy, which is a storage fault rather "
                 "than a full disk."
                 if unhealthy else
                 "Without TRIM an SSD cannot tell the drive which blocks are free, and it gets "
                 "slower over months in a way nothing else explains."
                 if trim is False else
                 "Every fixed volume reports healthy."),
                data=optimize, task_ids=("defrag_optimize",)))

        locker = raw.get("bitlocker_state") or {}
        if locker.get("available"):
            suspended = locker.get("suspended") or []
            encrypted = locker.get("encrypted") or []
            if suspended:
                status = "warn"
                value = ", ".join(v["drive"] for v in suspended) + " suspended"
            elif encrypted:
                status = "good"
                value = ", ".join(v["drive"] for v in encrypted) + " encrypted and protected"
            else:
                status, value = "info", "no drive is encrypted"
            out.append(_evidence(
                "encryption", "Drive encryption", status, value,
                ("The drive is still encrypted but protection is suspended, which means the key "
                 "is stored in the clear. That is the security of no encryption at all, and a "
                 "failed update is the usual reason a PC is left like this."
                 if suspended else
                 "BitLocker is protecting the data on this drive."
                 if encrypted else
                 "Nothing on this PC is encrypted, so anyone with the drive can read it."),
                data=locker, task_ids=("security_posture_report",)))

        disk_busy = raw.get("top_disk_processes") or {}
        if disk_busy.get("available"):
            busiest = disk_busy.get("busiest")
            listing = ", ".join(f"{row['name']} {row['mb_per_sec']:.1f} MB/s"
                                for row in (disk_busy.get("top") or [])) or "nothing significant"
            # A one-second sample, taken while this sweep is itself reading the
            # disk. It names candidates; it does not convict one.
            out.append(_evidence(
                "disk_activity", "What is using the disk", "info",
                (f"{busiest['name']} at {busiest['mb_per_sec']:.1f} MB/s"
                 if busiest else "nothing significant"),
                f"Busiest over one second: {listing}. WinMend's own reads are excluded.",
                data=disk_busy, task_ids=("pc_report",)))

        resolution = raw.get("dns_resolution") or {}
        if resolution.get("available"):
            if resolution.get("attempted") and resolution.get("resolved") == 0:
                status, value = "bad", "no name would resolve"
            elif resolution.get("hijacked"):
                status, value = "bad", "a name that cannot exist resolved anyway"
            elif resolution.get("slow"):
                status, value = "warn", f"slow: {resolution.get('slowest_ms', 0):.0f} ms"
            else:
                status = "good" if resolution.get("attempted") and resolution.get("resolved") == resolution.get("attempted") else "warn" if resolution.get("resolved") else "inconclusive"
                timing = resolution.get('slowest_ms')
                value = (f"{resolution.get('resolved')} of {resolution.get('attempted')} "
                         + (f"in {timing:.0f} ms" if isinstance(timing, (int, float)) else "(timing unavailable)"))
            out.append(_evidence(
                "dns_resolution", "Name resolution", status, value,
                ("A made-up name that cannot exist was answered with the address "
                 f"{resolution.get('wildcard_address')}. Something in the path is replying for "
                 "every domain -- an ISP's search page, a captive portal, or adware."
                 if resolution.get("hijacked") else
                 "Neither public name resolved in this check. Confirm with the repeated resolver and direct TCP tests before changing Windows."
                 if status == "bad" else
                 "Public names resolved; the reserved negative control returned no such name."
                 if resolution.get("wildcard_tested") and resolution.get("hijacked") is False else
                 "Only the listed public names were checked. The reserved negative control was not verified."),
                data=resolution, task_ids=("flush_dns", "change_dns")))

        profile_net = raw.get("network_profile") or {}
        if profile_net.get("available") and profile_net.get("profiles"):
            metered = profile_net.get("metered") or []
            local_only = profile_net.get("local_only") or []
            public = profile_net.get("public") or []
            if not profile_net.get("internet") and local_only:
                status = "bad"
                value = f"{local_only[0]['interface']} reaches the network but not the internet"
            elif metered:
                status, value = "warn", "the connection is set as metered"
            elif public:
                status = "info"
                value = f"{public[0]['interface']} is on the Public profile"
            else:
                status = "good"
                connected = next((p for p in profile_net["profiles"] if p["internet"]), None)
                value = (f"{connected['interface']} ({connected['category']}) has internet"
                         if connected else "connected")
            out.append(_evidence(
                "connection_profile", "Connection status", status, value,
                ("Windows can see the local network but cannot reach the internet through it. "
                 "That is the router, the line, or a portal waiting to be signed into."
                 if status == "bad" else
                 f"A metered connection stops Windows Update and Store downloads without "
                 f"reporting an error anywhere ({', '.join(metered)})."
                 if metered else
                 "On the Public profile, file sharing and device discovery are blocked. That is "
                 "correct on a cafe network and wrong at home."
                 if public else
                 "Windows reports a working internet connection."),
                data=profile_net, task_ids=("network_diagnostic_bundle",)))

        winsock = raw.get("winsock_health") or {}
        if winsock.get("available"):
            broken = winsock.get("broken") or []
            third = winsock.get("third_party") or []
            if broken:
                status = "bad"
                value = ", ".join(entry["module"] for entry in broken) + " is missing"
            elif third:
                status = "info"
                value = ", ".join(entry["module"] for entry in third[:3])
            else:
                status, value = "good", f"{winsock.get('total', 0)} stock entries, nothing added"
            out.append(_evidence(
                "winsock", "Network stack layers", status, value,
                ("Every socket on this PC is routed through a file that no longer exists. "
                 "Programs will say they are connected and nothing will load."
                 if broken else
                 "Something has inserted itself into the network stack -- usually a VPN, a "
                 "firewall, or a filtering product. Normal if you installed one."
                 if third else
                 "Nothing has been spliced into the network stack."),
                data=winsock, task_ids=("reset_network",)))

        mtu = raw.get("interface_mtu") or {}
        if mtu.get("available"):
            odd = mtu.get("nonstandard") or []
            out.append(_evidence(
                "mtu", "Packet size", "warn" if odd else "good",
                (", ".join(f"{row['interface']} at {row['mtu']}" for row in odd)
                 if odd else "standard on every physical adapter"),
                ("A packet size away from 1500 makes large transfers stall while small pages "
                 "load instantly -- the fault where half the internet appears to work."
                 if odd else
                 "Tunnels and virtual adapters legitimately run smaller and are not judged here."),
                data=mtu, task_ids=("reset_network",)))

        wu_policy = raw.get("update_policy") or {}
        if wu_policy.get("available"):
            if wu_policy.get("redirected"):
                status, value = "warn", f"updates come from {wu_policy.get('wsus')}"
            elif wu_policy.get("pinned_version"):
                status, value = "warn", f"pinned to {wu_policy.get('pinned_version')}"
            elif wu_policy.get("deferrals"):
                status = "info"
                value = ", ".join(f"{d['days']} days" for d in wu_policy["deferrals"])
            else:
                status, value = "good", "updates come from Microsoft"
            out.append(_evidence(
                "update_policy", "Where updates come from", status, value,
                ("This PC is pointed at an update server instead of Microsoft. If that server "
                 "is not reachable -- a work laptop that left the company, or a script that set "
                 "it -- Windows reports being up to date while receiving nothing."
                 if wu_policy.get("redirected") else
                 "A version pin stops this PC from ever moving past that Windows release, "
                 "including past its end of support."
                 if wu_policy.get("pinned_version") else
                 "Updates are held back for a set number of days by policy."
                 if wu_policy.get("deferrals") else
                 "Updates come straight from Microsoft, with nothing redirecting them."),
                data=wu_policy, task_ids=("windows_update_forensic",)))

        cache = raw.get("update_cache") or {}
        if cache.get("available"):
            stale = cache.get("stale")
            age = cache.get("oldest_days")
            out.append(_evidence(
                "update_cache", "Windows Update working files",
                "warn" if stale else "good",
                (f"{cache.get('gb', 0):.1f} GB, oldest {age:.0f} days"
                 if age is not None else f"{cache.get('gb', 0):.1f} GB"),
                ("A large download folder this old means an update has been failing and "
                 "retrying against the same broken files. Clearing it makes Windows fetch "
                 "them again."
                 if stale else
                 "Nothing is stuck in the download folder."),
                data=cache, task_ids=("reset_win_update",)))

        licence = raw.get("activation_state") or {}
        if licence.get("available") and licence.get("known"):
            licensed = licence.get("licensed")
            out.append(_evidence(
                "activation", "Windows activation",
                "good" if licensed else "warn",
                licence.get("state", "unknown"),
                ("Windows is activated." if licensed else
                 "Windows is not activated. Personalisation is blocked and a watermark appears, "
                 "but security updates still install."),
                data=licence, task_ids=("activate_windows",)))

        appx = raw.get("appx_health") or {}
        if appx.get("available"):
            broken = appx.get("broken") or []
            missing = appx.get("missing") or []
            if broken:
                status = "warn"
                value = f"{_plural(len(broken), 'app')} damaged"
            elif missing:
                status, value = "warn", ", ".join(missing) + " is not installed"
            else:
                status, value = "good", f"{appx.get('total', 0)} installed, none damaged"
            out.append(_evidence(
                "store_apps", "Store apps", status, value,
                (", ".join(entry["name"] for entry in broken[:4])
                 + ". A damaged package cannot start and cannot repair itself from the Store."
                 if broken else
                 "A part of Windows that should always be present has been removed, usually by "
                 "a debloat script."
                 if missing else
                 "Windows reports every installed package as intact."),
                data=appx, task_ids=("uwp_app_reset",)))

        shell = raw.get("shell_health") or {}
        if shell.get("available"):
            if not shell.get("explorer_running"):
                status, value = "warn", "Explorer is not running"
            elif shell.get("icon_cache_large"):
                status, value = "warn", f"icon cache {shell.get('icon_cache_mb', 0):.0f} MB"
            else:
                status = "good"
                value = f"Explorer running, icon cache {shell.get('icon_cache_mb', 0):.0f} MB"
            out.append(_evidence(
                "shell", "Desktop and Start menu", status, value,
                ("The desktop, taskbar, and Start menu are all Explorer. With it stopped there "
                 "is no desktop at all."
                 if not shell.get("explorer_running") else
                 "An oversized icon cache is what makes icons go blank or show the wrong picture."
                 if shell.get("icon_cache_large") else
                 "The shell is running normally."),
                data=shell, task_ids=("rebuild_icon_cache", "start_menu_reset")))

        audio = raw.get("audio_health") or {}
        if audio.get("available"):
            stopped = audio.get("service_stopped") or []
            faulty = audio.get("faulty") or []
            if stopped and audio.get("any_device"):
                status, value = "bad", f"{', '.join(stopped)} stopped"
            elif faulty:
                status = "warn"
                value = f"{_plural(len(faulty), 'device')} in a fault state"
            elif not audio.get("any_device"):
                status, value = "info", "no audio device found"
            else:
                status = "good"
                value = f"{_plural(len(audio.get('devices') or []), 'device')}, services running"
            out.append(_evidence(
                "audio", "Sound", status, value,
                ("The audio service is stopped, so nothing on this PC can play sound."
                 if stopped else
                 "; ".join(f"{d['name']}: {d['problem'] or d['status']}" for d in faulty[:3])
                 if faulty else
                 "This PC reports no sound hardware at all."
                 if not audio.get("any_device") else
                 "The audio services are running and every device reports healthy."),
                data=audio, task_ids=("audio_repair",)))

        bluetooth = raw.get("bluetooth_health") or {}
        if bluetooth.get("available"):
            if not bluetooth.get("present"):
                status, value = "good", "no Bluetooth hardware on this PC"
            elif bluetooth.get("service") == "stopped":
                status, value = "bad", "the Bluetooth service is stopped"
            elif bluetooth.get("faulty"):
                status = "warn"
                value = f"{_plural(len(bluetooth['faulty']), 'device')} in a fault state"
            else:
                status = "good"
                value = f"{_plural(len(bluetooth.get('devices') or []), 'device')}, service running"
            out.append(_evidence(
                "bluetooth", "Bluetooth", status, value,
                ("Nothing here is broken -- there is simply no Bluetooth radio to use."
                 if not bluetooth.get("present") else
                 "With the support service stopped, no Bluetooth device can pair or connect."
                 if bluetooth.get("service") == "stopped" else
                 "; ".join(f"{d['name']}: {d['problem'] or d['status']}"
                           for d in (bluetooth.get("faulty") or [])[:3])
                 or "Bluetooth is working normally."),
                data=bluetooth, task_ids=("bluetooth_repair",)))

        display = raw.get("display_config") or {}
        if display.get("available") and display.get("adapters"):
            basic = display.get("basic_driver") or []
            faulty = display.get("faulty") or []
            if basic:
                status, value = "bad", "running on Microsoft's fallback display driver"
            elif faulty:
                status = "warn"
                value = f"{_plural(len(faulty), 'adapter')} in a fault state"
            else:
                first = display["adapters"][0]
                status = "good"
                value = (f"{first['name']}"
                         + (f" at {first['resolution']}" if first.get("resolution") else ""))
            out.append(_evidence(
                "display", "Graphics", status, value,
                ("The real graphics driver is not loaded, so Windows is drawing everything in "
                 "software. Everything looks oversized and nothing is smooth."
                 if basic else
                 "; ".join(f"{a['name']}: {a['problem'] or 'fault'}" for a in faulty[:2])
                 if faulty else
                 (f"Driver {display['adapters'][0].get('driver_version', '')}"
                  + (f", {display['adapters'][0]['refresh_hz']} Hz"
                     if display["adapters"][0].get("refresh_hz") else ""))),
                data=display, task_ids=("gpu_diagnostic", "install_system_drivers")))

        integrity = raw.get("integrity_history") or {}
        if integrity.get("available"):
            if integrity.get("corrupt"):
                status = "bad"
                value = f"{_plural(integrity.get('unrepairable', 0), 'file')} could not be repaired"
            elif integrity.get("ever_run"):
                status = "good"
                value = (f"last checked {integrity['last_run_days']:.0f} days ago, clean"
                         if integrity.get("last_run_days") is not None else "last check was clean")
            else:
                status, value = "info", "never checked on this PC"
            out.append(_evidence(
                "system_files", "Windows file integrity", status, value,
                ("System File Checker has already run here and could not repair these. That "
                 "means the component store itself is damaged, so DISM has to repair the store "
                 "before another sfc pass can achieve anything."
                 if integrity.get("corrupt") else
                 "Read from the log of whenever the check last ran. Running it is a repair, not "
                 "a check, so nothing was started to produce this."
                 if integrity.get("ever_run") else
                 "No System File Checker run is recorded, so the Windows files are unproven "
                 "rather than proven good."),
                data=integrity, task_ids=("repair_system",)))

        policies = raw.get("policy_health") or {}
        if policies.get("available"):
            found = policies.get("restrictions") or []
            out.append(_evidence(
                "policies", "Features switched off by policy",
                "warn" if found else "good",
                (f"{_plural(len(found), 'restriction')}: "
                 + ", ".join(sorted(policies.get("areas", {})))
                 if found else "none"),
                ("; ".join(entry["meaning"] for entry in found[:4])
                 + ". On a work PC these are set deliberately by IT. On a home PC they are "
                   "almost always left over from a script."
                 if found else
                 "Nothing is switching Windows features off behind the Settings app."),
                data=policies, task_ids=("windows_tweaks",)))

        env = raw.get("environment_health") or {}
        if env.get("available"):
            if not env.get("has_system32"):
                status, value = "bad", "System32 is missing from the system PATH"
            elif env.get("truncation_risk"):
                status, value = "warn", f"{env.get('length')} characters -- close to the limit"
            elif env.get("missing_count", 0) >= 3:
                status = "warn"
                value = f"{_plural(env['missing_count'], 'folder')} in PATH do not exist"
            else:
                status = "good"
                value = f"{_plural(env.get('entries', 0), 'entry')}, {env.get('length')} characters"
            out.append(_evidence(
                "path", "System PATH", status, value,
                ("Without System32 on the PATH, a great deal of Windows fails with errors that "
                 "point nowhere near the real cause."
                 if not env.get("has_system32") else
                 "Past about 2,047 characters the value gets truncated, and everything after the "
                 "cut silently stops working."
                 if env.get("truncation_risk") else
                 "Entries pointing at folders that were uninstalled. Harmless individually, and "
                 "they slow down every command that has to search them."
                 if env.get("missing_count", 0) >= 3 else
                 "The PATH is intact and every entry resolves."),
                data=env, task_ids=("pc_report",)))

        folders = raw.get("known_folders") or {}
        if folders.get("available"):
            missing_folders = folders.get("missing") or []
            redirected = folders.get("redirected") or []
            if missing_folders:
                status = "bad"
                value = ", ".join(f["label"] for f in missing_folders) + " point at a missing folder"
            elif folders.get("stranded"):
                status, value = "warn", "stored in OneDrive, which is not running"
            elif redirected:
                status = "info"
                value = ", ".join(f["label"] for f in redirected) + " are in OneDrive"
            else:
                status, value = "good", "stored locally"
            out.append(_evidence(
                "known_folders", "Where your files live", status, value,
                ("Windows is pointing these folders at a location that no longer exists, which "
                 "is why files look like they have vanished. The originals are usually still on "
                 "the disk under the old path."
                 if missing_folders else
                 "The files are reachable, but nothing is syncing and anything saved now is not "
                 "being backed up."
                 if folders.get("stranded") else
                 "This is normal and deliberate -- the files are synced rather than local."
                 if redirected else
                 "Desktop and Documents are ordinary local folders."),
                data=folders, task_ids=("account_audit",)))

        out.extend(self._hardware_findings(raw))
        return out
