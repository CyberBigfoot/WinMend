"""WinMend diagnostics: hardware: memory."""

from __future__ import annotations

from winmend.diagnostics.hardware.reference import _num
import time


class HardwareMemoryMixin:
    """HardwareProbe methods grouped by responsibility."""

    # ---- memory -----------------------------------------------------------

    def memory_pattern_test(self, budget=30.0, cap_mb=2048):
        """Write known patterns across a block of RAM and read them back.

        Every other memory check in the engine is second-hand: it reads what
        Windows recorded after something already went wrong. This one puts data
        in memory and checks it comes back, which is the only way to catch a
        stuck bit before it corrupts something that matters.

        The honest limits, because they decide how the result may be phrased:

        * It can only test memory it is allowed to allocate -- never the pages
          Windows itself is using, and never more than a fraction of what is
          free. A clean pass therefore means "the memory I could reach is good",
          not "the RAM is good".
        * Physical addressing is the kernel's business, so a failure cannot be
          pinned to a slot from here. It proves a fault exists and justifies the
          real test; it does not replace it.

        A *failure*, though, is close to unarguable. Byte patterns do not change
        themselves, so a mismatch is a genuine fault in memory, in the controller
        or on the bus -- which is why this is worth the seconds it costs.
        """
        try:
            import psutil
            available = psutil.virtual_memory().available
        except Exception:
            return {"available": False, "reason": "memory statistics unreadable"}

        chunk_size = 1024 * 1024
        # Half of what is free, capped. Going further would push the machine
        # into its page file, which turns a memory test into a disk benchmark
        # and makes the PC unusable while it runs.
        size = min(int(cap_mb) * chunk_size, int(available * 0.5))
        size -= size % chunk_size
        if size < 64 * chunk_size:
            return {"available": False,
                    "reason": "not enough free memory to test without paging",
                    "available_mb": round(available / chunk_size)}

        patterns = [
            ("zeroes", bytes(chunk_size)),
            ("ones", b"\xff" * chunk_size),
            ("alternating", b"\xaa" * chunk_size),
            ("inverse alternating", b"\x55" * chunk_size),
            # A varied block catches coupling faults, where writing one cell
            # disturbs its neighbour -- uniform patterns can hide those.
            ("mixed", bytes(range(256)) * (chunk_size // 256)),
        ]
        deadline = time.monotonic() + max(5.0, float(budget))
        failures, passes_done, bytes_tested = [], 0, 0
        try:
            buffer = bytearray(size)
            view = memoryview(buffer)
        except MemoryError:
            return {"available": False, "reason": "the test buffer could not be allocated"}

        try:
            for name, chunk in patterns:
                if time.monotonic() > deadline:
                    break
                reference = memoryview(chunk)
                for offset in range(0, size, chunk_size):
                    view[offset:offset + chunk_size] = reference
                # Read back only after the whole block is written, so a fault
                # has to survive the rest of the writes to be reported.
                for offset in range(0, size, chunk_size):
                    if view[offset:offset + chunk_size] != reference:
                        failures.append(self._describe_mismatch(
                            view, reference, offset, chunk_size, name))
                        # One confirmed bad block is the finding. Grinding
                        # through the rest adds nothing and costs the user time.
                        break
                passes_done += 1
                bytes_tested += size
                if failures:
                    break
        except MemoryError:
            return {"available": False, "reason": "the machine ran out of memory mid-test"}
        finally:
            try:
                view.release()
            except Exception:
                pass
            del buffer

        return {
            "available": True,
            "tested_mb": round(size / chunk_size),
            "passes": passes_done,
            "patterns": len(patterns),
            "completed": passes_done >= len(patterns),
            "bytes_tested": bytes_tested,
            "failures": failures,
            "failed": bool(failures),
        }

    @staticmethod
    def _describe_mismatch(view, reference, offset, length, pattern):
        """Locate the first bad byte in a block and say which bits moved."""
        for index in range(length):
            wrote = reference[index]
            read = view[offset + index]
            if wrote != read:
                flipped = wrote ^ read
                return {
                    "pattern": pattern,
                    "offset_mb": round((offset + index) / (1024 * 1024), 2),
                    "wrote": wrote,
                    "read": read,
                    "bits_flipped": bin(flipped).count("1"),
                    "bit_mask": f"0x{flipped:02x}",
                }
        return {"pattern": pattern, "offset_mb": round(offset / (1024 * 1024), 2),
                "wrote": None, "read": None, "bits_flipped": None, "bit_mask": ""}

    def pool_usage(self):
        """Kernel memory pools, where a leaking driver hides.

        A driver that leaks non-paged pool consumes memory no task manager will
        attribute to anything: the user watches their RAM disappear with no
        process to blame, and every guide tells them to reinstall Windows. The
        pool counters name the shape of the problem even when they cannot name
        the driver, which is enough to stop the reinstall.
        """
        script = (
            "$m=Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction SilentlyContinue;"
            "Write-Output ('M|'+[string]$m.PoolPagedBytes+'|'+[string]$m.PoolNonpagedBytes"
            "+'|'+[string]$m.CacheBytes+'|'+[string]$m.CommittedBytes+'|'+[string]$m.CommitLimit);"
            "$s=Get-CimInstance Win32_PerfRawData_PerfOS_System -ErrorAction SilentlyContinue;"
            "Write-Output ('S|'+[string]$s.Threads+'|'+[string]$s.Processes)"
        )
        rc, rows, err = self._ps_rows(script, timeout=30)
        out = {}
        for row in rows:
            if row[0] == "M" and len(row) >= 6:
                out["paged_mb"] = round((_num(row[1]) or 0) / (1024 ** 2))
                out["nonpaged_mb"] = round((_num(row[2]) or 0) / (1024 ** 2))
                out["cache_mb"] = round((_num(row[3]) or 0) / (1024 ** 2))
                committed = _num(row[4]) or 0
                limit = _num(row[5]) or 0
                out["committed_mb"] = round(committed / (1024 ** 2))
                out["commit_limit_mb"] = round(limit / (1024 ** 2))
                out["commit_pct"] = (round(committed * 100.0 / limit, 1) if limit else None)
            elif row[0] == "S" and len(row) >= 3:
                out["threads"] = _num(row[1])
                out["processes"] = _num(row[2])
        if not out:
            return {"available": False, "reason": (err or "")[:200]}
        try:
            import psutil
            total_mb = round(psutil.virtual_memory().total / (1024 ** 2))
        except Exception:
            total_mb = None
        out["total_mb"] = total_mb
        nonpaged = out.get("nonpaged_mb") or 0
        # Non-paged pool cannot be swapped out, so it is charged directly against
        # physical memory. Windows sizes the cap generously; a machine sitting
        # near a fifth of its RAM in non-paged pool is not doing that by design.
        out["nonpaged_pct"] = (round(nonpaged * 100.0 / total_mb, 1)
                               if total_mb else None)
        out["nonpaged_high"] = bool(
            total_mb and nonpaged > max(1024, total_mb * 0.20))
        out["paged_high"] = bool(
            total_mb and (out.get("paged_mb") or 0) > max(2048, total_mb * 0.35))
        out["available"] = True
        return out
