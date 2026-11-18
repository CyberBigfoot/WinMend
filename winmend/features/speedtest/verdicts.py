"""WinMend features: speedtest: verdicts."""

from __future__ import annotations




def usage_verdicts(down_mbps, up_mbps, idle_ms, loaded_ms, grade):
    """Translate raw numbers into 'good for X' ratings people actually care
    about. Each verdict is 'good' / 'ok' / 'bad' with a short reason. Gaming and
    calls weight latency and bufferbloat, not just throughput -- which is the
    whole point, and what a bare Mbps figure misses."""
    down = down_mbps or 0.0
    up = up_mbps or 0.0
    bad_bloat = grade in ("D", "F")
    marginal_bloat = grade in ("C",)

    def rate(good, ok, note_bad):
        return ("good", "") if good else ("ok", "") if ok else ("bad", note_bad)

    verdicts = []

    r, n = rate(down >= 25, down >= 15, "needs ~25 Mbps down")
    verdicts.append({"activity": "4K / UHD streaming", "rating": r,
                     "note": n or f"{down:.0f} Mbps down"})

    r, n = rate(down >= 5, down >= 3, "needs ~5 Mbps down")
    verdicts.append({"activity": "HD video streaming", "rating": r,
                     "note": n or f"{down:.0f} Mbps down"})

    call_ok = down >= 3.5 and up >= 3.5
    if call_ok and bad_bloat:
        verdicts.append({"activity": "Video calls (Zoom/Teams)", "rating": "ok",
                         "note": "fine until the line is busy — bufferbloat causes drops"})
    else:
        r, n = rate(call_ok and not marginal_bloat, call_ok,
                    "needs ~3.5 Mbps up & down")
        verdicts.append({"activity": "Video calls (Zoom/Teams)", "rating": r, "note": n})

    if idle_ms is None:
        game_good = game_ok = False
    else:
        game_good = idle_ms < 50 and not (bad_bloat or marginal_bloat)
        game_ok = idle_ms < 100 and not bad_bloat
    note = ("lag spikes under load" if bad_bloat else
            f"{idle_ms:.0f} ms ping" if idle_ms is not None else "latency unknown")
    verdicts.append({"activity": "Competitive online gaming",
                     "rating": "good" if game_good else "ok" if game_ok else "bad",
                     "note": "" if game_good else note})

    r, n = rate(up >= 20, up >= 5, "needs ~5 Mbps up")
    verdicts.append({"activity": "Large uploads / cloud backup", "rating": r,
                     "note": n or f"{up:.0f} Mbps up"})

    r, n = rate(down >= 100, down >= 50, "tight for several 4K streams")
    verdicts.append({"activity": "Many devices at once", "rating": r, "note": n})

    return verdicts
