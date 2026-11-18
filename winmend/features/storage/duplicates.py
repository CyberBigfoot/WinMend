"""WinMend features: storage: duplicates."""

from __future__ import annotations

import hashlib


def wm_find_duplicates(files, progress=None):
    """Find byte-identical files. Returns [(size, [paths])] biggest waste first.

    Three passes, cheapest first: group by size (no I/O), then by a 64 KB head
    hash, then a full hash only for what still matches. Files with a unique size
    can never be duplicates, so the expensive hashing touches very little.
    """
    by_size = {}
    for path, meta in files:
        by_size.setdefault(meta.get("size", 0), []).append(path)
    candidates = {s: ps for s, ps in by_size.items() if len(ps) > 1}
    if not candidates:
        return []

    def digest(path, limit=None):
        h = hashlib.blake2b(digest_size=16)
        try:
            with open(path, "rb") as fh:
                if limit:
                    h.update(fh.read(limit))
                else:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
        except (OSError, PermissionError):
            return None
        return h.hexdigest()

    # pass 2: head hash
    stage2 = {}
    done = 0
    for size, paths in candidates.items():
        heads = {}
        for p in paths:
            d = digest(p, 64 * 1024)
            if d:
                heads.setdefault(d, []).append(p)
            done += 1
            if progress and done % 200 == 0:
                progress(f"Hashing… {done:,} files checked")
        for group in heads.values():
            if len(group) > 1:
                stage2.setdefault(size, []).append(group)

    # pass 3: full hash
    out = []
    for size, groups in stage2.items():
        for group in groups:
            full = {}
            for p in group:
                d = digest(p)
                if d:
                    full.setdefault(d, []).append(p)
            for same in full.values():
                if len(same) > 1:
                    out.append((size, same))
    out.sort(key=lambda g: g[0] * (len(g[1]) - 1), reverse=True)
    return out
