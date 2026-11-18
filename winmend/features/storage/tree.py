"""WinMend features: storage: tree."""

from __future__ import annotations

import os


# ============================================================================
# ==================== STORAGE ANALYZER — TREE + TREEMAP =====================
# ============================================================================
# SSScanner and the safety classifiers are reused as-is: they are pure Python
# (os.scandir + queue + callbacks) and contain the hard-won knowledge about what
# must never be auto-deleted. Only the interface is rebuilt.

class SSNode:
    """A file or folder in the scanned tree."""

    __slots__ = ('path', 'name', 'size', 'is_dir', 'mtime', 'children', 'parent')

    def __init__(self, path, size=0, is_dir=False, mtime=0, parent=None):
        self.path = path
        self.name = os.path.basename(path) or path
        self.size = size
        self.is_dir = is_dir
        self.mtime = mtime
        self.children = []
        self.parent = parent

    def sorted_children(self):
        return sorted(self.children, key=lambda c: c.size, reverse=True)


def wm_duration(secs):
    """Human duration. mm:ss renders a fast scan as '00:00', which reads as
    'nothing happened' rather than 'that was quick'."""
    secs = max(0.0, float(secs))
    if secs < 1:
        return "under a second"
    if secs < 60:
        return f"{secs:.0f} seconds" if secs >= 2 else "1 second"
    m, s = divmod(int(secs), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def wm_build_tree(results, root_path):
    """Turn the scanner's flat {path: metadata} into a parent/child tree.

    The scanner reports each path independently; the treemap needs hierarchy.
    Folder sizes already include their descendants, so they are used directly
    rather than re-summed.
    """
    root_path = os.path.normpath(root_path)
    nodes = {}
    for path, meta in results.items():
        p = os.path.normpath(path)
        nodes[p] = SSNode(p, meta.get("size", 0), meta.get("is_dir", False),
                          meta.get("mtime", 0))
    root = nodes.get(root_path)
    if root is None:
        root = SSNode(root_path, 0, True)
        nodes[root_path] = root
    for p, node in nodes.items():
        if p == root_path:
            continue
        parent = os.path.dirname(p)
        # walk up until we find a scanned ancestor (files below min-size are absent)
        while parent and parent not in nodes and len(parent) > len(root_path):
            parent = os.path.dirname(parent)
        host = nodes.get(parent)
        if host is not None and host is not node:
            node.parent = host
            host.children.append(node)
    return root
