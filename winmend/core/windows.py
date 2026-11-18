"""WinMend core: windows."""

from __future__ import annotations




# ---- Windows owned by a process: is it waiting on a prompt? -----------------

def _user32():
    import ctypes
    return ctypes.windll.user32


def visible_windows(pids=None):
    """[(hwnd, pid, class_name, title)] of visible top-level windows, optionally
    only those owned by `pids`. GetWindowText on another process's top-level
    window reads the cached caption and never blocks, even if that process is
    hung -- which is exactly when this is called."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []
    user32 = _user32()
    wanted = None if pids is None else {int(p) for p in pids}
    found = []
    proc_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def _each(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if wanted is not None and pid.value not in wanted:
                return True
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, title, 512)
            found.append((int(hwnd), int(pid.value), cls.value, title.value))
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(proc_type(_each), 0)
    except Exception:
        pass
    return found


def pids_with_visible_windows():
    """Process ids that own at least one visible top-level window."""
    return {pid for _hwnd, pid, _cls, _title in visible_windows()}


def window_children(hwnd, timeout_ms=300):
    """[(class_name, text)] for a window's child controls. Text is read with
    SendMessageTimeout(SMTO_ABORTIFHUNG) so a control whose owner thread is
    hung answers "" instead of hanging this one too."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []
    user32 = _user32()
    WM_GETTEXT = 0x000D
    SMTO_ABORTIFHUNG = 0x0002
    children = []
    proc_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def _each(child, _lparam):
        try:
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(child, cls, 256)
            buf = ctypes.create_unicode_buffer(1024)
            result = ctypes.c_size_t()
            user32.SendMessageTimeoutW(child, WM_GETTEXT, 1024, buf, SMTO_ABORTIFHUNG,
                                       timeout_ms, ctypes.byref(result))
            children.append((cls.value, buf.value))
        except Exception:
            pass
        return True

    try:
        user32.EnumChildWindows(hwnd, proc_type(_each), 0)
    except Exception:
        pass
    return children


PROGRESS_BAR_CLASS = "msctls_progress32"


def classify_prompt(title, children):
    """Is this window a question the process is waiting on?

    A progress window carries a progress bar and is the process working. A
    prompt has buttons and no progress bar. Returns None for anything else,
    otherwise {"title", "text", "buttons"} built from the Static and Button
    controls -- the text a user would read on screen."""
    classes = {cls for cls, _text in children}
    if PROGRESS_BAR_CLASS in classes:
        return None
    buttons = [t.replace("&", "").strip() for cls, t in children
               if cls == "Button" and t.strip()]
    if not buttons:
        return None
    statics = [t.strip() for cls, t in children if cls == "Static" and t.strip()]
    return {"title": title, "text": " ".join(statics), "buttons": buttons}


def process_prompts(pids):
    """Visible windows owned by `pids` that look like a prompt rather than a
    progress window: [{hwnd, pid, title, text, buttons}]."""
    prompts = []
    for hwnd, pid, _cls, title in visible_windows(pids):
        verdict = classify_prompt(title, window_children(hwnd))
        if verdict:
            verdict.update({"hwnd": hwnd, "pid": pid})
            prompts.append(verdict)
    return prompts


def bring_window_to_front(hwnd):
    """Best effort: restore and raise a window so a hidden prompt becomes
    visible. Windows may refuse to steal focus for a background process, in
    which case the taskbar button flashes instead."""
    try:
        import ctypes
        from ctypes import wintypes
        user32 = _user32()
        SW_RESTORE = 9
        user32.ShowWindow(hwnd, SW_RESTORE)
        if not user32.SetForegroundWindow(hwnd):
            class FLASHWINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND),
                            ("dwFlags", wintypes.DWORD), ("uCount", wintypes.UINT),
                            ("dwTimeout", wintypes.DWORD)]
            info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 0x0000000F, 6, 0)
            user32.FlashWindowEx(ctypes.byref(info))
        return True
    except Exception:
        return False
