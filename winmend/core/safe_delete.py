"""WinMend core: delete a folder tree without ever following a link into somewhere else.

WinMend runs elevated, and C:\\Windows\\Temp lets every standard account create
files and folders (BUILTIN\\Users: create files / create folders, inherited).
shutil.rmtree is not safe there: on Windows it is the path-based version its own
source calls "vulnerable to race conditions". It lists a folder, then opens each
subfolder by name -- and the account that owns a subfolder can swap it for a
junction in between. rmtree then walks the junction and deletes whatever is
behind it, with administrator rights.

Everything here works on handles instead:

* every entry is opened with FILE_FLAG_OPEN_REPARSE_POINT, so a link is opened
  as itself and deleted as itself -- its target is never touched;
* every handle is checked with GetFinalPathNameByHandle against the path it was
  expected to have, so an object reached through a swapped-in junction anywhere
  above it is left alone;
* a folder is held open without FILE_SHARE_DELETE while its contents go, so it
  cannot be renamed or replaced under us, and it is listed through that handle
  rather than by path;
* deletion is by handle (delete-on-close), so nothing is looked up by name
  again between the check and the delete.

clear_folder applies the same rules to emptying a folder that must itself stay,
such as a browser or shader cache under the user's app data: less exposed than
C:\\Windows\\Temp, since only the user's own programs can write there, but the
deletion runs elevated all the same.
"""

from __future__ import annotations

import ctypes
import os
import struct
from ctypes import wintypes

try:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
except (AttributeError, OSError):  # pragma: no cover - WinMend runs on Windows
    _kernel32 = None


_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_INVALID_HANDLE = ctypes.c_void_p(-1).value

_FILE_BASIC_INFO = 0
_FILE_STANDARD_INFO = 1
_FILE_DISPOSITION_INFO = 4
_FILE_FULL_DIRECTORY_INFO = 14
_FILE_FULL_DIRECTORY_RESTART_INFO = 15

_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_ERROR_NO_MORE_FILES = 18

# FILE_FULL_DIR_INFO: NextEntryOffset at 0, FileAttributes at 56,
# FileNameLength (bytes) at 60, FileName at 68.
_DIR_ATTRS_OFFSET = 56
_DIR_NAME_OFFSET = 68

# Listing or deleting a folder; the delete-only fallback is for a file some
# other program holds open without sharing reads, and the list-only one for a
# folder that is kept anyway but will not grant delete access.
_ACCESS_FULL = _DELETE | _FILE_READ_ATTRIBUTES | _FILE_LIST_DIRECTORY | _SYNCHRONIZE
_ACCESS_DELETE_ONLY = _DELETE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
_ACCESS_LIST_ONLY = _FILE_READ_ATTRIBUTES | _FILE_LIST_DIRECTORY | _SYNCHRONIZE
_FOR_DELETING = (_ACCESS_FULL, _ACCESS_DELETE_ONLY)
_FOR_KEEPING_FOLDERS = (_ACCESS_FULL, _ACCESS_DELETE_ONLY, _ACCESS_LIST_ONLY)

_LINKED = "it is a link, or is reached through one, and links are never followed"


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD)]


class _FileStandardInfo(ctypes.Structure):
    _fields_ = [("AllocationSize", ctypes.c_longlong),
                ("EndOfFile", ctypes.c_longlong),
                ("NumberOfLinks", wintypes.DWORD),
                ("DeletePending", wintypes.BOOLEAN),
                ("Directory", wintypes.BOOLEAN)]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]


if _kernel32 is not None:
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                                           wintypes.DWORD]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                              wintypes.DWORD]
    _GetFileInformationByHandleEx.restype = wintypes.BOOL
    _SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                            wintypes.DWORD]
    _SetFileInformationByHandle.restype = wintypes.BOOL


def _open(path, access, share):
    """A handle to `path` itself (never a link's target), or (None, error)."""
    handle = _CreateFileW(path, access, share, None, _OPEN_EXISTING,
                          _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle is None or handle == _INVALID_HANDLE:
        return None, ctypes.get_last_error()
    return handle, 0


def _final_path(handle):
    size = 512
    while True:
        buf = ctypes.create_unicode_buffer(size)
        got = _GetFinalPathNameByHandleW(handle, buf, size, 0)
        if not got:
            raise ctypes.WinError(ctypes.get_last_error())
        if got < size:
            return buf.value
        size = got + 1


def _attributes(handle):
    info = _FileBasicInfo()
    if not _GetFileInformationByHandleEx(handle, _FILE_BASIC_INFO, ctypes.byref(info),
                                         ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.FileAttributes


def _size(handle):
    """Bytes deleting this file frees: none for one of several hard links to it."""
    info = _FileStandardInfo()
    if not _GetFileInformationByHandleEx(handle, _FILE_STANDARD_INFO, ctypes.byref(info),
                                         ctypes.sizeof(info)):
        return 0
    return info.EndOfFile if info.NumberOfLinks == 1 else 0


def _list_names(handle):
    """Every entry in the folder `handle` is open on, read through the handle."""
    buf = ctypes.create_string_buffer(64 * 1024)
    base = ctypes.addressof(buf)
    names = []
    info_class = _FILE_FULL_DIRECTORY_RESTART_INFO
    while True:
        if not _GetFileInformationByHandleEx(handle, info_class, buf, len(buf)):
            error = ctypes.get_last_error()
            if error == _ERROR_NO_MORE_FILES:
                return names
            raise ctypes.WinError(error)
        info_class = _FILE_FULL_DIRECTORY_INFO
        offset = 0
        while True:
            (next_offset,) = struct.unpack_from("<I", buf, offset)
            (name_bytes,) = struct.unpack_from("<I", buf, offset + _DIR_ATTRS_OFFSET + 4)
            name = ctypes.wstring_at(base + offset + _DIR_NAME_OFFSET, name_bytes // 2)
            if name not in (".", ".."):
                names.append(name)
            if not next_offset:
                break
            offset += next_offset


def _delete_on_close(handle):
    info = _FileDispositionInfo(True)
    return bool(_SetFileInformationByHandle(handle, _FILE_DISPOSITION_INFO, ctypes.byref(info),
                                            ctypes.sizeof(info)))


class _Entry:
    __slots__ = ("handle", "path", "folder", "link", "pending")

    def __init__(self, handle, path, folder, link, pending):
        self.handle = handle
        self.path = path
        self.folder = folder  # a real folder, not a link to one
        self.link = link
        self.pending = pending  # None for a folder that could not be listed


def _open_entry(path, accesses=_FOR_DELETING):
    """Open `path` itself if, and only if, it really is at `path`.

    Each access in `accesses` is tried in turn while the one before is refused
    (in use, or protected). Returns an _Entry, with the names to visit first
    when it is a real folder. Raises OSError when it cannot be opened --
    FileNotFoundError when it is gone -- or turns out to live somewhere else.
    """
    share = _FILE_SHARE_READ | _FILE_SHARE_WRITE  # never DELETE: nobody may move it now
    for access in accesses:
        handle, error = _open(path, access, share)
        if handle is not None or error not in (_ERROR_ACCESS_DENIED, _ERROR_SHARING_VIOLATION):
            break
    if handle is None:
        raise ctypes.WinError(error)
    try:
        if os.path.normcase(_final_path(handle)) != os.path.normcase(path):
            # Reached through a junction somewhere above it: this is not the
            # object that was listed, so it is not ours to delete.
            raise OSError(_LINKED)
        attributes = _attributes(handle)
        link = bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
        folder = bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) and not link
        pending = []
        if folder:
            pending = _list_names(handle) if access & _FILE_LIST_DIRECTORY else None
        return _Entry(handle, path, folder, link, pending)
    except BaseException:
        _CloseHandle(handle)
        raise


def _delete_tree(top, keep_dirs=False, keep_top=False):
    """Delete what the open entry `top` holds, and `top` itself unless keep_top.

    With keep_dirs every real folder stays and only files and links go.
    Returns (files deleted, bytes freed, entries left, whether `top` went).
    Files and links count as left when they are, folders only when they could
    not be looked inside: a folder left because of what it holds is already
    counted through that.
    """
    accesses = _FOR_KEEPING_FOLDERS if keep_dirs else _FOR_DELETING
    stack = [top]
    deleted = freed = left = 0
    top_gone = False
    try:
        while stack:
            entry = stack[-1]
            if entry.pending:
                try:
                    stack.append(_open_entry(entry.path + "\\" + entry.pending.pop(), accesses))
                except FileNotFoundError:
                    pass  # deleted by something else since the listing
                except OSError:
                    left += 1  # in use, or not where it was listed
                continue
            stack.pop()
            if entry.folder and (keep_dirs or (keep_top and entry is top)):
                _CloseHandle(entry.handle)
                if entry.pending is None:
                    left += 1
                continue
            size = 0 if entry.folder else _size(entry.handle)
            # Children were closed (and so deleted) before their parent got
            # here, which is what lets an emptied folder go too.
            gone = _delete_on_close(entry.handle)
            _CloseHandle(entry.handle)
            if entry is top:
                top_gone = gone
            if not entry.folder:
                if gone:
                    deleted += 1
                    freed += size
                else:
                    left += 1
            elif not gone and entry.pending is None:
                left += 1
    finally:
        for entry in stack:
            _CloseHandle(entry.handle)
    return deleted, freed, left, top_gone


def final_path(path):
    """The fully resolved path of an existing folder, in the form remove_tree and
    clear_folder expect.

    This one follows links: it answers "where is this Temp folder really?".
    """
    if _kernel32 is None:
        raise OSError("safe deletion needs Windows")
    handle = _CreateFileW(path, _FILE_READ_ATTRIBUTES,
                          _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE, None,
                          _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle is None or handle == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _final_path(handle)
    finally:
        _CloseHandle(handle)


def remove_tree(path):
    """Delete the file, link or folder tree at `path`. True when it is gone.

    `path` must be in the resolved form final_path() returns, with the entry's
    name appended (``final_path(temp) + "\\\\" + name``): each object's real
    location is compared against it. A link is deleted as a link. Anything in
    use is left in place, which leaves its folders in place too, and the result
    is False.
    """
    if _kernel32 is None:
        raise OSError("safe deletion needs Windows")
    try:
        top = _open_entry(path)
    except OSError:
        return False
    return _delete_tree(top)[3]


def clear_folder(path, keep_dirs=False):
    """Delete everything inside the folder at `path`, leaving the folder itself.

    With keep_dirs only files (and links) go, and every real subfolder stays:
    browsers expect their cache layout to survive. `path` is in the form
    final_path() returns, with any names below it appended, and the folder
    must really be there -- not a link, nor reached through one -- or nothing
    is touched and OSError is raised (FileNotFoundError when it does not
    exist). Inside it, remove_tree's rules hold: a link is deleted as the
    link, never followed.

    Returns (files deleted, bytes freed, entries left because they were in use
    or could not be checked).
    """
    if _kernel32 is None:
        raise OSError("safe deletion needs Windows")
    # List access only: the folder is never deleted, so it need not grant that.
    top = _open_entry(path, (_ACCESS_LIST_ONLY,))
    if not top.folder:
        _CloseHandle(top.handle)
        if top.link:
            raise OSError(_LINKED)
        raise NotADirectoryError("it is a file, not a folder")
    deleted, freed, left, _gone = _delete_tree(top, keep_dirs=keep_dirs, keep_top=True)
    return deleted, freed, left
