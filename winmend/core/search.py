"""WinMend core: search."""

from __future__ import annotations

import re


def wm_normalize_query(text):
    """Search text reduced to plain lower-case words, the same way for the query
    and for every keyword it is matched against: "Wi-Fi" -> "wifi", "can't" ->
    "cant", "100% CPU" -> "100 cpu". Normalising only the query -- as the
    symptom matcher used to -- left every keyword with an apostrophe or a
    hyphen ("can't connect", "won't pair") impossible to match."""
    q = (text or "").lower().replace("’", "'")
    q = re.sub(r"['\-]", "", q)
    q = re.sub(r"[^a-z0-9\s]", " ", q)
    return re.sub(r"\s+", " ", q).strip()


def wm_query_has(query, term):
    """True when `term` starts a word of the normalised `query`: "crash" finds
    "crashing", but "port" no longer finds "report" nor "ram" "program"."""
    term = wm_normalize_query(term)
    return bool(term) and re.search(r"(?<![a-z0-9])" + re.escape(term), query) is not None


# Windows PowerShell 5.1 prints an error record message FIRST and its
# bookkeeping last:
#
#     Get-AppxProvisionedPackage : The requested operation requires elevation.
#     At line:1 char:1
#     + Get-AppxProvisionedPackage -Online -ErrorAction Stop
#     + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#         + CategoryInfo          : NotSpecified: (:) [...], COMException
#         + FullyQualifiedErrorId : Microsoft.Dism.Commands.GetAppx...
#
# so the last line of stderr is the error id, which tells the user nothing.
# A Write-Error inside a -Command script echoes the whole script before the
# message ("try {...} : message"), and a long message wraps at the buffer width.
_PS_TRAILER = re.compile(r"^\s*\+ (CategoryInfo|FullyQualifiedErrorId|PSComputerName)\s*:")
_PS_POSITION = re.compile(r"^At (line:\d+|.+:\d+) char:\d+\s*$")


def _ps_error_message(lines):
    """The message of the last PowerShell error record in `lines`, or None when
    the text holds no error record."""
    trailers = [i for i, line in enumerate(lines) if _PS_TRAILER.match(line)]
    if not trailers:
        return None
    # The last record's trailer block begins at the first trailer line of the
    # final run of consecutive trailer lines.
    end = trailers[-1]
    while end - 1 in trailers:
        end -= 1
    i = end - 1
    # Above the trailer: the "+ <code>" echo and "+ ~~~~" underline, then the
    # "At line:N char:N" position -- all present for a cmdlet error or a throw,
    # absent for a Write-Error.
    while i >= 0 and (lines[i].startswith("+ ") or lines[i].strip() == "+"):
        i -= 1
    if i >= 0 and _PS_POSITION.match(lines[i].strip()):
        i -= 1
    last = i
    while i >= 0 and lines[i].strip() and not _PS_TRAILER.match(lines[i]):
        i -= 1
    block = " ".join(line.strip() for line in lines[i + 1:last + 1] if line.strip())
    block = re.sub(r"\s+", " ", block).strip()
    if not block:
        return None
    # "<command or echoed script> : <message>". The separator is the last
    # " : " -- script text comes before it; messages almost never hold one.
    if " : " in block:
        block = block.rsplit(" : ", 1)[1].strip() or block
    return block


def _wm_last_line(*streams):
    """The reason a command failed, from the given captured streams.

    For PowerShell's own error output that is the message of its last error
    record (see the note above); for anything else, the last non-empty line.
    A script that only wrote to stdout before dying still deserves a reason,
    so the streams are tried in the order given.
    """
    for stream in streams:
        raw = (stream or "").splitlines()
        message = _ps_error_message(raw)
        if message:
            return message
        lines = [ln.strip() for ln in raw if ln.strip()]
        if lines:
            return lines[-1]
    return ""
