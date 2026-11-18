"""WinMend features: apps: winget."""

from __future__ import annotations

import re

def winget_listing_error(result, *, updates=False):
    """Distinguish an empty package list from a failed source/query operation.

    Codes: microsoft/winget-cli, doc/windows/package-manager/winget/returnCodes.md.
    Masking also accepts the signed HRESULT returned by some subprocess shims.
    """
    code = result.returncode & 0xFFFFFFFF
    empty_codes = {0x8A150014}
    if updates:
        empty_codes.add(0x8A15002B)
    if code in empty_codes:
        return None
    if code != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        detail = lines[-1].strip() if lines else "Windows Package Manager could not complete the query."
        return f"{detail} (winget 0x{code:08X})"
    if not (result.stdout or "").strip():
        return "Windows Package Manager returned no listing; the installed/update state is unknown."
    return None

# ---------------------------------------------------------------------------
# winget upgrade-table parsing
# ---------------------------------------------------------------------------

def _winget_table_rows(text, min_columns=4):
    """Yield (line, column-start-offsets) for every data row in winget's tables.

    winget prints fixed-width tables with no stable machine-readable
    alternative, so rows are sliced at the column start offsets taken from each
    table's header (the line above the ----- separator). Offsets are
    positional, so this works in any UI language: winget's column order
    (Name, Id, Version, Available, Source) is fixed even when labels are
    localized.
    """
    if not text:
        return
    lines = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        # progress spinners emit backspace-erased frames; drop control chars
        lines.append(re.sub(r"[\x00-\x08\x0b-\x1f]", "", line).rstrip())
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        is_separator = (len(stripped) >= 10 and set(stripped) == {"-"}
                        and index > 0 and lines[index - 1].strip())
        if not is_separator:
            index += 1
            continue
        header = lines[index - 1]
        starts = [m.start() for m in re.finditer(r"\S+(?: \S+)*", header)]
        index += 1
        if len(starts) < min_columns:
            continue
        while index < len(lines) and lines[index].strip():
            yield lines[index], starts
            index += 1


def parse_winget_upgrade(text):
    """Rows from `winget upgrade` output.

    Ids winget truncated with '…' are flagged so callers can refuse to target
    them."""
    rows = []
    for line, starts in _winget_table_rows(text):
        row = _parse_winget_row(line, starts)
        if row is not None:
            rows.append(row)
    return rows


def parse_winget_list(text):
    """Installed packages from `winget list` output, as {id: version}.

    Same fixed-width table as the upgrade listing, but the Available column is
    empty for anything without a pending update, so a row only needs a Name and
    an Id to count. Keys are lower-cased because winget matches ids
    case-insensitively while printing the manifest's own casing.

    Packages winget did not install itself get an invented pseudo-id
    (`ARP\\Machine\\X64\\...`, `MSIX\\...`); they are returned as-is and simply
    never match a real winget id, which is the honest outcome -- absence here
    means "not detected", not "not installed".
    """
    installed = {}
    for line, starts in _winget_table_rows(text, min_columns=3):
        cols = _winget_columns(line, starts)
        name, pkg_id, version = cols[0], cols[1], cols[2]
        # The trailing "N packages have pins" / count lines slice to an empty Id.
        if not name or not pkg_id or "…" in pkg_id or " " in pkg_id:
            continue
        installed.setdefault(pkg_id.lower(), version)
    return installed


def _winget_columns(line, starts):
    cols = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(line)
        cols.append(line[start:end].strip())
    while len(cols) < 5:
        cols.append("")
    return cols


def _parse_winget_row(line, starts):
    name, pkg_id, version, available, source = _winget_columns(line, starts)[:5]
    # Slicing also hits the trailing "N upgrades available." count line; it has
    # nothing in the Id or Available columns, so these checks drop it.
    if not name or not pkg_id or not available:
        return None
    return {
        "name": name,
        "id": pkg_id,
        "version": version,
        "available": available,
        "source": source,
        "truncated": ("…" in pkg_id) or (" " in pkg_id),
    }
