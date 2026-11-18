"""WinMend features: shell helpers."""

from __future__ import annotations

try:
    import winreg
except ImportError:  # pragma: no cover - WinMend runs on Windows
    winreg = None


# ---------------------------------------------------------------------------
# File associations: clearing the user's chosen default app
# ---------------------------------------------------------------------------

FILE_EXTS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"


# The protocol choices (http, https, mailto...) live here. The old reset used
# ...\CurrentVersion\Explorer\UrlAssociations, which does not exist, so web
# links were never reset.
URL_ASSOCIATIONS_KEY = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations"


# Windows 11 24H2 added UserChoiceLatest and reads it first; clearing only
# UserChoice left the association exactly as it was.
USER_CHOICE_KEYS = ("UserChoice", "UserChoiceLatest")


def _delete_key_tree(root, path):
    """'deleted', 'absent' or 'protected'.

    Children are enumerated through a read-only handle: a UserChoice key denies
    the user Set Value, so asking for write access (as delete_registry_tree
    does) is refused before anything is tried. Deleting a key needs only DELETE
    access, which the user has -- unless Windows' User Choice Protection Driver
    guards it, and then it is genuinely protected.
    """
    if winreg is None:
        return "protected"
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            children = []
            while True:
                try:
                    children.append(winreg.EnumKey(key, len(children)))
                except OSError:
                    break
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "protected"
    for child in children:
        if _delete_key_tree(root, path + "\\" + child) == "protected":
            return "protected"
    try:
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "protected"
    return "deleted"


def reset_user_choices(extensions, protocols, root=None, file_exts_key=FILE_EXTS_KEY,
                       url_key=URL_ASSOCIATIONS_KEY):
    """Clear the per-user default-app choice for each extension and protocol.

    Returns {item: 'cleared' | 'not set' | 'protected'}. Windows asks which app
    to use the next time a cleared type is opened. 'protected' means Windows
    refused -- it guards http, https and .pdf against changes by any program --
    and the choice has to be reset in Settings > Apps > Default apps.
    """
    if winreg is None:
        return {item: "protected" for item in list(extensions) + list(protocols)}
    root = root if root is not None else winreg.HKEY_CURRENT_USER
    results = {}
    targets = [(item, file_exts_key) for item in extensions] + [(item, url_key) for item in protocols]
    for item, base in targets:
        states = [_delete_key_tree(root, f"{base}\\{item}\\{sub}") for sub in USER_CHOICE_KEYS]
        if "protected" in states:
            results[item] = "protected"
        elif "deleted" in states:
            results[item] = "cleared"
        else:
            results[item] = "not set"
    return results


# ---------------------------------------------------------------------------
# Windows optional features: the feature that does the work
# ---------------------------------------------------------------------------
#
# Some picker entries name a parent feature that is an empty container. Its
# children are what install anything, and Windows leaves these ones off when
# only the parent is turned on (their manifests mark them detectNone
# default="false"). DISM's /all pulls in a feature's PARENTS, never its
# children. So "Enable DirectPlay" used to turn on LegacyComponents and leave
# DirectPlay itself off, and the NFS entry did the same to the NFS client.
#
# Read from C:\Windows\servicing\Packages\*.mum on build 26100. The children of
# Hyper-V, Containers and MediaPlayback default to on, so naming the parent is
# enough for those.

# Enabled in place of the parent; /all then brings the parent with it.
OPTIONAL_FEATURE_WORKER = {
    "LegacyComponents": "DirectPlay",
    "ServicesForNFS-ClientOnly": "ClientForNFS-Infrastructure",
}

# Turned off before their parent, so none is left on underneath it.
OPTIONAL_FEATURE_CHILDREN = {
    "LegacyComponents": ("DirectPlay",),
    "ServicesForNFS-ClientOnly": ("ClientForNFS-Infrastructure", "NFS-Administration"),
}

# DISM: "Feature name X is unknown" -- the feature is not part of this edition.
DISM_UNKNOWN_FEATURE = 0x800F080C


def optional_feature_steps(feature, action):
    """[(feature name, DISM argv)] that turn `feature` on or off, in order.

    Enabling is one step: the feature that does the work, with /all. Disabling
    goes through the children first and ends with `feature` itself.
    """
    if action == "enable":
        name = OPTIONAL_FEATURE_WORKER.get(feature, feature)
        return [(name, ["dism", "/online", "/enable-feature", f"/featurename:{name}", "/all",
                        "/norestart"])]
    names = OPTIONAL_FEATURE_CHILDREN.get(feature, ()) + (feature,)
    return [(name, ["dism", "/online", "/disable-feature", f"/featurename:{name}", "/norestart"])
            for name in names]
