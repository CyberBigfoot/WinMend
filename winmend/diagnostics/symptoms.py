"""Local clause-aware symptom interpretation. Language selects checks, never facts."""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict

PATTERNS = {
    "network": r"\b(?:internet|wi[ -]?fi|wireless|network|dns|online|disconnect\w*|websites?|nothing loads|no connection)\b",
    "performance": r"\b(?:slow\w*|sluggish|lag\w*|performance|freez\w*|hang\w*|startup|boot|100 percent|unresponsive)\b",
    "storage": r"\b(?:storage|disk|space|drive full|cleanup|junk|temporary|ssd|hard drive)\b",
    "updates": r"\b(?:windows update|update fails?|updates? stuck|stuck update|cannot update|installing updates?)\b",
    "crashes": r"\b(?:crash\w*|blue screen|bsod|bugcheck|randomly restarts?|randomly shuts? off|screen goes black|shuts? down unexpectedly)\b",
    "security": r"\b(?:virus|malware|security|defender|hacked|suspicious|ransomware)\b",
    "battery": r"\b(?:battery|charg\w*|laptop dies|power drain)\b",
    "audio": r"\b(?:audio|sound|speakers?|microphone|headphones)\b",
    "printer": r"\b(?:printer|printing|print queue|spooler)\b",
    "shell": r"\b(?:start menu|taskbar|search|icons?|thumbnail|file association|explorer)\b",
    "bluetooth": r"\b(?:bluetooth|bt headset|pairing|paired)\b",
    "apps": r"\b(?:microsoft store|store app|app\w* crash\w*|app\w* (?:will not|won't|cannot) open|uwp)\b",
    "time": r"\b(?:wrong time|clock is wrong|date is wrong|time sync|certificate (?:error|warning))\b",
    "browser": r"\b(?:browser|chrome|edge|firefox|tabs)\b",
    "devices": r"\b(?:usb|device|display|screen|monitor)\b",
}
CORRECTIONS = {"wierless": "wireless", "blutooth": "bluetooth", "bluethooth": "bluetooth",
               "intenet": "internet", "interent": "internet", "frezzes": "freezes",
               "cras hes": "crashes", "slwo": "slow", "windo ws": "windows"}


@dataclass
class SymptomInterpretation:
    normalized: str
    categories: list
    negated: list
    applications: list
    temporal: list
    intermittent: bool
    uncertain: bool
    connected: bool
    scope: str

    def as_dict(self):
        return asdict(self)


def interpret(problem):
    query = str(problem or "").lower().replace("’", "'")
    query = re.sub(r"\s+", " ", query).strip()
    query = re.sub(r"\b100\s*%", "100 percent", query)
    for wrong, right in CORRECTIONS.items():
        query = re.sub(r"\b" + re.escape(wrong) + r"\b", right, query)
    clauses = re.split(r"[,;.!?]|\b(?:but|however|although)\b", query)
    positives, negatives = set(), set()
    for clause in clauses:
        for category, pattern in PATTERNS.items():
            for match in re.finditer(pattern, clause):
                before = clause[max(0, match.start() - 45):match.start()]
                # Negate the actual symptom, not failures such as "can't load websites".
                denied = (category in ("performance", "crashes") and
                          re.search(r"\b(?:not|isn't|aren't|never|no|doesn't|is not)\s+(?:\w+\s+){0,2}$", before))
                denied = denied or re.search(r"\b(?:no (?:problems?|issues?) with|working fine|works fine)\s*$", before)
                (negatives if denied else positives).add(category)
    # A driver update is a temporal clue, distinct from a failed Windows update.
    if "updates" not in positives and re.search(r"\bupdates?\b", query) and not re.search(r"after|since|driver update", query):
        positives.add("updates")
    if "updates" in positives and re.search(r"\b(?:after|since|following)\b[^,;.]*\bupdate\w*\b", query) and not re.search(
            r"\bupdate\w*\b.{0,30}(?:fail|stuck|error|cannot|won't|will not)", query):
        positives.remove("updates")
    apps = re.findall(r"\b(?:chrome|firefox|edge|outlook|teams|onedrive|steam|games?)\b", query)
    return SymptomInterpretation(
        query, sorted(positives), sorted(negatives - positives), sorted(set(apps)),
        re.findall(r"\b(?:yesterday|today|after[^,;.]{0,70}|since[^,;.]{0,70})", query),
        bool(re.search(r"sometimes|random|intermittent|keeps|after \d+|occasionally|cutting out", query)),
        bool(re.search(r"maybe|might|not sure|i think|seems", query)),
        bool(re.search(r"(?:wi[ -]?fi|internet|network).{0,20}(?:connected|connects)|have internet", query)),
        "application" if re.search(r"only|one (?:app|program)|specific (?:site|app)", query) else "unknown")


def classify(problem):
    result = interpret(problem)
    return ("+".join(result.categories) or "general", len(result.categories))
