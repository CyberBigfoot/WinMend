"""WinMend diagnostics: interview."""

from __future__ import annotations




# ---------------------------------------------------------------------------
# The interview
#
# These are the questions a PC cannot answer about itself. "When did it start"
# is the single most valuable fact in a diagnosis, and no probe can measure it.
# ---------------------------------------------------------------------------

class Question:
    """One triage question.

    ``weight`` orders the shortlist; ``applies`` decides whether the question is
    worth a user's attention given what they already typed.
    """

    __slots__ = ("id", "text", "options", "weight", "applies", "help")

    def __init__(self, id, text, options, weight=50, applies=None, help=""):
        self.id = id
        self.text = text
        self.options = list(options)          # [(value, label), ...]
        self.weight = weight
        self.applies = applies or (lambda parts, query: True)
        self.help = help

    def as_dict(self):
        return {
            "id": self.id,
            "text": self.text,
            "help": self.help,
            "options": [{"value": value, "label": label} for value, label in self.options],
        }


def _in_parts(*names):
    wanted = set(names)
    return lambda parts, query: bool(wanted & set(parts))


def _mentions(*words):
    return lambda parts, query: any(word in query for word in words)


INTERVIEW_QUESTIONS = [
    Question("net_browsers", "Does this affect every browser and app?",
             [("all", "Every browser and app"), ("one", "Only one browser or app"), ("unknown", "Not sure")],
             weight=108, applies=_in_parts("network"),
             help="This separates a system connectivity problem from one application or site."),
    # -- asked for almost everything, because they steer every rule ----------
    Question(
        "onset", "When did this start?",
        [("today", "Today"), ("week", "In the last week"),
         ("month", "In the last month"), ("older", "Longer than a month ago"),
         ("always", "It has always been like this"), ("unknown", "I am not sure")],
        weight=100,
        help="Timing selects the records to inspect. A recent change is not proof of the cause.",
    ),
    Question(
        "trigger", "Did anything happen right before it started?",
        [("update", "A Windows update installed"),
         ("software", "I installed a program or driver"),
         ("hardware", "I added or changed hardware"),
         ("power", "A power cut, crash, or forced shutdown"),
         ("nothing", "Nothing I know of"), ("unknown", "I am not sure")],
        weight=95,
        help="This is what a technician asks first, and it decides where to look.",
    ),
    Question(
        "frequency", "How often does it happen?",
        [("constant", "Constantly"), ("daily", "Several times a day"),
         ("occasional", "Now and then"),
         ("specific", "Only when I do one particular thing")],
        weight=70,
    ),
    Question(
        "reboot_helps", "Does restarting the PC make it better, even briefly?",
        [("yes", "Yes, for a while"), ("no", "No difference"),
         ("untried", "I have not tried")],
        weight=60,
        applies=_in_parts("performance", "network", "shell", "apps", "audio",
                          "printer", "bluetooth", "general", "browser"),
        help="Temporary relief helps choose what to observe; it does not establish a software or hardware cause.",
    ),
    Question(
        "safe_mode", "Does it still happen in Safe Mode?",
        [("yes", "Yes, it still happens"), ("no", "No, Safe Mode is fine"),
         ("untried", "I have not tried Safe Mode")],
        weight=85,
        applies=_in_parts("crashes", "performance", "shell", "security", "apps"),
        help="Safe Mode changes drivers and workload. A difference narrows the investigation but does not rule out hardware.",
    ),
    # -- network -----------------------------------------------------------
    Question(
        "net_scope", "Do other devices on the same network work normally?",
        [("others_fine", "Yes, only this PC has trouble"),
         ("others_too", "No, everything on the network is affected"),
         ("no_others", "There are no other devices to compare")],
        weight=90, applies=_in_parts("network"),
        help="If every device is affected, the fault is the router or the line, "
             "and nothing done on this PC will fix it.",
    ),
    Question(
        "net_medium", "How is this PC connected?",
        [("wifi", "Wi-Fi"), ("ethernet", "Ethernet cable"),
         ("both", "Both, and it happens either way"), ("unknown", "Not sure")],
        weight=80, applies=_in_parts("network"),
    ),
    Question(
        "net_symptom", "Which is closest?",
        [("none", "No connection at all"), ("slow", "Connected but slow"),
         ("drops", "Connects then drops repeatedly"),
         ("some_sites", "Most things work, specific sites or apps do not")],
        weight=75, applies=_in_parts("network"),
    ),
    # -- performance -------------------------------------------------------
    Question(
        "perf_when", "When is it slow?",
        [("boot", "Starting up and signing in"),
         ("always", "All the time"),
         ("after_time", "Fine at first, worse the longer it is on"),
         ("app", "Only in one program")],
        weight=80, applies=_in_parts("performance"),
    ),
    Question(
        "perf_signs", "Does anything else stand out?",
        [("fans", "The fans get loud or it feels hot"),
         ("disk", "The disk light is constantly busy"),
         ("freeze", "It freezes completely for seconds at a time"),
         ("nothing", "Nothing in particular")],
        weight=65, applies=_in_parts("performance"),
    ),
    # -- crashes -----------------------------------------------------------
    Question(
        "crash_kind", "What actually happens?",
        [("bsod", "A blue screen with a message"),
         ("reboot", "It restarts with no warning"),
         ("freeze", "It freezes and I have to hold the power button"),
         ("app", "One program closes, Windows keeps running"),
         ("shutdown", "It powers off completely")],
        weight=95, applies=_in_parts("crashes"),
    ),
    Question(
        "crash_when", "When does it crash?",
        [("load", "Under load -- games, video, heavy work"),
         ("idle", "When idle or doing very little"),
         ("boot", "During startup or shutdown"),
         ("sleep", "Waking from sleep"),
         ("random", "No pattern I can see")],
        weight=85, applies=_in_parts("crashes"),
        help="Load and sleep patterns help select measurements; they do not identify a faulty component.",
    ),
    # -- storage / updates / security --------------------------------------
    Question(
        "storage_target", "Which drive is filling up?",
        [("system", "The main Windows drive (C:)"),
         ("other", "A different drive"), ("unknown", "Not sure")],
        weight=70, applies=_in_parts("storage"),
    ),
    Question(
        "update_stage", "Where does the update get stuck?",
        [("search", "Checking for updates never finishes"),
         ("download", "Downloading stalls"),
         ("install", "Installing fails with an error"),
         ("loop", "It installs, then rolls back or reinstalls forever")],
        weight=85, applies=_in_parts("updates"),
    ),
    Question(
        "security_signs", "What made you suspect this?",
        [("popups", "Pop-ups or adverts appear on their own"),
         ("browser", "The browser home page or search changed"),
         ("slow", "It got very slow and noisy"),
         ("warned", "Something warned me, or a contact said so"),
         ("files", "Files were renamed, encrypted, or vanished"),
         ("check", "Nothing specific, I want it checked")],
        weight=90, applies=_in_parts("security"),
    ),
    # -- devices -----------------------------------------------------------
    Question(
        "device_scope", "Does it affect every device, or just one?",
        [("all", "All of them"), ("one", "Just one device"),
         ("unknown", "Not sure")],
        weight=75, applies=_in_parts("audio", "printer", "bluetooth"),
        help="One failing device is a device problem. All of them at once is a "
             "Windows service or driver problem.",
    ),
    Question(
        "app_scope", "Is it one app or all of them?",
        [("one", "One app"), ("store", "Everything from the Microsoft Store"),
         ("all", "Everything")],
        weight=75, applies=_in_parts("apps", "browser"),
    ),
    Question(
        "battery_symptom", "What is the battery doing?",
        [("drains", "Draining unusually fast"),
         ("nocharge", "Not charging"),
         ("shutdown", "Shutting down with charge remaining"),
         ("life", "Just does not last like it used to")],
        weight=75, applies=_in_parts("battery"),
    ),
]


INTERVIEW_BY_ID = {question.id: question for question in INTERVIEW_QUESTIONS}


class Interview:
    """Chooses the few questions worth asking about this particular complaint."""

    MAX_QUESTIONS = 5

    def __init__(self, engine=None):
        # Deliberately reuses DiagnosticEngine's keyword table so the interview
        # and the probes agree on what the user is talking about.
        from winmend.diagnostics.profiles import DiagnosticEngine
        self.classifier = engine or DiagnosticEngine()

    def profile_for(self, problem):
        return self.classifier.classify_detail(problem or "")

    def select(self, problem, profile=None, limit=None, answers=None, observations=None):
        """Return the question dicts to ask, most useful first."""
        if profile is None:
            profile, _score = self.profile_for(problem)
        parts = [p for p in str(profile).split("+") if p]
        query = (problem or "").lower()
        chosen = [q for q in INTERVIEW_QUESTIONS if q.applies(parts, query)]
        answers = self.normalise(answers)
        chosen = [q for q in chosen if q.id not in answers]
        if (observations or {}).get("network_config", {}).get("available"):
            chosen = [q for q in chosen if q.id != "net_medium"]
        if any(app in query for app in ("only", "one program", "specific site")):
            chosen = [q for q in chosen if q.id != "app_scope"]
        # Distinguish competing local/upstream and application/system explanations
        # before general history questions. Earlier answers change the next set.
        priority = {"net_scope": 110, "net_symptom": 105, "perf_when": 110,
                    "crash_kind": 110, "app_scope": 105, "update_stage": 110}
        if answers.get("net_scope") == "others_too":
            chosen = [q for q in chosen if q.id not in ("net_medium", "reboot_helps")]
        if answers.get("net_browsers") == "one":
            chosen = [q for q in chosen if q.id not in ("net_medium", "net_scope")]
        if answers.get("perf_when") == "app":
            chosen = [q for q in chosen if q.id != "safe_mode"]
        chosen.sort(key=lambda q: (-priority.get(q.id, q.weight), q.id))
        limit = self.MAX_QUESTIONS if limit is None else min(self.MAX_QUESTIONS, max(1, int(limit)))
        limit = min(limit, max(0, self.MAX_QUESTIONS - len(answers)))
        return [q.as_dict() for q in chosen[:limit]]

    @staticmethod
    def normalise(answers):
        """Keep only answers to known questions with known option values."""
        clean = {}
        for key, value in (answers or {}).items():
            question = INTERVIEW_BY_ID.get(key)
            if question is None:
                continue
            allowed = {option for option, _label in question.options}
            if value in allowed:
                clean[key] = value
        return clean

    @staticmethod
    def summarise(answers):
        """One line per answered question, for the case report."""
        lines = []
        for key, value in (answers or {}).items():
            question = INTERVIEW_BY_ID.get(key)
            if question is None:
                continue
            label = next((text for option, text in question.options if option == value), value)
            lines.append(f"{question.text} {label}")
        return lines

    @staticmethod
    def onset_days(answers):
        """Upper bound in days on how long the problem has existed, or None.

        Used to decide whether a change (an update, a driver) is close enough in
        time to be a plausible cause.
        """
        return {"today": 1.5, "week": 8.0, "month": 32.0}.get(
            (answers or {}).get("onset"))
