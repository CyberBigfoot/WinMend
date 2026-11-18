"""WinMend features: debloat: helpers."""

from __future__ import annotations




# ---------------------------------------------------------------------------
# Debloat: which preinstalled apps to offer, and which to leave unticked
#
# The two debloat tasks used to remove every app on these lists that matched,
# for every user, and log "91/91 processed" whatever happened -- so Teams on a
# PC that used it daily went with the rest, and nothing said what had gone.
# Now the lists are matched against what is actually installed and shown as a
# checklist. Apps people commonly use on purpose, and anything whose removal
# breaks something else, are listed but start unticked, with the reason.
# ---------------------------------------------------------------------------

# 91 entries sourced from Win11Debloat's Apps.json (SelectedByDefault: true).
DEBLOAT_STANDARD = (
    # --- Microsoft apps ---
    ("Clipchamp.Clipchamp", "Clipchamp (Video Editor)"),
    ("Microsoft.3DBuilder", "3D Builder"),
    ("Microsoft.549981C3F5F10", "Cortana"),
    ("Microsoft.BingFinance", "Bing Finance"),
    ("Microsoft.BingFoodAndDrink", "Bing Food And Drink"),
    ("Microsoft.BingHealthAndFitness", "Bing Health And Fitness"),
    ("Microsoft.BingNews", "Bing News"),
    ("Microsoft.BingSports", "Bing Sports"),
    ("Microsoft.BingTranslator", "Bing Translator"),
    ("Microsoft.BingTravel", "Bing Travel"),
    ("Microsoft.BingWeather", "Bing Weather"),
    ("Microsoft.Copilot", "Copilot"),
    ("Microsoft.Windows.AIHub", "Copilot+ AI Hub"),
    ("Microsoft.PCManager", "Microsoft PC Manager"),
    ("Microsoft.Getstarted", "Get Started"),
    ("Microsoft.Messaging", "Messaging"),
    ("Microsoft.Microsoft3DViewer", "3D Viewer"),
    ("Microsoft.MicrosoftJournal", "Microsoft Journal"),
    ("Microsoft.MicrosoftOfficeHub", "Office Hub"),
    ("Microsoft.MicrosoftPowerBIForWindows", "Power BI"),
    ("Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection"),
    ("Microsoft.MicrosoftStickyNotes", "Sticky Notes"),
    ("Microsoft.MixedReality.Portal", "Mixed Reality Portal"),
    ("Microsoft.NetworkSpeedTest", "Network Speed Test"),
    ("Microsoft.News", "Microsoft News"),
    ("Microsoft.Office.OneNote", "OneNote (UWP)"),
    ("Microsoft.Office.Sway", "Sway"),
    ("Microsoft.OneConnect", "One Connect"),
    ("Microsoft.Print3D", "Print 3D"),
    ("Microsoft.PowerAutomateDesktop", "Power Automate"),
    ("Microsoft.SkypeApp", "Skype (UWP)"),
    ("Microsoft.Todos", "Microsoft To Do"),
    ("Microsoft.Windows.DevHome", "Dev Home"),
    ("Microsoft.WindowsAlarms", "Alarms & Clock"),
    ("Microsoft.WindowsFeedbackHub", "Feedback Hub"),
    ("Microsoft.WindowsMaps", "Windows Maps"),
    ("Microsoft.WindowsSoundRecorder", "Sound Recorder"),
    ("Microsoft.XboxApp", "Xbox Console Companion"),
    ("Microsoft.ZuneVideo", "Movies & TV"),
    ("MicrosoftCorporationII.MicrosoftFamily", "Family Safety"),
    ("MicrosoftCorporationII.QuickAssist", "Quick Assist"),
    ("MicrosoftTeams", "Microsoft Teams (Old)"),
    ("MSTeams", "Microsoft Teams (New)"),
    # --- Third-party / OEM preinstalled ---
    ("ACGMediaPlayer", "ACG Media Player"),
    ("ActiproSoftwareLLC", "Actipro Software"),
    ("AdobeSystemsIncorporated.AdobePhotoshopExpress", "Adobe Photoshop Express"),
    ("Amazon.com.Amazon", "Amazon"),
    ("AmazonVideo.PrimeVideo", "Prime Video"),
    ("Asphalt8Airborne", "Asphalt 8"),
    ("AutodeskSketchBook", "Autodesk SketchBook"),
    ("CaesarsSlotsFreeCasino", "Caesars Slots"),
    ("COOKINGFEVER", "Cooking Fever"),
    ("CyberLinkMediaSuiteEssentials", "CyberLink Media Suite"),
    ("DisneyMagicKingdoms", "Disney Magic Kingdoms"),
    ("Disney", "Disney"),
    ("DrawboardPDF", "Drawboard PDF"),
    ("Duolingo-LearnLanguagesforFree", "Duolingo"),
    ("EclipseManager", "Eclipse Manager"),
    ("Facebook", "Facebook"),
    ("FarmVille2CountryEscape", "FarmVille 2"),
    ("fitbit", "Fitbit"),
    ("Flipboard", "Flipboard"),
    ("HiddenCity", "Hidden City"),
    ("HULULLC.HULUPLUS", "Hulu"),
    ("iHeartRadio", "iHeartRadio"),
    ("Instagram", "Instagram"),
    ("king.com.BubbleWitch3Saga", "Bubble Witch 3"),
    ("king.com.CandyCrushSaga", "Candy Crush Saga"),
    ("king.com.CandyCrushSodaSaga", "Candy Crush Soda"),
    ("LinkedInforWindows", "LinkedIn"),
    ("MarchofEmpires", "March of Empires"),
    ("Netflix", "Netflix"),
    ("NYTCrossword", "NYT Crossword"),
    ("OneCalendar", "One Calendar"),
    ("PandoraMediaInc", "Pandora"),
    ("PhototasticCollage", "Phototastic Collage"),
    ("PicsArt-PhotoStudio", "PicsArt"),
    ("Plex", "Plex"),
    ("PolarrPhotoEditorAcademicEdition", "Polarr Photo Editor"),
    ("Royal Revolt", "Royal Revolt"),
    ("Shazam", "Shazam"),
    ("Sidia.LiveWallpaper", "Live Wallpaper"),
    ("SlingTV", "Sling TV"),
    ("Spotify", "Spotify"),
    ("TikTok", "TikTok"),
    ("TuneInRadio", "TuneIn Radio"),
    ("Twitter", "Twitter / X"),
    ("Viber", "Viber"),
    ("WinZipUniversal", "WinZip"),
    ("Wunderlist", "Wunderlist"),
    ("XING", "XING"),
)


# Debloat Extreme adds Windows' own optional apps, components other apps rely
# on, and OEM tools.
DEBLOAT_EXTREME_EXTRA = (
    ("Microsoft.BingSearch", "Bing Search"),
    ("Microsoft.GamingApp", "Xbox app"),
    ("Microsoft.M365Companions", "Microsoft 365 Companions"),
    ("Microsoft.MSPaint", "Paint 3D"),
    ("Microsoft.OutlookForWindows", "Outlook for Windows (new)"),
    ("Microsoft.Paint", "Paint"),
    ("Microsoft.People", "People"),
    ("Microsoft.RemoteDesktop", "Remote Desktop (Store app)"),
    ("Microsoft.ScreenSketch", "Snipping Tool"),
    ("Microsoft.StartExperiencesApp", "Widgets Experience"),
    ("Microsoft.Whiteboard", "Whiteboard"),
    ("Microsoft.Windows.Photos", "Photos"),
    ("Microsoft.WindowsCalculator", "Calculator"),
    ("Microsoft.WindowsCamera", "Camera"),
    ("Microsoft.windowscommunicationsapps", "Mail & Calendar"),
    ("Microsoft.WindowsNotepad", "Notepad"),
    ("Microsoft.WindowsTerminal", "Windows Terminal"),
    ("Microsoft.XboxGameOverlay", "Xbox Game Overlay (old)"),
    ("Microsoft.XboxGamingOverlay", "Xbox Game Bar"),
    ("Microsoft.YourPhone", "Phone Link"),
    ("Microsoft.ZuneMusic", "Media Player"),
    ("MicrosoftWindows.CrossDevice", "Cross Device Experience"),
    ("Microsoft.Edge", "Microsoft Edge Store add-ons"),
    ("Microsoft.GetHelp", "Get Help"),
    ("Microsoft.WindowsStore", "Microsoft Store"),
    ("Microsoft.Xbox.TCUI", "Xbox TCUI Framework"),
    ("Microsoft.XboxIdentityProvider", "Xbox Identity Provider"),
    ("Microsoft.XboxSpeechToTextOverlay", "Xbox Speech To Text"),
    ("AD2F1837.HPAIExperienceCenter", "HP AI Experience Center"),
    ("AD2F1837.HPConnectedMusic", "HP Connected Music"),
    ("AD2F1837.HPConnectedPhotopoweredbySnapfish", "HP Connected Photo"),
    ("AD2F1837.HPDesktopSupportUtilities", "HP Desktop Support Utilities"),
    ("AD2F1837.HPEasyClean", "HP Easy Clean"),
    ("AD2F1837.HPFileViewer", "HP File Viewer"),
    ("AD2F1837.HPJumpStarts", "HP JumpStarts"),
    ("AD2F1837.HPPCHardwareDiagnosticsWindows", "HP PC Hardware Diagnostics"),
    ("AD2F1837.HPPowerManager", "HP Power Manager"),
    ("AD2F1837.HPPrinterControl", "HP Printer Control"),
    ("AD2F1837.HPPrivacySettings", "HP Privacy Settings"),
    ("AD2F1837.HPQuickDrop", "HP QuickDrop"),
    ("AD2F1837.HPQuickTouch", "HP QuickTouch"),
    ("AD2F1837.HPRegistration", "HP Registration"),
    ("AD2F1837.HPSupportAssistant", "HP Support Assistant"),
    ("AD2F1837.HPSureShieldAI", "HP Sure Shield AI"),
    ("AD2F1837.HPSystemInformation", "HP System Information"),
    ("AD2F1837.HPWelcome", "HP Welcome"),
    ("AD2F1837.HPWorkWell", "HP WorkWell"),
    ("AD2F1837.myHP", "myHP"),
    ("E046963F.LenovoCompanion", "Lenovo Vantage"),
    ("LenovoCompanyLimited.LenovoVantageService", "Lenovo Vantage Service"),
    ("DellInc.DellSupportAssistforPCs", "Dell SupportAssist"),
    ("DellInc.DellDigitalDelivery", "Dell Digital Delivery"),
    ("DellInc.DellMobileConnect", "Dell Mobile Connect"),
)


# Listed, but unticked: apps people install or keep on purpose. A preinstalled
# stub and the real app share one package name, so presence says nothing
# about which it is -- the user does.
_DEBLOAT_COMMONLY_USED = (
    "Microsoft.Todos", "Microsoft.MicrosoftStickyNotes", "MSTeams", "MicrosoftTeams",
    "MicrosoftCorporationII.QuickAssist", "MicrosoftCorporationII.MicrosoftFamily",
    "Microsoft.WindowsSoundRecorder", "Microsoft.WindowsAlarms",
    "Microsoft.PowerAutomateDesktop", "Microsoft.Office.OneNote",
    "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MicrosoftJournal", "Microsoft.Copilot",
    "Spotify", "Netflix", "Plex", "Disney", "AmazonVideo.PrimeVideo", "HULULLC.HULUPLUS",
    "SlingTV", "iHeartRadio", "PandoraMediaInc", "TuneInRadio",
    "Duolingo-LearnLanguagesforFree", "Instagram", "Facebook", "Twitter", "TikTok",
    "LinkedInforWindows", "Viber", "Shazam", "fitbit",
)


# Listed, but unticked, with what goes wrong without them.
DEBLOAT_BREAKS = {
    "Microsoft.WindowsStore": "the Microsoft Store: most apps, and any winget install from the "
                             "Store, can no longer be installed or updated",
    "Microsoft.GetHelp": "Get Help: Windows 11 runs its built-in troubleshooters through it",
    "Microsoft.XboxIdentityProvider": "Xbox sign-in: PC games that use an Xbox account stop "
                                      "signing in",
    "Microsoft.Xbox.TCUI": "the Xbox sign-in and friends screens games show",
    "Microsoft.XboxSpeechToTextOverlay": "Xbox party chat speech-to-text",
    "Microsoft.GamingApp": "the Xbox app and PC Game Pass",
    "Microsoft.XboxGamingOverlay": "Game Bar (Win+G), its screen recording and performance overlay",
    "Microsoft.WindowsCalculator": "Calculator",
    "Microsoft.WindowsNotepad": "Notepad",
    "Microsoft.Windows.Photos": "Photos: pictures open in nothing until another viewer is set",
    "Microsoft.ScreenSketch": "Snipping Tool, and the Print Screen key's screenshot tool with it",
    "Microsoft.Paint": "Paint",
    "Microsoft.WindowsTerminal": "Windows Terminal: command windows open in the old console",
    "Microsoft.WindowsCamera": "the Camera app",
    "Microsoft.ZuneMusic": "Media Player: music and videos open in nothing until another "
                          "player is set",
    "Microsoft.OutlookForWindows": "the new Outlook -- your mail app if you use it",
    "Microsoft.YourPhone": "Phone Link",
    "Microsoft.RemoteDesktop": "the Remote Desktop app (the built-in mstsc is unaffected)",
    "MicrosoftWindows.CrossDevice": "phone and cross-device features in Settings",
    "Microsoft.StartExperiencesApp": "the Widgets board",
    "Microsoft.Edge": "only Edge's Store-delivered add-ons such as Game Assist -- Edge itself "
                      "cannot be removed this way",
    "AD2F1837.HPSupportAssistant": "HP's BIOS and driver updates for this PC",
    "E046963F.LenovoCompanion": "Lenovo's BIOS and driver updates for this PC",
    "LenovoCompanyLimited.LenovoVantageService": "Lenovo Vantage",
    "DellInc.DellSupportAssistforPCs": "Dell's BIOS and driver updates for this PC",
    "DellInc.DellDigitalDelivery": "software bought with this Dell (it delivers it)",
}


ONEDRIVE_DEBLOAT_KEY = "__onedrive__"


def debloat_candidates(extreme):
    """(app id, friendly name) pairs the task considers, in display order."""
    return list(DEBLOAT_STANDARD) + (list(DEBLOAT_EXTREME_EXTRA) if extreme else [])


def match_debloat_packages(app_id, package_names):
    """Installed or provisioned package names an app id matches -- the same
    case-insensitive substring test as the old `-like "*id*"`."""
    needle = app_id.lower()
    return sorted({name for name in package_names if name and needle in name.lower()})


def build_debloat_options(installed, provisioned, extreme, onedrive_holds_files=False,
                          onedrive_present=False):
    """Checklist rows for the apps actually on this PC.

    Each row: key (app id), label, detail, checked, packages (the exact package
    names to remove). Only apps that match something installed or provisioned
    are listed -- a checklist of 145 names mostly absent says nothing useful.
    """
    names = set(installed or ()) | set(provisioned or ())
    options = []
    for app_id, label in debloat_candidates(extreme):
        packages = match_debloat_packages(app_id, names)
        if not packages:
            continue
        breaks = DEBLOAT_BREAKS.get(app_id)
        common = app_id in _DEBLOAT_COMMONLY_USED
        if breaks:
            detail = f"Left unticked -- removing it breaks {breaks}."
        elif common:
            detail = "Left unticked -- people often install or use this on purpose."
        else:
            detail = "Preinstalled; not part of Windows itself."
        state = []
        if set(packages) & set(installed or ()):
            state.append("installed")
        if set(packages) & set(provisioned or ()):
            state.append("installs for new users")
        detail += f" ({', '.join(state)}: {', '.join(packages)})"
        options.append({"key": app_id, "label": label, "detail": detail,
                        "checked": not (breaks or common), "packages": packages})
    if extreme and onedrive_present:
        options.append({
            "key": ONEDRIVE_DEBLOAT_KEY, "label": "OneDrive (uninstall through winget)",
            "detail": ("Left unticked -- your Desktop or Documents are stored in OneDrive on this "
                       "PC: uninstalling stops them syncing, and files kept only in the cloud stop "
                       "opening." if onedrive_holds_files else
                       "Left unticked -- uninstalling stops OneDrive syncing and backing up files."),
            "checked": False, "packages": []})
    return options
