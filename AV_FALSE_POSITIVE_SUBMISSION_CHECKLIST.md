# AV False-Positive Submission Checklist (Copy/Paste Ready)

Use this text when submitting your WinMend executable to antivirus vendors as a false positive.

## 1) Build Hardening Settings (Already Applied)
- UPX disabled in `WinMend.spec` (`upx=False`).
- Build mode switch added in `WinMend.spec`:
  - Onefile (default): `WINMEND_BUILD_MODE=onefile`
  - Onedir (recommended for fewer detections): `WINMEND_BUILD_MODE=onedir`

## 2) Build Commands
### Onefile
```powershell
$env:WINMEND_BUILD_MODE='onefile'
pyinstaller WinMend.spec --clean
```

### Onedir (recommended)
```powershell
$env:WINMEND_BUILD_MODE='onedir'
pyinstaller WinMend.spec --clean
```

## 3) Data to Collect Before Submitting
- Product name: WinMend
- Version: <PUT_VERSION_HERE>
- SHA256: <PUT_SHA256_HERE>
- File name: <PUT_EXE_NAME_HERE>
- Build mode: onefile or onedir
- Download URL (if any): <PUT_URL_HERE>
- Developer/Publisher name: <PUT_NAME_HERE>
- Code-signing certificate details (if signed): <PUT_CERT_DETAILS_HERE>

## 4) Vendor Submission Text (Exact Template)
Subject: False Positive Request - WinMend Windows Maintenance Utility

Hello Security Team,

I am the developer/publisher of a legitimate Windows maintenance utility named **WinMend**.
Your engine is flagging our binary as malware (often generic Trojan/Spy/Python heuristic), but this is a false positive.

Product details:
- Product: WinMend
- Version: <PUT_VERSION_HERE>
- SHA256: <PUT_SHA256_HERE>
- File name: <PUT_EXE_NAME_HERE>
- Build type: <onefile/onedir>
- Download URL: <PUT_URL_HERE>

What the app does:
- Windows cleanup, diagnostics, update tooling, and repair workflows
- Uses administrative commands and PowerShell for system maintenance tasks
- User-driven actions with confirmation prompts for sensitive operations

Recent hardening changes:
- Removed inline remote execution pattern (`irm ... | iex`) and replaced with download-to-file + hash logging + explicit user confirmation prior to execution
- Tightened Wi-Fi export gating with multi-step confirmation and typed unlock phrase
- Removed keyword patterns that can trigger keylogger-family heuristics
- Disabled UPX and added optional onedir packaging mode

Please review and reclassify this sample as clean if appropriate.
I can provide source code excerpts and additional validation data on request.

Thank you.

Best regards,
<PUT_NAME_HERE>
<PUT_EMAIL_HERE>

## 5) Microsoft-Specific Addendum (Optional)
Include this at the end for Microsoft submissions:

Additional note for Microsoft Defender:
- This application is distributed as a PyInstaller-built executable and may be heuristically classified due to admin/system tooling behavior.
- Please re-evaluate cloud/ML classification for SHA256: <PUT_SHA256_HERE>.

## 6) Post-Submission Tracking
- Keep a table: Vendor | Submission Date | Case ID | Current Detection Name | Status
- Re-submit each new release hash (detections are hash-specific).
- Prioritize vendors currently detecting on VirusTotal first.
