<p align="center"><img src="assets/logo.png" width="110" alt="NetQuota logo"></p>

<h1 align="center">NetQuota</h1>
<p align="center">Per-app internet monitor, data quotas and firewall control for Windows.</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green.svg"></a>
  <img alt="Platform: Windows" src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue.svg">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
</p>

<!-- Add a screenshot: save it as docs/screenshot.png, then uncomment the next line -->
<!-- ![NetQuota screenshot](docs/screenshot.png) -->

## Features
- Live per-app download/upload speed and a 60-second traffic graph
- Daily and monthly totals per app, saved locally, with a 30-day history chart
- Pause/resume any app's network access (Windows Firewall rules)
- Daily or monthly data quotas that block an app automatically and reset by themselves
- Optional [VirusTotal](https://www.virustotal.com) check of an app's file (hash lookup by default)
- Dark UI, search, sortable table, right-click menu

## Quick start
1. Open the project's **Releases** page on GitHub and download `NetQuota.exe` from the latest release.
2. Double-click `NetQuota.exe` and approve the Windows Administrator prompt.

The release is a standalone, one-file Windows application: Python and a terminal are not required. The windowed executable requests Administrator rights because packet capture and firewall changes require them. The UAC prompt is from Windows, not a command window.

### Build a standalone .exe
This is for maintainers creating a release, not something end users need to do. On Windows, install Python 3.10+ with Tcl/Tk, then double-click `build_exe.bat` or run `python build_prod_exe.py`. The build creates `dist\NetQuota.exe` as a one-file, windowed executable and prints its SHA-256. Pushing a tag like `v1.0.0` runs the tests on Python 3.10–3.13, audits dependencies and scans Git history for secrets, builds the executable, and attaches it to a GitHub Release after those checks pass. CI also stores the executable as a downloadable artifact.

### Run from source
For development only; end users should use the release executable.
```powershell
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python netquota.py
```
The source launcher is also available for development:
```bat
NetQuota.bat
```

### Develop and test
```powershell
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
```

## How it works
- **Capture:** [WinDivert](https://reqrypt.org/windivert.html) via `pydivert` in *sniff* mode. Packets are copied for counting; traffic is never delayed, changed or dropped.
- **Per-app attribution:** `psutil` maps each packet's ports to the owning process.
- **Control:** pausing or exceeding a quota creates Windows Firewall rules named `NetQuota-<hash>-IN/OUT` for that executable. Resuming deletes them.
- **Storage:** SQLite at `%LOCALAPPDATA%\NetQuota\usage.sqlite3`. No telemetry; nothing leaves your PC except optional VirusTotal requests.

## VirusTotal (optional)
1. Create a free account and copy your API key from your profile.
2. In NetQuota, open **API key & settings** and paste it.
3. Select an app and click **Scan selected app**.

Only the file's SHA-256 hash is sent. A file is uploaded (max 64 MB) only if VirusTotal doesn't know it **and** you click Yes. The free key allows 4 lookups/minute and is for non-commercial use.

## Limitations
- Windows only; needs Administrator rights (packet capture and firewall changes).
- Attribution is best-effort: very short connections, some UDP and VPN traffic may show as `[unattributed]`.
- Counts are IP packet bytes, slightly higher than application payload.
- Quotas are enforced only while NetQuota is running. Firewall blocks stay after you close it until you resume the app.
- Apps hosted inside a shared process (e.g. `svchost.exe`) are controlled as that one executable. Don't block system or VPN software.
- The VirusTotal API key is stored unencrypted in the local database.

## FAQ
**Why Administrator?** WinDivert and firewall rules require it.
**Will it slow my internet?** Sniff mode only reads copies of packets; overhead is small.
**How do I remove it?** Select each blocked app and click *Resume app*, then delete the folder and `%LOCALAPPDATA%\NetQuota`.
**Antivirus warning?** Packet-capture drivers sometimes trigger heuristics. Review the code, and allow-list the folder if you trust it.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [THIRD_PARTY.md](THIRD_PARTY.md).

## Data and privacy
Usage history, settings, and logs are stored under the current Windows user's
`%LOCALAPPDATA%\NetQuota` directory. These files are not part of the repository
and should not be shared. The app does not depend on the repository being in a
specific folder or on a particular Windows user account.

## License
[MIT](LICENSE). Not affiliated with VirusTotal, Google or the WinDivert authors.
