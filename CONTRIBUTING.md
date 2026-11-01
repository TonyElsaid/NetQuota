# Contributing

Thanks for helping! NetQuota is a single-file Windows app (`netquota.py`).

## Set up
```powershell
git clone <repository-url>
cd netquota
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q          # run tests
.venv\Scripts\python netquota.py            # the app requests elevation when needed
```

Replace `<repository-url>` with the clone URL shown by GitHub.

## Guidelines
- Keep it Windows-only and dependency-light (`psutil`, `pydivert`, standard library).
- Never log, print or commit API keys or personal paths.
- Add or update tests in `tests/` for logic changes.
- Describe what you tested on Windows in your pull request.

## Good first issues
- Encrypt the stored API key with Windows DPAPI
- Optional system-tray icon / start minimised
- Export usage history to CSV
- Split `netquota.py` into modules
