# Security policy

NetQuota runs as Administrator, captures packet metadata and edits Windows
Firewall rules, so security reports are taken seriously.

## Reporting a vulnerability
Please do **not** open a public issue. Use GitHub's private vulnerability
reporting: the repository's **Security** tab, then **Report a vulnerability**.

## Things to know
- Your VirusTotal API key is stored unencrypted in
  `%LOCALAPPDATA%\NetQuota\usage.sqlite3`. Never commit or share that file.
- Firewall rules created by NetQuota are named `NetQuota-<hash>-IN/OUT` and
  stay active after the app closes. Use "Resume app" to remove them.
- CI runs Gitleaks against the checked-out files and full Git history to detect
  common API keys, credentials, and other secret-like values. This is a
  best-effort check, not a guarantee that all sensitive data will be detected.
- If a real credential is detected, revoke or rotate it immediately. Removing
  it from the latest files does not remove it from Git history; treat it as
  exposed and follow GitHub's guidance before rewriting published history.
