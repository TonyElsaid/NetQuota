# Third-party software and services

NetQuota does not bundle these projects in this repository. They are installed
from PyPI by `NetQuota.bat` or `pip install -r requirements.txt`.

| Project | Use | License |
|---|---|---|
| [psutil](https://github.com/giampaolo/psutil) | Maps network sockets to processes | BSD-3-Clause |
| [pydivert](https://github.com/ffalcinelli/pydivert) | Python bindings for WinDivert | LGPL-3.0 |
| [WinDivert](https://reqrypt.org/windivert.html) | Packet capture driver (shipped inside the pydivert wheel) | LGPL-3.0 / GPL-2.0 |

**Services:** the optional file-scan feature uses the
[VirusTotal API](https://docs.virustotal.com/). You supply your own API key and
must follow VirusTotal's terms (the free key is for non-commercial use only).
This project is not affiliated with or endorsed by VirusTotal or Google.

**If you distribute a bundled .exe** (for example built with PyInstaller), you
are redistributing pydivert/WinDivert and must comply with their LGPL terms.
