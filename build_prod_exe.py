"""Build the standalone Windows production executable."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys


PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
ENVIRONMENT_VARIABLES_TO_CLEAR = (
    "TCL_LIBRARY",
    "TK_LIBRARY",
    "TCLLIBPATH",
    "PYTHONHOME",
    "PYTHONPATH",
)


def build_environment():
    environment = os.environ.copy()
    for name in ENVIRONMENT_VARIABLES_TO_CLEAR:
        environment.pop(name, None)
    return environment


def run(command, environment):
    subprocess.run(command, cwd=PROJECT_DIR, env=environment, check=True)


def build_python(environment):
    if Path(sys.prefix).resolve() == VENV_DIR.resolve():
        return Path(sys.executable)

    if not VENV_PYTHON.is_file():
        print(f"Creating build environment: {VENV_DIR}")
        run([sys.executable, "-m", "venv", str(VENV_DIR)], environment)

    return VENV_PYTHON


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    if os.name != "nt":
        raise SystemExit("The NetQuota production executable must be built on Windows.")

    environment = build_environment()
    python = build_python(environment)

    print("Installing application and build dependencies...")
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--default-timeout=60",
            "--retries",
            "10",
            "--upgrade",
            "-r",
            str(PROJECT_DIR / "requirements.txt"),
            "pyinstaller",
        ],
        environment,
    )

    print("Checking Python, Tcl/Tk, and application dependencies...")
    run(
        [
            str(python),
            "-c",
            "import tkinter, psutil, pydivert; tkinter.Tcl()",
        ],
        environment,
    )

    print("Building one-file, windowed, administrator-elevated executable...")
    run(
        [
            str(python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--windowed",
            "--uac-admin",
            "--name",
            "NetQuota",
            "--icon",
            "assets/icon.ico",
            "--collect-all",
            "pydivert",
            "--hidden-import",
            "tkinter",
            "netquota.py",
        ],
        environment,
    )

    executable = PROJECT_DIR / "dist" / "NetQuota.exe"
    if not executable.is_file() or executable.stat().st_size == 0:
        raise SystemExit(f"Build completed without producing a valid executable: {executable}")

    print(f"\nSUCCESS: {executable}")
    print(f"SHA-256: {sha256(executable)}")


if __name__ == "__main__":
    main()
