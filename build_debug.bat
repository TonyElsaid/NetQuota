@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Build NetQuota DEBUG exe
echo === Building NetQuota-debug.exe (shows a console with errors) ===
set "PYEXE="
call :findpy
if not defined PYEXE goto notk
echo Using Python: %PYEXE%
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import tkinter" >nul 2>&1
  if errorlevel 1 (
    echo ERROR: The existing .venv cannot import Tcl/Tk.
    echo Recreate .venv manually with a Python installation that includes Tcl/Tk.
    goto badvenv
  )
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating build environment...
  %PYEXE% -m venv .venv || goto fail
)
".venv\Scripts\python.exe" -m pip install --quiet --default-timeout=60 --retries 10 --upgrade pip || goto fail
".venv\Scripts\python.exe" -m pip install --quiet --default-timeout=60 --retries 10 -r requirements.txt pyinstaller || goto fail
".venv\Scripts\python.exe" -c "import tkinter, psutil, pydivert" || goto notk
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --console --uac-admin ^
  --name NetQuota-debug --icon assets\icon.ico --collect-all pydivert --hidden-import tkinter netquota.py || goto fail
echo.
echo SUCCESS: dist\NetQuota-debug.exe
echo Run it, and read any error text in the black window.
pause
exit /b 0

:notk
echo.
echo ERROR: No supported Python with Tcl/Tk was found.
echo Install Python 3.10 or newer with Tcl/Tk, and make "py" or "python" available.
pause
exit /b 1

:badvenv
pause
exit /b 1

:fail
echo.
echo BUILD FAILED. Read the messages above.
pause
exit /b 1

:findpy
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys, tkinter, venv; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
  if not errorlevel 1 set "PYEXE=py -3"
)
if not defined PYEXE (
  where python >nul 2>&1
  if not errorlevel 1 (
    python -c "import sys, tkinter, venv; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
    if not errorlevel 1 set "PYEXE=python"
  )
)
exit /b
