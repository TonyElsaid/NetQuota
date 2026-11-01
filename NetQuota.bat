@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title NetQuota launcher
set "HERE=%~dp0"
set "VENV=%LOCALAPPDATA%\NetQuota\venv"
set "VPY=%VENV%\Scripts\python.exe"

echo NetQuota launcher
echo.
if not exist "%HERE%netquota.py" (
  echo ERROR: netquota.py was not found next to this file.
  echo Extract the complete download before running the launcher.
  goto fail
)

echo [1/3] Looking for Python 3.10 or newer with Tcl/Tk...
set "PYTHON_CMD="
call :findpython
if not defined PYTHON_CMD (
  echo ERROR: No supported Python installation with Tcl/Tk was found.
  echo Install Python 3.10 or newer with Tcl/Tk, then run this launcher again.
  echo The Python launcher ^(py^) or Python on PATH can be used.
  goto fail
)
echo Using %PYTHON_CMD%

if not exist "%VPY%" (
  echo [2/3] Creating the private application environment...
  %PYTHON_CMD% -m venv "%VENV%"
  if errorlevel 1 goto fail
)

"%VPY%" -c "import sys, tkinter; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 (
  echo ERROR: The existing environment at "%VENV%" is invalid or too old.
  echo Remove that environment and run this launcher again.
  goto fail
)

"%VPY%" -c "import psutil, pydivert" >nul 2>&1
if errorlevel 1 (
  echo [2/3] Installing NetQuota dependencies...
  "%VPY%" -m pip install --disable-pip-version-check --default-timeout=60 --retries 5 -r "%HERE%requirements.txt"
  if errorlevel 1 goto fail
)
"%VPY%" -c "import psutil, pydivert" >nul 2>&1
if errorlevel 1 (
  echo ERROR: NetQuota dependencies could not be imported after installation.
  goto fail
)

echo [3/3] Starting NetQuota...
"%VPY%" "%HERE%netquota.py"
if errorlevel 1 goto fail
exit /b 0

:findpython
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys, tkinter, venv; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
  if not errorlevel 1 set "PYTHON_CMD=py -3"
)
if not defined PYTHON_CMD (
  where python >nul 2>&1
  if not errorlevel 1 (
    python -c "import sys, tkinter, venv; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=python"
  )
)
exit /b

:fail
echo.
echo NetQuota could not be started. Review the message above.
pause
exit /b 1
