@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Build NetQuota.exe
echo === Building NetQuota.exe ===
set "PYEXE="
call :findpy
if not defined PYEXE goto notk
echo Using Python: %PYEXE%
%PYEXE% build_prod_exe.py
if errorlevel 1 goto fail
pause
exit /b 0

:notk
echo.
echo ERROR: No supported Python with Tcl/Tk was found.
echo Install Python 3.10 or newer with Tcl/Tk, and make "py" or "python" available.
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
