@echo off
setlocal
rem phonehackscan - Windows launcher for phonehackscan.py
set "PYEXE="
set "ANDROID_SCAN_LAUNCHER=cmd"
where py >nul 2>nul && set "PYEXE=py -3"
if not defined PYEXE (where python >nul 2>nul && set "PYEXE=python")
if not defined PYEXE (
  echo Python 3.10 or newer is required: https://www.python.org/downloads/
  echo During setup, tick "Add python.exe to PATH", then run this file again.
  pause
  exit /b 1
)
%PYEXE% "%~dp0phonehackscan.py" %*
echo.
pause
