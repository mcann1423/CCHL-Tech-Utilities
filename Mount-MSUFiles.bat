@echo off
REM Mount-MSUFiles wrapper — calls PowerShell with execution policy bypass.
setlocal
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Mount-MSUFiles.ps1" %*
endlocal
