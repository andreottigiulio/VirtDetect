@echo off
REM Pulizia di binari e/o toolchain portatile.
setlocal
chcp 65001 >nul
powershell.exe -NoProfile -File "%~dp0scripts\clean.ps1" %*
if errorlevel 1 exit /b 1
exit /b 0
