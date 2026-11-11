@echo off
REM Entry point portatile: prepara .tools\ al primo avvio, poi compila in dist\.
setlocal
chcp 65001 >nul
powershell.exe -NoProfile -File "%~dp0scripts\build.ps1" %*
if errorlevel 1 (
  echo.
  echo BUILD FALLITA
  exit /b 1
)
exit /b 0
