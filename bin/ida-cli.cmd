@echo off
REM ida-cli.cmd — Global wrapper for ida_cli.py (Windows)
REM Add this directory to PATH, then use: ida-cli start ./target.exe
setlocal
set "SCRIPT_DIR=%~dp0"
python "%SCRIPT_DIR%..\tools\ida_cli.py" %*
