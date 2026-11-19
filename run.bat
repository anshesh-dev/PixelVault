@echo off
title PixelVault
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [*] First run - creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [!] Python was not found. Install Python 3 from python.org and tick "Add to PATH".
        pause
        exit /b 1
    )
)

".venv\Scripts\python.exe" -c "import flask, PIL, numpy, cryptography" 2>nul
if errorlevel 1 (
    echo [*] Installing requirements, this happens only once...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)

echo [*] Opening PixelVault at http://localhost:8000
start "" cmd /c "timeout /t 3 >nul & start http://localhost:8000"
".venv\Scripts\python.exe" app.py
pause
