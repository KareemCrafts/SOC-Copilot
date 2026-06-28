@echo off
echo ============================================
echo   SOC COPILOT - INSTALLER
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [X] Python not found. Install Python 3.10+ from https://python.org first.
    echo     Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment...
if not exist venv ( python -m venv venv )
call venv\Scripts\activate.bat

echo [2/4] Installing Python packages...
pip install --quiet -r requirements.txt

echo [3/4] Downloading Sigma rules + MITRE ATTACK data...
python run_all.py --setup-only

echo [4/4] Checking for Ollama (AI engine)...
where ollama >nul 2>nul
if errorlevel 1 (
    echo.
    echo     NOTE: Ollama not detected on PATH.
    echo     If you have not installed it, get it free: https://ollama.com/download
    echo     Then run: ollama pull llama3.2
    echo     The tool still works without it, just without AI case notes.
) else (
    echo     Ollama found. Pulling AI model llama3.2...
    ollama pull llama3.2
)

echo.
echo ============================================
echo   INSTALL COMPLETE
echo ============================================
echo   Analyze a log:  analyze.bat path\to\file.evtx
echo   Open dashboard: dashboard.bat
echo ============================================
pause