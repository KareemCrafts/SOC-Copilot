@echo off
echo === SOC Copilot Setup ===

if not exist venv (
    python -m venv venv
)
call venv\Scripts\activate.bat

pip install --quiet python-evtx sqlalchemy pyyaml requests

where ollama >nul 2>nul
if errorlevel 1 (
    echo Ollama not found. Install free from https://ollama.com/download then re-run this.
    pause
    exit /b 1
)

ollama pull llama3.2
python run_all.py --setup-only

echo.
echo Setup complete. Drag any .evtx file onto analyze.bat to analyze it.
pause