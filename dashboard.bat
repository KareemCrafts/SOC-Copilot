@echo off
call venv\Scripts\activate.bat
start http://localhost:5000
python -m src.dashboard.app