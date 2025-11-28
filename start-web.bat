@echo off
echo ==========================================
echo   INJECTICIDE - LLM Security Testing
echo ==========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check/Create virtual environment
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install/Update dependencies
echo Installing dependencies...
pip install -q --upgrade pip
pip install -q -r requirements.txt

REM Start the web application
echo.
echo ==========================================
echo Starting Injecticide Web Platform...
echo ==========================================
echo.
set HOST=127.0.0.1
if not "%INJECTICIDE_HOST%"=="" set HOST=%INJECTICIDE_HOST%
echo Web UI:   http://%HOST%:8000
echo API Docs: http://%HOST%:8000/api/docs
echo.
echo Press Ctrl+C to stop the server
echo ==========================================
echo.

python -m uvicorn webapp.api:app --host %HOST% --port 8000 --reload
