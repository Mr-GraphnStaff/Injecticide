@echo off
title Injecticide Web Server - WITH PROPER CLEANUP
color 0A

echo ==========================================
echo   INJECTICIDE WEB SERVER
echo ==========================================
echo.
echo This version properly cleans up when you close it!
echo.

REM Store the Python process PIDs
set PYTHON_PIDS_FILE=%TEMP%\injecticide_pids.txt
del %PYTHON_PIDS_FILE% 2>nul

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Function to kill all Python processes we started
:CLEANUP
echo.
echo Cleaning up processes...

REM Kill all Python processes (nuclear option but effective)
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
taskkill /F /IM uvicorn.exe 2>nul

echo Cleanup complete!
goto :EOF

REM Set up trap for window close
if "%1"=="LAUNCHER" goto LAUNCH

REM Restart with wrapper to catch close
start "Injecticide Server" /WAIT cmd /c "%~f0" LAUNCHER
goto CLEANUP

:LAUNCH
echo Starting server...
echo.
echo Server will run at: http://localhost:8080
echo.
echo TO STOP: Close this window or press Ctrl+C
echo ==========================================
echo.

cd /d P:\Injecticide

REM Start the server
python run_web_safe.py

REM If we get here, server stopped
echo.
echo Server stopped.
exit
