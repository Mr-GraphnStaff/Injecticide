@echo off
echo ==========================================
echo   INJECTICIDE - EMERGENCY KILL SWITCH
echo ==========================================
echo.
echo This will forcefully terminate ALL Python processes
echo and unlock any files that are stuck.
echo.
echo Press Ctrl+C to cancel, or
pause

echo.
echo [1] Killing all Python processes...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
taskkill /F /IM py.exe 2>nul

echo [2] Killing any uvicorn processes...
taskkill /F /IM uvicorn.exe 2>nul

echo [3] Killing any node processes (if React dev server)...
taskkill /F /IM node.exe 2>nul

echo [4] Waiting for processes to fully terminate...
timeout /t 3 /nobreak >nul

echo [5] Checking for remaining Python processes...
echo.
tasklist | findstr /I python
if %ERRORLEVEL% == 0 (
    echo.
    echo WARNING: Some Python processes still running!
    echo Attempting aggressive termination...
    
    REM Get all Python PIDs and kill them
    for /f "tokens=2" %%i in ('tasklist ^| findstr /I python') do (
        echo Killing PID %%i
        taskkill /F /PID %%i 2>nul
    )
) else (
    echo No Python processes found - GOOD!
)

echo.
echo [6] Testing file access...
echo. > P:\Injecticide\test_unlock.tmp 2>nul
if exist P:\Injecticide\test_unlock.tmp (
    del P:\Injecticide\test_unlock.tmp
    echo Files appear to be unlocked - SUCCESS!
) else (
    echo WARNING: Files may still be locked!
)

echo.
echo ==========================================
echo   CLEANUP COMPLETE
echo ==========================================
echo.
echo You should now be able to:
echo - Edit all files
echo - Run git commands
echo - Start the web server fresh
echo.
pause
