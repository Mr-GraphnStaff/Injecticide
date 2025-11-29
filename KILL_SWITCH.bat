@echo off
echo ==========================================
echo   INJECTICIDE - GRACEFUL SHUTDOWN HELPER
echo ==========================================
echo.
echo 1) Use the "Close App" button in the web UI whenever possible.
echo 2) This helper will try a graceful shutdown before doing anything else.
echo.
echo Press Ctrl+C to cancel, or
pause

set SHUTDOWN_URL=http://localhost:8080/api/app/close

echo.
echo [1] Requesting graceful shutdown from the running server...
powershell -Command "try { Invoke-WebRequest -Method POST -Uri '%SHUTDOWN_URL%' -ErrorAction Stop ^| Out-Null; Start-Sleep -Seconds 2; exit 0 } catch { exit 1 }"
if %ERRORLEVEL%==0 (
    echo.
    echo Graceful shutdown requested. If the window stays open, close it manually.
    goto END
)

echo.
echo [2] Graceful shutdown failed or server not running. Performing final cleanup...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul
taskkill /F /IM py.exe 2>nul
taskkill /F /IM uvicorn.exe 2>nul
taskkill /F /IM node.exe 2>nul

echo.
echo [3] Waiting for processes to fully terminate...
timeout /t 3 /nobreak >nul

echo.
echo [4] Checking for remaining Python processes...
tasklist | findstr /I python
if %ERRORLEVEL% == 0 (
    echo Additional Python processes detected. Attempting final termination...
    for /f "tokens=2" %%i in ('tasklist ^| findstr /I python') do (
        taskkill /F /PID %%i 2>nul
    )
) else (
    echo No Python processes found - GOOD!
)

:END
echo.
echo ==========================================
echo   CLEANUP COMPLETE
echo ==========================================
echo.
pause
