@echo off
echo Fixing Injecticide permission issues...
echo.

REM Try to close any Python processes
taskkill /F /IM python.exe 2>nul
taskkill /F /IM pythonw.exe 2>nul

echo Waiting for processes to close...
timeout /t 2 /nobreak >nul

REM Try to delete the locked file
echo Attempting to delete locked endpoints.py...
del /F /Q P:\Injecticide\endpoints.py 2>nul

if exist P:\Injecticide\endpoints.py (
    echo.
    echo WARNING: Could not delete endpoints.py - it's still locked!
    echo Please close any programs that might be using this file:
    echo  - VSCode
    echo  - PyCharm
    echo  - Notepad++
    echo  - Any Python scripts
    echo.
    echo Then run this script again.
    echo.
    echo As a workaround, we've created endpoints_fixed.py with the corrections.
    echo You can manually rename it to endpoints.py after closing the locking program.
) else (
    echo Successfully removed locked file.
    
    REM Rename the fixed file
    if exist P:\Injecticide\endpoints_fixed.py (
        move /Y P:\Injecticide\endpoints_fixed.py P:\Injecticide\endpoints.py
        echo Successfully replaced endpoints.py with fixed version!
    )
)

echo.
echo Current status:
dir P:\Injecticide\endpoints*.py 2>nul

echo.
echo Done!
pause
