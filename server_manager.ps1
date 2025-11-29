# Injecticide Web Server Manager
# Properly tracks and kills all child processes

$ErrorActionPreference = "SilentlyContinue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  INJECTICIDE WEB SERVER MANAGER" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Store the main process info
$script:MainPID = $null
$script:ChildPIDs = @()

function Start-InjecticideServer {
    Write-Host "`n[*] Starting Injecticide Web Server..." -ForegroundColor Green
    
    # Start the Python server and capture its PID
    $process = Start-Process -FilePath "python" `
                            -ArgumentList "run_web_safe.py" `
                            -WorkingDirectory "P:\Injecticide" `
                            -PassThru `
                            -NoNewWindow
    
    $script:MainPID = $process.Id
    Write-Host "[*] Server started with PID: $($script:MainPID)" -ForegroundColor Yellow
    
    # Wait a moment for child processes to spawn
    Start-Sleep -Seconds 2
    
    # Get all child processes
    $script:ChildPIDs = Get-WmiObject Win32_Process | 
                        Where-Object { $_.ParentProcessId -eq $script:MainPID } | 
                        Select-Object -ExpandProperty ProcessId
    
    if ($script:ChildPIDs) {
        Write-Host "[*] Child processes detected: $($script:ChildPIDs -join ', ')" -ForegroundColor Yellow
    }
    
    Write-Host "`n[*] Server is running at http://localhost:8080" -ForegroundColor Green
    Write-Host "[*] Press Ctrl+C or close this window to stop the server" -ForegroundColor Cyan
    
    # Monitor the process
    while ($true) {
        if (-not (Get-Process -Id $script:MainPID -ErrorAction SilentlyContinue)) {
            Write-Host "`n[!] Server process has stopped" -ForegroundColor Red
            break
        }
        Start-Sleep -Seconds 1
    }
}

function Stop-InjecticideServer {
    Write-Host "`n[*] Stopping Injecticide Server..." -ForegroundColor Yellow
    
    # Kill child processes first
    if ($script:ChildPIDs) {
        foreach ($pid in $script:ChildPIDs) {
            Write-Host "  - Killing child process $pid" -ForegroundColor Gray
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Kill main process
    if ($script:MainPID) {
        Write-Host "  - Killing main process $($script:MainPID)" -ForegroundColor Gray
        Stop-Process -Id $script:MainPID -Force -ErrorAction SilentlyContinue
    }
    
    # Kill any remaining Python processes (nuclear option)
    $pythonProcesses = Get-Process python, pythonw -ErrorAction SilentlyContinue
    if ($pythonProcesses) {
        Write-Host "  - Found $($pythonProcesses.Count) remaining Python processes" -ForegroundColor Yellow
        $pythonProcesses | Stop-Process -Force
    }
    
    Write-Host "[*] All processes terminated" -ForegroundColor Green
}

# Set up cleanup on exit
Register-EngineEvent PowerShell.Exiting -Action { Stop-InjecticideServer }

# Handle Ctrl+C
[Console]::TreatControlCAsInput = $false
$null = [Console]::CancelKeyPress.Add({
    Write-Host "`n[!] Interrupt received" -ForegroundColor Red
    Stop-InjecticideServer
    exit
})

try {
    Start-InjecticideServer
}
finally {
    Stop-InjecticideServer
    Write-Host "`nServer stopped. Files should be unlocked now." -ForegroundColor Green
}
