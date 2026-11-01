$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$RunDirectory = Join-Path $ProjectRoot ".run"
$BackendPidFile = Join-Path $RunDirectory "backend.pid"
$FrontendPidFile = Join-Path $RunDirectory "frontend.pid"
$StopRequestFile = Join-Path $RunDirectory "stop.request"
$BackendLog = Join-Path $RunDirectory "backend.log"
$BackendErrorLog = Join-Path $RunDirectory "backend-error.log"
$FrontendLog = Join-Path $RunDirectory "frontend.log"
$FrontendErrorLog = Join-Path $RunDirectory "frontend-error.log"
$BackendProcess = $null
$FrontendProcess = $null

function Test-PortInUse([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(250)) {
            return $false
        }
        $client.EndConnect($pending)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-HttpReady([string]$Url) {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return [int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 400
    }
    catch {
        return $false
    }
}

function Stop-AppProcess($Process) {
    if ($null -ne $Process) {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -ErrorAction SilentlyContinue
            $Process.WaitForExit(5000)
        }
    }
}

if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "Virtual environment not found. Create it with: py -3 -m venv .venv"
}

Push-Location $ProjectRoot
try {
    & $PythonExe -c "import fastapi, httpx, plotly, reportlab, streamlit, uvicorn"
    if ($LASTEXITCODE -ne 0) {
        throw "Required packages are missing. Run: .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    }

    foreach ($port in @(8000, 8501)) {
        if (Test-PortInUse $port) {
            throw "Port $port is already in use. Stop that service or configure another port before starting ScamShield."
        }
    }

    New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
    Remove-Item -LiteralPath $StopRequestFile -Force -ErrorAction SilentlyContinue
    $BackendProcess = Start-Process `
        -FilePath $PythonExe `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000") `
        -WorkingDirectory $ProjectRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $BackendLog `
        -RedirectStandardError $BackendErrorLog
    Set-Content -LiteralPath $BackendPidFile -Value $BackendProcess.Id -NoNewline

    $FrontendProcess = Start-Process `
        -FilePath $PythonExe `
        -ArgumentList @("-m", "streamlit", "run", "frontend\streamlit_app.py", "--server.headless", "true", "--server.address", "127.0.0.1", "--server.port", "8501") `
        -WorkingDirectory $ProjectRoot `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $FrontendLog `
        -RedirectStandardError $FrontendErrorLog
    Set-Content -LiteralPath $FrontendPidFile -Value $FrontendProcess.Id -NoNewline

    $deadline = (Get-Date).AddSeconds(90)
    $backendReady = $false
    $frontendReady = $false

    while ((Get-Date) -lt $deadline) {
        $BackendProcess.Refresh()
        $FrontendProcess.Refresh()
        if ($BackendProcess.HasExited) {
            throw "FastAPI stopped during startup. Review .run\backend-error.log."
        }
        if ($FrontendProcess.HasExited) {
            throw "Streamlit stopped during startup. Review .run\frontend-error.log."
        }

        if (-not $backendReady) {
            $backendReady = Test-HttpReady "http://127.0.0.1:8000/health"
        }
        if (-not $frontendReady) {
            $frontendReady = Test-HttpReady "http://127.0.0.1:8501/"
        }
        if ($backendReady -and $frontendReady) {
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $backendReady -or -not $frontendReady) {
        throw "Startup timed out. Review the .run log files for the service that did not become ready."
    }

    Write-Host ""
    Write-Host "ScamShield AI is running." -ForegroundColor Cyan
    Write-Host "Dashboard: http://127.0.0.1:8501" -ForegroundColor Green
    Write-Host "FastAPI:   http://127.0.0.1:8000/docs" -ForegroundColor Green
    Write-Host "Press Ctrl+C here or run .\stop.ps1 to stop both services." -ForegroundColor Gray
    Start-Process "http://127.0.0.1:8501"

    while ($true) {
        if (Test-Path -LiteralPath $StopRequestFile) {
            break
        }
        $BackendProcess.Refresh()
        $FrontendProcess.Refresh()
        if ($BackendProcess.HasExited -or $FrontendProcess.HasExited) {
            throw "A ScamShield service exited. Check the matching .run log file."
        }
        Start-Sleep -Seconds 1
    }
}
finally {
    Stop-AppProcess $FrontendProcess
    Stop-AppProcess $BackendProcess
    Remove-Item -LiteralPath $BackendPidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $FrontendPidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StopRequestFile -Force -ErrorAction SilentlyContinue
    Pop-Location
    Write-Host "ScamShield AI services stopped." -ForegroundColor Gray
}
