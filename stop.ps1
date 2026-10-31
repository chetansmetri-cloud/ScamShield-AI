$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunDirectory = Join-Path $ProjectRoot ".run"
$StopRequestFile = Join-Path $RunDirectory "stop.request"
$ProcessFiles = @(
    @{ Path = (Join-Path $RunDirectory "frontend.pid"); Pattern = "streamlit\s+run\s+frontend[\\/]+streamlit_app\.py" },
    @{ Path = (Join-Path $RunDirectory "backend.pid"); Pattern = "-m\s+uvicorn\s+app\.main:app" }
)

if (-not (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
    Write-Host "No ScamShield launcher state found."
    exit 0
}

Set-Content -LiteralPath $StopRequestFile -Value "stop" -NoNewline
$stopped = 0

foreach ($entry in $ProcessFiles) {
    if (-not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
        continue
    }

    $rawPid = Get-Content -LiteralPath $entry.Path -Raw
    $processId = 0
    if (-not [int]::TryParse($rawPid.Trim(), [ref]$processId)) {
        Write-Warning "Ignoring invalid launcher PID file: $($entry.Path)"
        continue
    }

    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
    if ($null -eq $processInfo) {
        Remove-Item -LiteralPath $entry.Path -Force -ErrorAction SilentlyContinue
        continue
    }

    if ($processInfo.Name -notmatch "^python(w)?\.exe$" -or $processInfo.CommandLine -notmatch $entry.Pattern) {
        Write-Warning "PID $processId no longer matches the expected ScamShield service; leaving it untouched."
        continue
    }

    Stop-Process -Id $processId -ErrorAction Stop
    $stopped++
    Remove-Item -LiteralPath $entry.Path -Force -ErrorAction SilentlyContinue
}

Write-Host "Stop requested. Stopped $stopped ScamShield service process(es)."
