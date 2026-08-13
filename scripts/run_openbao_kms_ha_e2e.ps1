param(
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }

$bao = Get-Command bao.exe -ErrorAction SilentlyContinue
if ($null -eq $bao) {
    $bao = Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter bao.exe -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($null -eq $bao) { throw 'bao.exe not found; install OpenBao.OpenBao' }
$baoPath = if ($bao.PSObject.Properties.Name -contains 'Source') { $bao.Source } else { $bao.FullName }

$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$rng.Dispose()
$devToken = ($tokenBytes | ForEach-Object { $_.ToString('x2') }) -join ''
$env:AGENTGUARD_BAO_ADDR = 'http://127.0.0.1:18200'
$env:AGENTGUARD_BAO_TOKEN = $devToken
$logDir = Join-Path $projectRoot 'reports\openbao_state'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdout = Join-Path $logDir 'openbao_stdout.log'
$stderr = Join-Path $logDir 'openbao_stderr.log'
$process = Start-Process -FilePath $baoPath `
    -ArgumentList @('server', '-dev', "-dev-root-token-id=$devToken", '-dev-listen-address=127.0.0.1:18200') `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -Uri "$env:AGENTGUARD_BAO_ADDR/v1/sys/health" -TimeoutSec 1
            if ($health.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) { throw 'OpenBao dev server did not become ready' }
    Push-Location $projectRoot
    try {
        & $venvPython .\scripts\run_openbao_kms_ha_e2e.py
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
} finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    Remove-Item Env:AGENTGUARD_BAO_TOKEN -ErrorAction SilentlyContinue
}
