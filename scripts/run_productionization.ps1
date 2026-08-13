param(
    [string]$Python = '',
    [string]$AuthorizedJsonl = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }

Push-Location $projectRoot
try {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_openbao_kms_ha_e2e.ps1 -Python $venvPython
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\run_qemu_native_isolation_e2e.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if ($AuthorizedJsonl -ne '') {
        if (-not (Test-Path -LiteralPath $AuthorizedJsonl)) { throw 'Authorized JSONL file not found' }
        if (-not $env:AGENTGUARD_REDACTION_SALT_HEX) { throw 'AGENTGUARD_REDACTION_SALT_HEX is required' }
        $redactedDir = Join-Path $projectRoot 'datasets\authorized_redacted'
        New-Item -ItemType Directory -Path $redactedDir -Force | Out-Null
        & $venvPython .\integrations\redact_dataset.py `
            --input $AuthorizedJsonl `
            --output (Join-Path $redactedDir 'authorized_redacted.jsonl') `
            --report (Join-Path $projectRoot 'reports\authorized_data_redaction.json')
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    & $venvPython .\scripts\run_authorized_business_api_e2e.py
    if ($LASTEXITCODE -notin @(0, 2)) { exit $LASTEXITCODE }

    & $venvPython .\scripts\prepublish_security_check.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\generate_productionization_status.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
