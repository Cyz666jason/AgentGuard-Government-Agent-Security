param(
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$opaPath = Join-Path $projectRoot 'tools\opa.exe'
$reportDir = Join-Path $projectRoot 'reports\core'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

& (Join-Path $PSScriptRoot 'bootstrap_opa.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python (Join-Path $PSScriptRoot 'generate_dataset.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $projectRoot
try {
    $regoFiles = @(Get-ChildItem -Path policy,tests -Recurse -Filter '*.rego' | Select-Object -ExpandProperty FullName)
    & $opaPath fmt -w @regoFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $opaPath fmt --fail @regoFiles | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $opaPath check --strict policy tests data
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $opaPath version | Set-Content -LiteralPath (Join-Path $reportDir 'opa_version.txt') -Encoding UTF8

    & $opaPath test policy tests data -v --fail-on-empty 2>&1 | Tee-Object -FilePath (Join-Path $reportDir 'unit_tests.txt')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $opaPath test policy tests data --coverage --format=json | Set-Content -LiteralPath (Join-Path $reportDir 'coverage.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $opaPath bench --count 3 --benchmem --metrics -d policy -d data -i samples\allow_low_risk.json 'data.agent.guard.decision' 2>&1 | Set-Content -LiteralPath (Join-Path $reportDir 'benchmark.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

& $Python (Join-Path $PSScriptRoot 'evaluate.py') --opa $opaPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "全部检查通过。核心报告目录：$reportDir"
