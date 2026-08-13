param(
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$projectRoot = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $projectRoot 'reports'
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'

if ($Python -ne '') {
    $venvPython = $Python
}
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw '未找到审批环境，请先运行 scripts/setup_approval.ps1'
}

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
Push-Location $projectRoot
try {
    $testOutput = & $venvPython -m approval.run_tests
    $testExitCode = $LASTEXITCODE
    $testOutput | Set-Content -LiteralPath (Join-Path $reportDir 'approval_unit_tests.txt') -Encoding UTF8
    $testOutput | Write-Output
    if ($testExitCode -ne 0) { exit $testExitCode }

    foreach ($scenario in @('allow', 'approve', 'reject', 'tamper')) {
        & $venvPython -m approval.demo --scenario $scenario |
            Set-Content -LiteralPath (Join-Path $reportDir "approval_demo_$scenario.json") -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    & $venvPython -m approval.generate_report |
        Set-Content -LiteralPath (Join-Path $reportDir 'approval_evaluation_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

Write-Host "审批工作流全部测试通过。报告目录：$reportDir"
