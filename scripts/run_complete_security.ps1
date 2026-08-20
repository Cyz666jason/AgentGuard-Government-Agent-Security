param(
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$projectRoot = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $projectRoot 'reports'
$coreReportDir = Join-Path $reportDir 'core'
$demoReportDir = Join-Path $reportDir 'demos'
$networkReportDir = Join-Path $reportDir 'e2e\network'
$identityReportDir = Join-Path $reportDir 'e2e\identity'
$preflightReportDir = Join-Path $reportDir 'preflight'
$statusReportDir = Join-Path $reportDir 'status'
$opaPath = Join-Path $projectRoot 'tools\opa.exe'
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw '未找到 Python 虚拟环境，请先运行 scripts/setup_full.ps1'
}

foreach ($directory in @(
    $reportDir, $coreReportDir, $demoReportDir, $networkReportDir,
    $identityReportDir, $preflightReportDir, $statusReportDir
)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
& (Join-Path $PSScriptRoot 'bootstrap_opa.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $projectRoot
try {
    & $opaPath check --strict policy tests data
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $opaPath check --strict deployment\opa-envoy
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $envoyPolicyOutput = & $opaPath test deployment\opa-envoy -v --fail-on-empty 2>&1
    $envoyPolicyExitCode = $LASTEXITCODE
    $envoyPolicyOutput | Set-Content -LiteralPath (Join-Path $networkReportDir 'opa_envoy_policy_tests.txt') -Encoding UTF8
    if ($envoyPolicyExitCode -ne 0) { exit $envoyPolicyExitCode }

    $opaOutput = & $opaPath test policy tests data -v --fail-on-empty 2>&1
    $opaExitCode = $LASTEXITCODE
    $opaOutput | Set-Content -LiteralPath (Join-Path $coreReportDir 'full_opa_tests.txt') -Encoding UTF8
    if ($opaExitCode -ne 0) { exit $opaExitCode }

    & $venvPython .\scripts\evaluate.py --opa $opaPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $pythonOutput = & $venvPython -m enforcement.run_tests
    $pythonExitCode = $LASTEXITCODE
    $pythonOutput | Set-Content -LiteralPath (Join-Path $coreReportDir 'full_python_tests.txt') -Encoding UTF8
    if ($pythonExitCode -ne 0) { exit $pythonExitCode }

    & $venvPython .\scripts\run_public_benchmark_evaluation.py smoke
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\run_stage4_preflight.py
    $stage4PreflightExitCode = $LASTEXITCODE
    if ($stage4PreflightExitCode -notin @(0, 2)) { exit $stage4PreflightExitCode }

    & $venvPython .\scripts\run_network_e2e.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'network_enforcement_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $keycloakZip = Join-Path $projectRoot 'third_party\downloads\keycloak-26.7.1.zip'
    $javaZip = Join-Path $projectRoot 'third_party\downloads\OpenJDK21U-jre_x64_windows_hotspot.zip'
    if (-not (Test-Path -LiteralPath $keycloakZip) -or -not (Test-Path -LiteralPath $javaZip)) {
        throw 'Missing portable Keycloak/Java test packages; follow third_party/README.md.'
    }
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_keycloak_oidc_e2e.ps1 |
        Set-Content -LiteralPath (Join-Path $reportDir 'keycloak_oidc_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    foreach ($scenario in @(
        'allow', 'pending', 'deny', 'approved', 'replay', 'tamper',
        'opa_down', 'full_chain', 'kernel_loop', 'kernel_wasi'
    )) {
        & $venvPython -m enforcement.demo --scenario $scenario |
            Set-Content -LiteralPath (Join-Path $demoReportDir "full_demo_$scenario.json") -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    & $venvPython -m enforcement.test_machine |
        Set-Content -LiteralPath (Join-Path $preflightReportDir 'test_machine_environment.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_openbao_kms_ha_e2e.ps1 -Python $venvPython |
        Set-Content -LiteralPath (Join-Path $reportDir 'openbao_kms_ha_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\run_openbao_raft_ha_e2e.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'openbao_raft_ha_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\run_qemu_native_isolation_e2e.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'qemu_native_isolation_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\run_container_product_e2e.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'container_product_e2e_console.json') -Encoding UTF8
    if ($LASTEXITCODE -notin @(0, 2)) { exit $LASTEXITCODE }

    & $venvPython .\scripts\generate_evidence_precedence.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython -m enforcement.generate_report |
        Set-Content -LiteralPath (Join-Path $reportDir 'full_security_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\generate_route_progress.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'open_source_route_progress_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\generate_productionization_status.py |
        Set-Content -LiteralPath (Join-Path $reportDir 'productionization_status_console.json') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $venvPython .\scripts\check_status_consistency.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

Write-Host "完整安全原型测试通过。主报告：$coreReportDir\full_security_evaluation_report.md"
Write-Host "开源路线进度已刷新：$statusReportDir\open_source_route_progress.md"
