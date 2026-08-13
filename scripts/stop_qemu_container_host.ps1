$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $projectRoot 'reports\qemu_container_host\qemu.pid'
if (Test-Path -LiteralPath $pidFile) {
    $processId = [int](Get-Content -LiteralPath $pidFile -Raw)
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -ne $process) { Stop-Process -Id $processId -Force }
    Remove-Item -LiteralPath $pidFile -Force
}
