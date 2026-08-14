param([string]$Python = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }

# The cloud image path depends on an IO-APIC timer unsupported by TCG on this
# Windows host.  The live launcher direct-boots the same Alpine kernel with
# noapic, provisions Docker and SSH, and binds all forwarded ports to loopback.
Push-Location $projectRoot
try {
    & $venvPython .\scripts\run_live_container_host.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
Write-Host 'QEMU Linux container host ready. SSH=root@127.0.0.1:2222'
