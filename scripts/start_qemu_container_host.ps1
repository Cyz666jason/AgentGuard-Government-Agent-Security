param([string]$Python = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }
$state = Join-Path $projectRoot 'reports\qemu_container_host'
$sourceDisk = Join-Path $projectRoot 'third_party\downloads\alpine-cloud.qcow2'
$qemuDir = Join-Path $projectRoot 'third_party\runtime\qemu'
$asciiRoot = 'C:\Windows\Temp\agentguard-container-host'
New-Item -ItemType Directory -Path $state -Force | Out-Null
New-Item -ItemType Directory -Path $asciiRoot -Force | Out-Null
$key = Join-Path $state 'id_ed25519'
Push-Location $projectRoot
try {
    & $venvPython .\scripts\prepare_qemu_container_host.py --state-dir $state --source-disk $sourceDisk
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally { Pop-Location }
Copy-Item -LiteralPath (Join-Path $state 'base.qcow2') -Destination (Join-Path $asciiRoot 'base.qcow2') -Force
Copy-Item -LiteralPath (Join-Path $state 'seed.iso') -Destination (Join-Path $asciiRoot 'seed.iso') -Force
if (-not (Test-Path -LiteralPath (Join-Path $asciiRoot 'qemu\qemu-system-x86_64.exe'))) {
    Copy-Item -LiteralPath $qemuDir -Destination (Join-Path $asciiRoot 'qemu') -Recurse -Force
}
$qemu = Join-Path $asciiRoot 'qemu\qemu-system-x86_64.exe'
$qemuImg = Join-Path $asciiRoot 'qemu\qemu-img.exe'
$overlay = Join-Path $asciiRoot 'overlay.qcow2'
if (Test-Path -LiteralPath $overlay) { Remove-Item -LiteralPath $overlay -Force }
& $qemuImg create -f qcow2 -F qcow2 -b (Join-Path $asciiRoot 'base.qcow2') $overlay
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$stdout = Join-Path $state 'container_host_stdout.log'
$stderr = Join-Path $state 'container_host_stderr.log'
$arguments = @(
    '-L', (Join-Path $asciiRoot 'qemu\share'),
    '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '1', '-m', '1536M',
    '-drive', "file=$overlay,if=virtio,format=qcow2",
    '-drive', "file=$(Join-Path $asciiRoot 'seed.iso'),media=cdrom,readonly=on",
    '-nic', 'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8081-:8081',
    '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot'
)
$process = Start-Process -FilePath $qemu -ArgumentList $arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
Set-Content -LiteralPath (Join-Path $state 'qemu.pid') -Value $process.Id -Encoding ASCII
$ready = $false
$oldPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
for ($attempt = 0; $attempt -lt 180; $attempt++) {
    & ssh.exe -i $key -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=2 agentguard@127.0.0.1 'test -f /opt/agentguard/ready && docker version --format {{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 2
}
$ErrorActionPreference = $oldPreference
if (-not $ready) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    throw 'QEMU Linux container host did not become ready'
}
Write-Host "QEMU Linux container host ready. PID=$($process.Id), SSH=127.0.0.1:2222"
