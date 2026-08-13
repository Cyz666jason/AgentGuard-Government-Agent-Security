param(
    [string]$Version = 'v1.19.0'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolDir = Join-Path $projectRoot 'tools'
$opaPath = Join-Path $toolDir 'opa.exe'
$checksumPath = Join-Path $toolDir 'opa.exe.sha256'
New-Item -ItemType Directory -Path $toolDir -Force | Out-Null

if (Test-Path -LiteralPath $opaPath) {
    $installed = (& $opaPath version | Select-String '^Version:').ToString().Split(':', 2)[1].Trim()
    if ($installed -eq $Version.TrimStart('v')) {
        Write-Host "OPA $installed 已安装：$opaPath"
        exit 0
    }
}

$base = "https://github.com/open-policy-agent/opa/releases/download/$Version"
Write-Host "正在从 OPA 官方 GitHub 下载 $Version ..."
Invoke-WebRequest -Uri "$base/opa_windows_amd64.exe" -OutFile $opaPath
Invoke-WebRequest -Uri "$base/opa_windows_amd64.exe.sha256" -OutFile $checksumPath

$expected = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $opaPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -ne $actual) {
    throw "OPA 校验和不一致：expected=$expected actual=$actual"
}

& $opaPath version
