param(
    [string]$Repository = 'agentguard-government-agent-security',
    [ValidateSet('private', 'internal', 'public')]
    [string]$Visibility = 'private'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$gh = Get-Command gh.exe -ErrorAction SilentlyContinue
if ($null -eq $gh) {
    $gh = Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter gh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($null -eq $gh) { throw 'GitHub CLI is not installed.' }
$ghPath = if ($gh.PSObject.Properties.Name -contains 'Source') { $gh.Source } else { $gh.FullName }

Push-Location $projectRoot
try {
    & $python .\scripts\prepublish_security_check.py
    if ($LASTEXITCODE -ne 0) { throw 'Pre-publish secret scan failed; refusing to publish.' }

    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $ghPath auth status *> $null
    $authExitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    if ($authExitCode -ne 0) {
        Write-Host 'GitHub authentication is required. Run: gh auth login --web --git-protocol https'
        exit 2
    }

    $origin = git remote get-url origin 2>$null
    if ($LASTEXITCODE -eq 0 -and $origin) {
        git push -u origin main
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        & $ghPath repo create $Repository "--$Visibility" --source $projectRoot --remote origin --push --description 'Policy, approval, enforcement and security-kernel prototype for government and enterprise agents'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
} finally {
    Pop-Location
}
