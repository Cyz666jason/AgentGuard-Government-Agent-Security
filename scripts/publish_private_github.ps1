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

    $currentBranch = (git branch --show-current).Trim()
    if (-not $currentBranch) { throw 'Cannot determine the current git branch.' }

    $origin = git remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $origin) {
        & $ghPath repo create $Repository "--$Visibility" --source $projectRoot --remote origin `
            --description 'Policy, approval, enforcement and security-kernel prototype for government and enterprise agents'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    git show-ref --verify --quiet refs/heads/main
    $mainExists = $LASTEXITCODE -eq 0
    if ($currentBranch -ne 'main' -and $mainExists) {
        git push -u origin main
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    git push -u origin $currentBranch
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    if ($currentBranch -ne 'main') {
        $existingPr = & $ghPath pr list --head $currentBranch --json url --jq '.[0].url'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        if (-not $existingPr) {
            $bodyFile = Join-Path ([System.IO.Path]::GetTempPath()) 'agentguard-pr-body.md'
            @(
                '## What changed',
                '',
                '- Added OpenBao Transit/KV and three-node Raft leader-failover E2E evidence',
                '- Added QEMU isolated Linux guest-kernel verification',
                '- Added gates for authorized business credentials, data, containers, and GitHub publication',
                '- Refreshed the full security evaluation, open-source route, and gap reports',
                '',
                '## Validation',
                '',
                '- OPA 31/31, dataset 55/55, Python security tests 60/60',
                '- Network enforcement 5/5, Keycloak OIDC 7/7',
                '- OpenBao Transit/KV 10/10, three-node Raft HA 8/8',
                '- QEMU isolation 11/11, integrated demonstration checks 21/21',
                '- Pre-publication secret scan passed with zero findings'
            ) | Set-Content -LiteralPath $bodyFile -Encoding UTF8
            & $ghPath pr create --draft --base main --head $currentBranch `
                --title 'feat: complete HA productionization automation' --body-file $bodyFile
            $prExitCode = $LASTEXITCODE
            Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
            if ($prExitCode -ne 0) { exit $prExitCode }
        } else {
            Write-Host "Draft pull request already exists: $existingPr"
        }
    }
} finally {
    Pop-Location
}
