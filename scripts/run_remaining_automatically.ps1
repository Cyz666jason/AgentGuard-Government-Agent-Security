param(
    [string]$Python = '',
    [string]$AuthorizedJsonl = '',
    [string]$Repository = 'agentguard-government-agent-security',
    [ValidateSet('private', 'internal', 'public')]
    [string]$Visibility = 'private',
    [switch]$PublishGitHub
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if ($Python -ne '') { $venvPython = $Python }
$reportPath = Join-Path $projectRoot 'reports\automatic_remaining_run.json'
$items = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Detail)
    $items.Add([ordered]@{ item = $Name; status = $Status; detail = $Detail })
}

function Invoke-PythonStep {
    param([string]$Name, [string[]]$Arguments, [int[]]$AllowedExitCodes = @(0))
    & $venvPython @Arguments
    $code = $LASTEXITCODE
    if ($code -in $AllowedExitCodes) {
        $status = if ($code -eq 0) { 'completed' } else { 'skipped_missing_external_input' }
        Add-Result $Name $status "exit_code=$code"
        return
    }
    Add-Result $Name 'failed' "exit_code=$code"
    throw "$Name failed with exit code $code"
}

function Find-GitHubCli {
    $command = Get-Command gh.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }
    $candidate = Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" `
        -Recurse -Filter gh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $candidate) { return $candidate.FullName }
    return $null
}

Push-Location $projectRoot
try {
    Invoke-PythonStep 'OpenBao three-node Raft failover' @('.\scripts\run_openbao_raft_ha_e2e.py')
    Invoke-PythonStep 'QEMU isolated Linux guest kernel' @('.\scripts\run_qemu_native_isolation_e2e.py')

    $runtimeReady = $false
    foreach ($runtime in @('docker', 'podman')) {
        $command = Get-Command $runtime -ErrorAction SilentlyContinue
        if ($null -eq $command) { continue }
        & $command.Source info *> $null
        if ($LASTEXITCODE -eq 0) {
            $runtimeReady = $true
            Add-Result 'Product container runtime' 'ready' "$runtime is available"
            break
        }
    }
    if (-not $runtimeReady) {
        Add-Result 'OPA-Envoy/ToolHive product container E2E' 'blocked_external_environment' 'Docker/Podman daemon is unavailable on this Windows test machine'
    } else {
        Add-Result 'OPA-Envoy/ToolHive product container E2E' 'ready_for_linux_runner' 'Container runtime is ready; execute the pinned deployment configuration on a Linux host'
    }

    if ($AuthorizedJsonl -ne '') {
        if (-not (Test-Path -LiteralPath $AuthorizedJsonl)) { throw 'Authorized JSONL file not found' }
        if (-not $env:AGENTGUARD_REDACTION_SALT_HEX) { throw 'AGENTGUARD_REDACTION_SALT_HEX is required' }
        $redactedDir = Join-Path $projectRoot 'datasets\authorized_redacted'
        New-Item -ItemType Directory -Path $redactedDir -Force | Out-Null
        Invoke-PythonStep 'Authorized production data redaction' @(
            '.\integrations\redact_dataset.py',
            '--input', $AuthorizedJsonl,
            '--output', (Join-Path $redactedDir 'authorized_redacted.jsonl'),
            '--report', (Join-Path $projectRoot 'reports\authorized_data_redaction.json')
        )
    } else {
        Add-Result 'Authorized production data redaction' 'skipped_missing_external_input' 'No approved source JSONL was supplied'
    }

    Invoke-PythonStep 'Authorized business API credential-gated E2E' @('.\scripts\run_authorized_business_api_e2e.py') @(0, 2)
    Invoke-PythonStep 'Pre-publication secret scan' @('.\scripts\prepublish_security_check.py')
    Invoke-PythonStep 'Productionization status report' @('.\scripts\generate_productionization_status.py')

    $ghPath = Find-GitHubCli
    if ($null -eq $ghPath) {
        Add-Result 'GitHub private repository publication' 'blocked_external_environment' 'GitHub CLI is not installed'
    } else {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $ghPath auth status *> $null
        $authCode = $LASTEXITCODE
        $ErrorActionPreference = $oldPreference
        if ($authCode -ne 0) {
            Add-Result 'GitHub private repository publication' 'blocked_user_authentication' 'Run gh auth login --web --git-protocol https once, then rerun this script with -PublishGitHub'
        } elseif (-not $PublishGitHub) {
            Add-Result 'GitHub private repository publication' 'ready_awaiting_publish_switch' 'Authentication is ready; rerun with -PublishGitHub to create/push the private repository'
        } else {
            powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\publish_private_github.ps1 `
                -Repository $Repository -Visibility $Visibility
            if ($LASTEXITCODE -ne 0) { throw "GitHub publication failed with exit code $LASTEXITCODE" }
            Add-Result 'GitHub private repository publication' 'completed' "$Visibility repository=$Repository"
        }
    }
} finally {
    $report = [ordered]@{
        generated_at = [DateTimeOffset]::Now.ToString('o')
        all_automatable_steps_succeeded = -not [bool]($items | Where-Object { $_.status -eq 'failed' })
        items = $items
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Pop-Location
}

Write-Host "Automatic continuation report: $reportPath"
