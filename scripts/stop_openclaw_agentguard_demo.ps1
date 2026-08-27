<#
.SYNOPSIS
Stop the isolated OpenClaw and AgentGuard demo processes.

.DESCRIPTION
Only processes whose PID, start time, executable and command identity match the
ignored demo records are stopped. Use -RemoveDemoState to also delete the
isolated config, model credential, sessions, logs and synthetic service state.
Use -RemoveProjectLocalOpenClaw only for an explicit full local uninstall.
#>

[CmdletBinding()]
param(
    [string]$NodePath,
    [switch]$RemoveDemoState,
    [switch]$RemoveProjectLocalOpenClaw
)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath
    $expectedNode = (Resolve-Path -LiteralPath $node).Path
    $expectedEntry = if (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf) { (Resolve-Path -LiteralPath $paths.OpenClawEntry).Path } else { $paths.OpenClawEntry }
    $gatewayStopped = $false
    $agentGuardStopped = $false
    $unverifiedLiveProcess = $false

    $gatewayRecord = Get-OpenClawDemoGatewayProcessRecord -Paths $paths
    if ($null -ne $gatewayRecord) {
        $gatewayPid = if ($null -ne $gatewayRecord.PSObject.Properties['process_id']) { [int]($gatewayRecord.process_id) } else { 0 }
        $gatewayAlive = $gatewayPid -gt 0 -and $null -ne (Get-Process -Id $gatewayPid -ErrorAction SilentlyContinue)
        if ($gatewayAlive -and (Test-OpenClawDemoGatewayProcessIdentity -Record $gatewayRecord -ExpectedNodePath $expectedNode -ExpectedOpenClawEntry $expectedEntry)) {
            $childIds = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $gatewayPid" -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.ProcessId })
            foreach ($childId in $childIds) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
            Stop-Process -Id $gatewayPid -Force -ErrorAction Stop
            Wait-Process -Id $gatewayPid -Timeout 10 -ErrorAction SilentlyContinue
            $gatewayStopped = $true
        }
        elseif ($gatewayAlive) {
            $unverifiedLiveProcess = $true
        }
    }

    $agentGuardRecord = Get-OpenClawDemoAgentGuardProcessRecord -Paths $paths
    if ($null -ne $agentGuardRecord) {
        $agentGuardPid = if ($null -ne $agentGuardRecord.PSObject.Properties['process_id']) { [int]($agentGuardRecord.process_id) } else { 0 }
        $agentGuardAlive = $agentGuardPid -gt 0 -and $null -ne (Get-Process -Id $agentGuardPid -ErrorAction SilentlyContinue)
        if ($agentGuardAlive -and (Test-OpenClawDemoAgentGuardProcessIdentity -Record $agentGuardRecord -Paths $paths -Port ([int]$agentGuardRecord.port))) {
            $childIds = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $agentGuardPid" -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.ProcessId })
            foreach ($childId in $childIds) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
            Stop-Process -Id $agentGuardPid -Force -ErrorAction Stop
            Wait-Process -Id $agentGuardPid -Timeout 10 -ErrorAction SilentlyContinue
            $agentGuardStopped = $true
        }
        elseif ($agentGuardAlive) {
            $unverifiedLiveProcess = $true
        }
    }

    if (($RemoveDemoState -or $RemoveProjectLocalOpenClaw) -and $unverifiedLiveProcess) {
        throw '存在与演示记录不匹配的活动 PID；已拒绝删除任何目录。'
    }
    $demoStateRemoved = $false
    if ($RemoveDemoState -and (Test-Path -LiteralPath $paths.DemoRoot -PathType Container)) {
        $resolvedDemoRoot = [System.IO.Path]::GetFullPath($paths.DemoRoot).TrimEnd('\')
        $expectedDemoRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'integrations\openclaw_mcp\.e2e_state\visual-demo')).TrimEnd('\')
        if (-not [string]::Equals($resolvedDemoRoot, $expectedDemoRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolvedDemoRoot.IndexOf($projectRoot, [System.StringComparison]::OrdinalIgnoreCase) -ne 0) {
            throw '演示状态目录解析结果不符合预期；已拒绝删除。'
        }
        Remove-Item -LiteralPath $resolvedDemoRoot -Recurse -Force
        $demoStateRemoved = $true
    }

    $runtimeRemoved = $false
    if ($RemoveProjectLocalOpenClaw -and (Test-Path -LiteralPath $paths.RuntimeDir -PathType Container)) {
        $resolvedRuntime = [System.IO.Path]::GetFullPath($paths.RuntimeDir).TrimEnd('\')
        $expectedRuntime = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'third_party\runtime\openclaw-client')).TrimEnd('\')
        if (-not [string]::Equals($resolvedRuntime, $expectedRuntime, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolvedRuntime.IndexOf($projectRoot, [System.StringComparison]::OrdinalIgnoreCase) -ne 0) {
            throw '项目内 OpenClaw runtime 目录解析结果不符合预期；已拒绝删除。'
        }
        Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force
        $runtimeRemoved = $true
    }

    [pscustomobject][ordered]@{
        status = if ($unverifiedLiveProcess) { 'stopped_verified_processes_with_unverified_pid_left_untouched' } else { 'stopped' }
        gateway_stopped = $gatewayStopped
        agentguard_backend_stopped = $agentGuardStopped
        unverified_process_stopped = $false
        demo_state_removed = $demoStateRemoved
        project_local_openclaw_removed = $runtimeRemoved
        secret_values_recorded = $false
    } | ConvertTo-Json -Depth 5
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
