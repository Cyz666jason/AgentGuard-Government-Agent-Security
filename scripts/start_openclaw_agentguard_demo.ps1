<#
.SYNOPSIS
Start the isolated loopback OpenClaw Gateway used by the AgentGuard demo.

.DESCRIPTION
Run setup_openclaw_agentguard_demo.ps1 first.  The default mode starts
`gateway run` as a hidden child process, writes only non-sensitive process
metadata into the ignored demo runtime directory, and verifies Gateway health.

Use -Foreground when you prefer to keep the Gateway logs in the current
PowerShell window.  No Windows service is installed and no existing listener
is stopped.  If the preferred port is occupied, a free loopback fallback port
is selected and saved into the isolated configuration.
#>

[CmdletBinding()]
param(
    [string]$NodePath,
    [ValidateRange(1024, 65535)]
    [int]$PreferredPort = 18789,
    [switch]$Foreground,
    [switch]$OpenControlUi
)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

function Show-OpenClawDemoStartResult {
    param(
        [string]$Status,
        [int]$Port,
        [AllowNull()]
        [object]$ProcessId,
        [bool]$GatewayHealthy,
        [bool]$ControlUiOpened,
        [string]$AgentGuardBackendStatus
    )

    [ordered]@{
        status = $Status
        gateway_healthy = $GatewayHealthy
        gateway_bind = 'loopback'
        control_ui_url = "http://127.0.0.1:$Port/"
        port = $Port
        process_id = $ProcessId
        agentguard_backend = $AgentGuardBackendStatus
        global_openclaw_used = $false
        gateway_token_recorded = $false
        control_ui_opened = $ControlUiOpened
        note = '页面可访问；Gateway token 不会打印、写入报告或传给远程地址。'
    } | ConvertTo-Json -Depth 6
}

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath
    if (-not (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf)) {
        throw '项目内 OpenClaw 不存在。请先运行 setup_openclaw_agentguard_demo.ps1。'
    }
    $config = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    Initialize-OpenClawDemoDirectories -Paths $paths

    $agentGuardBackendStatus = 'external_configuration'
    $configuredAgentGuardUrl = $config.mcp.servers.'agentguard-notices'.env.AGENTGUARD_MCP_BASE_URL
    if ($configuredAgentGuardUrl -eq 'http://127.0.0.1:8080') {
        $agentGuardStart = Start-OpenClawDemoAgentGuardBackend -Paths $paths -Port 8080 -OpaPort 8181
        $agentGuardBackendStatus = [string]$agentGuardStart.Status
    }

    $token = New-OpenClawDemoGatewayToken -TokenPath $paths.GatewayTokenPath
    $record = Get-OpenClawDemoGatewayProcessRecord -Paths $paths
    $configHash = Get-OpenClawDemoFileSha256 -Path $paths.ConfigPath
    $expectedNode = (Resolve-Path -LiteralPath $node).Path
    $expectedEntry = (Resolve-Path -LiteralPath $paths.OpenClawEntry).Path
    $recordIsCurrent = $false
    if ($null -ne $record -and $null -ne $record.PSObject.Properties['port']) {
        $recordPortCandidate = [int]$record.PSObject.Properties['port'].Value
        $recordIsCurrent = Test-OpenClawDemoGatewayProcessRunning `
            -Record $record `
            -ExpectedConfigHash $configHash `
            -ExpectedPort $recordPortCandidate `
            -ExpectedNodePath $expectedNode `
            -ExpectedOpenClawEntry $expectedEntry `
            -ExpectedConfigPath $paths.ConfigPath
    }
    if ($recordIsCurrent) {
        $recordPort = [int]$record.port
        $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $recordPort -GatewayToken $token
        try {
            $health = Wait-OpenClawDemoGatewayHealth `
                -NodePath $node `
                -OpenClawEntry $paths.OpenClawEntry `
                -Port $recordPort `
                -Attempts 1
        }
        finally {
            Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
        }
        if ($health.Healthy) {
            $opened = $false
            if ($OpenControlUi) {
                Start-Process -FilePath "http://127.0.0.1:$recordPort/"
                $opened = $true
            }
            Show-OpenClawDemoStartResult `
                -Status 'already_running' `
                -Port $recordPort `
                -ProcessId ([int]$record.process_id) `
                -GatewayHealthy $true `
                -ControlUiOpened $opened `
                -AgentGuardBackendStatus $agentGuardBackendStatus
            exit 0
        }
    }

    # A configuration update intentionally invalidates the record hash.  Stop
    # the old isolated demo Gateway only after independently proving its PID,
    # start time, executable and full command identity.  Never touch another
    # listener merely because it occupies a preferred port.
    if ($null -ne $record -and (Test-OpenClawDemoGatewayProcessIdentity `
            -Record $record `
            -ExpectedNodePath $expectedNode `
            -ExpectedOpenClawEntry $expectedEntry)) {
        $staleProcessId = [int]($record.process_id)
        Stop-Process -Id $staleProcessId -Force -ErrorAction Stop
        Wait-Process -Id $staleProcessId -Timeout 10 -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $paths.GatewayProcessPath -Force -ErrorAction SilentlyContinue
    }

    $selectedPort = Select-OpenClawDemoGatewayPort -PreferredPort $PreferredPort
    Set-OpenClawDemoGatewayPort -Paths $paths -GatewayPort $selectedPort
    $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $selectedPort -GatewayToken $token
    try {
        if ($Foreground) {
            Write-Host "OpenClaw Control UI: http://127.0.0.1:$selectedPort/"
            Write-Host 'Gateway 正在前台运行；不会打印 Gateway token。按 Ctrl+C 停止。'
            & $node $paths.OpenClawEntry gateway run --bind loopback --port $selectedPort --auth token
            $gatewayExitCode = $LASTEXITCODE
            if ($gatewayExitCode -ne 0) {
                throw "OpenClaw Gateway 已退出（退出码 $gatewayExitCode）。"
            }
            exit 0
        }

        $gatewayProcess = Start-OpenClawDemoGatewayBackground `
            -NodePath $node `
            -OpenClawEntry $paths.OpenClawEntry `
            -ProjectRoot $projectRoot `
            -Paths $paths `
            -Port $selectedPort
        $newProcessId = [int]$gatewayProcess.Id
        try {
            Write-OpenClawDemoGatewayProcessRecord `
                -Paths $paths `
                -ProcessId $newProcessId `
                -Port $selectedPort `
                -NodePath $expectedNode `
                -OpenClawEntry $expectedEntry `
                -Status 'starting'

            $health = Wait-OpenClawDemoGatewayHealth `
                -NodePath $node `
                -OpenClawEntry $paths.OpenClawEntry `
                -Port $selectedPort
            if (-not $health.Healthy) {
                # Only terminate the process created by this invocation.  Never
                # use --force or stop an unrelated listener on the port.
                Stop-Process -Id $newProcessId -Force -ErrorAction SilentlyContinue
                Write-OpenClawDemoGatewayProcessRecord `
                    -Paths $paths `
                    -ProcessId $newProcessId `
                    -Port $selectedPort `
                    -NodePath $expectedNode `
                    -OpenClawEntry $expectedEntry `
                    -Status 'failed_to_become_ready'
                throw "Gateway 未在预期时间内健康。请检查已忽略的日志目录：$($paths.LogDir)"
            }
            Write-OpenClawDemoGatewayProcessRecord `
                -Paths $paths `
                -ProcessId $newProcessId `
                -Port $selectedPort `
                -NodePath $expectedNode `
                -OpenClawEntry $expectedEntry `
                -Status 'ready'
        }
        catch {
            # If record creation itself failed, still clean up this invocation's
            # child.  Stop-Process is scoped to the PID returned above.
            if ($null -ne $gatewayProcess -and (Get-Process -Id $newProcessId -ErrorAction SilentlyContinue)) {
                Stop-Process -Id $newProcessId -Force -ErrorAction SilentlyContinue
            }
            throw
        }

        $opened = $false
        if ($OpenControlUi) {
            Start-Process -FilePath "http://127.0.0.1:$selectedPort/"
            $opened = $true
        }
        Show-OpenClawDemoStartResult `
            -Status 'started' `
            -Port $selectedPort `
            -ProcessId $gatewayProcess.Id `
            -GatewayHealthy $true `
            -ControlUiOpened $opened `
            -AgentGuardBackendStatus $agentGuardBackendStatus
    }
    finally {
        Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
