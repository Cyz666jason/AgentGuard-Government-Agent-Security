<#
.SYNOPSIS
Prepare an isolated OpenClaw Control UI demo and register the AgentGuard MCP.

.DESCRIPTION
The script uses only the project-local OpenClaw runtime.  If that runtime is
missing or has the wrong version, it installs the fixed, tested package version
into third_party/runtime/openclaw-client.  It never uses or installs a global
openclaw command.

The resulting OpenClaw state, workspace, home, logs and temporary Gateway
credential all live below integrations/openclaw_mcp/.e2e_state/visual-demo,
which is ignored by Git.
#>

[CmdletBinding()]
param(
    [string]$NodePath,
    [string]$PnpmPath,
    [ValidateRange(1024, 65535)]
    [int]$GatewayPort = 18789,
    [string]$AgentGuardBaseUrl = 'http://127.0.0.1:8080'
)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath

    $nodeVersion = (& $node --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Node.js 无法启动（退出码 $LASTEXITCODE）。"
    }

    $installationAction = 'already_present'
    $openclawVersion = $null
    if (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf) {
        try {
            $openclawVersion = Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry
        }
        catch {
            $openclawVersion = $null
        }
    }

    if ($null -eq $openclawVersion -or -not (Test-OpenClawDemoExpectedVersion -Version $openclawVersion)) {
        $pnpm = Resolve-OpenClawDemoPnpm -PnpmPath $PnpmPath
        Install-OpenClawDemoRuntime -NodePath $node -PnpmPath $pnpm -RuntimeDir $paths.RuntimeDir
        $installationAction = 'installed_fixed_version'
        $openclawVersion = Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry
    }

    if (-not (Test-OpenClawDemoExpectedVersion -Version $openclawVersion)) {
        throw "项目内 OpenClaw 版本不符合固定测试版本 $script:OpenClawDemoExpectedVersion：$openclawVersion"
    }

    & $node $paths.OpenClawEntry mcp --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '当前项目内 OpenClaw 不具备 MCP 命令。'
    }
    & $node $paths.OpenClawEntry agent --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw '当前项目内 OpenClaw 不具备 agent 命令。'
    }

    Initialize-OpenClawDemoDirectories -Paths $paths
    $normalizedAgentGuardUrl = Assert-OpenClawDemoAgentGuardUrl -BaseUrl $AgentGuardBaseUrl
    $null = Write-OpenClawDemoConfiguration -Paths $paths -GatewayPort $GatewayPort

    # Do not inherit a caller's default OpenClaw state or Gateway token.
    $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $GatewayPort
    try {
        $definition = New-OpenClawDemoMcpDefinition -Paths $paths -AgentGuardBaseUrl $normalizedAgentGuardUrl
        $definitionJson = $definition | ConvertTo-Json -Depth 12 -Compress
        & $node $paths.OpenClawEntry mcp set agentguard-notices $definitionJson
        if ($LASTEXITCODE -ne 0) {
            throw 'AgentGuard MCP 注册失败，已停止后续启动。'
        }
        # mcp set is additive.  Rewrite the isolated file after registration so
        # this demo can never inherit an unrelated MCP server from an older run.
        $null = Set-OpenClawDemoMcpServerOnly -Paths $paths -Definition $definition
    }
    finally {
        Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
    }

    $displayConfig = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/state/openclaw.json'
    $finalConfig = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    $finalMcp = $finalConfig.PSObject.Properties['mcp'].Value
    $finalServers = $finalMcp.PSObject.Properties['servers'].Value
    [ordered]@{
        status = 'configured'
        installation_action = $installationAction
        global_openclaw_used = $false
        node_version = $nodeVersion
        openclaw_version = $openclawVersion
        openclaw_entry = '<PROJECT_ROOT>/third_party/runtime/openclaw-client/node_modules/openclaw/openclaw.mjs'
        config_path = $displayConfig
        state_directory = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/state'
        workspace_directory = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/workspace'
        gateway_bind = 'loopback'
        gateway_port = $GatewayPort
        gateway_auth = 'token'
        gateway_token_recorded = $false
        mcp_server = 'agentguard-notices'
        mcp_server_names = @($finalServers.PSObject.Properties.Name)
        tool_filter_include = @('list_notices')
        supports_parallel_tool_calls = $false
        next_step = '.\scripts\start_openclaw_agentguard_demo.ps1'
    } | ConvertTo-Json -Depth 8
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
