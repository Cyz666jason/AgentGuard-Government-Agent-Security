<#
.SYNOPSIS
Verify the isolated OpenClaw Control UI and AgentGuard MCP demo.

.DESCRIPTION
Records fresh, portable evidence for the project-local OpenClaw runtime. This
stage verifies the Gateway and the one allowed MCP tool only; it intentionally
does not run a model turn or tools/call.
#>

[CmdletBinding()]
param(
    [string]$NodePath
)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

function Get-OpenClawDemoPropertyValue {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Invoke-OpenClawDemoCapturedCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$RecordedCommand,
        [Parameter(Mandatory)][pscustomobject]$Paths,
        [Parameter(Mandatory)][string]$GatewayToken
    )
    $startedAt = [DateTime]::UtcNow
    $output = (& $FilePath @Arguments 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    return [pscustomobject][ordered]@{
        name = $Name
        command = $RecordedCommand
        started_at = $startedAt.ToString('o')
        finished_at = [DateTime]::UtcNow.ToString('o')
        duration_ms = [Math]::Round((([DateTime]::UtcNow - $startedAt).TotalMilliseconds), 3)
        exit_code = $exitCode
        stdout = ConvertTo-OpenClawDemoPortableText -Text $output -Paths $Paths -GatewayToken $GatewayToken
    }
}

function ConvertFrom-OpenClawDemoJsonOutput {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ConvertFrom-Json -InputObject $Text }
    catch {
        $candidateLines = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        [array]::Reverse($candidateLines)
        foreach ($line in $candidateLines) {
            try { return ConvertFrom-Json -InputObject $line }
            catch { continue }
        }
        return $null
    }
}

function Get-OpenClawDemoMcpServerNames {
    param([AllowNull()][object]$Payload)
    if ($null -eq $Payload) { return @() }
    return @($Payload.PSObject.Properties | ForEach-Object { [string]$_.Name } | Sort-Object)
}

function Set-OpenClawDemoMcpEnvironment {
    param([AllowNull()][object]$Definition)
    $names = @('AGENTGUARD_MCP_BASE_URL', 'AGENTGUARD_MCP_IDENTITY_MODE', 'AGENTGUARD_MCP_DEV_SUBJECT_FILE')
    $snapshot = @{}
    foreach ($name in $names) {
        $exists = Test-Path -LiteralPath "Env:$name"
        $snapshot[$name] = [pscustomobject]@{ Exists = $exists; Value = if ($exists) { (Get-Item -LiteralPath "Env:$name").Value } else { $null } }
    }
    $definitionEnvironment = Get-OpenClawDemoPropertyValue -Object $Definition -Name 'env'
    foreach ($name in $names) {
        $value = Get-OpenClawDemoPropertyValue -Object $definitionEnvironment -Name $name
        if ([string]::IsNullOrWhiteSpace([string]$value)) {
            throw "MCP 定义缺少 $name，无法执行协议 schema 验证。"
        }
        Set-Item -LiteralPath "Env:$name" -Value ([string]$value)
    }
    return $snapshot
}

function Test-OpenClawDemoControlUi {
    param([Parameter(Mandatory)][int]$Port)
    $url = "http://127.0.0.1:$Port/"
    try {
        $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing
        return [pscustomobject][ordered]@{ url = $url; reachable = $true; status_code = [int]$response.StatusCode; control_ui_marker_found = ($response.Content -match 'OpenClaw Control'); error = $null }
    }
    catch {
        return [pscustomobject][ordered]@{ url = $url; reachable = $false; status_code = $null; control_ui_marker_found = $false; error = $_.Exception.Message }
    }
}

function Write-OpenClawDemoVerificationMarkdown {
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$MarkdownPath,
        [Parameter(Mandatory)][pscustomobject]$Paths,
        [string]$GatewayToken
    )
    $versions = Get-OpenClawDemoPropertyValue -Object $Report -Name 'versions'
    $gateway = Get-OpenClawDemoPropertyValue -Object $Report -Name 'gateway'
    $commandsValue = Get-OpenClawDemoPropertyValue -Object $Report -Name 'commands'
    $lines = @(
        '# OpenClaw Control UI × AgentGuard 演示验证报告',
        '',
        "- 生成时间：``$(Get-OpenClawDemoPropertyValue -Object $Report -Name 'generated_at')``",
        "- 总体状态：``$(Get-OpenClawDemoPropertyValue -Object $Report -Name 'status')``",
        "- OpenClaw：``$(Get-OpenClawDemoPropertyValue -Object $versions -Name 'openclaw')``",
        "- Control UI：``$(Get-OpenClawDemoPropertyValue -Object $gateway -Name 'control_ui_url')``",
        '',
        '## 已证明的范围',
        '',
        '- 项目内 OpenClaw runtime 实际运行，Gateway 的 Control UI HTTP 页面可访问。',
        '- OpenClaw 已在隔离状态目录中注册唯一的 `agentguard-notices`，并实际执行 `mcp list`、`doctor --probe` 与 `probe`。',
        '- 实际 `tools/list` schema 只公开 `list_notices(limit: integer, 1..100)`，且标为只读、非破坏性。',
        '',
        '## 命令退出码',
        '',
        '| 命令 | 退出码 |',
        '|---|---:|'
    )
    if ($null -ne $commandsValue) {
        foreach ($step in @($commandsValue)) { $lines += "| ``$($step.command)`` | $($step.exit_code) |" }
    }
    $limitationsValue = Get-OpenClawDemoPropertyValue -Object $Report -Name 'limitations'
    if ($null -ne $limitationsValue) {
        $lines += @('', '## 范围边界', '')
        foreach ($limitation in @($limitationsValue)) { $lines += "- $limitation" }
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $MarkdownPath) -Force | Out-Null
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($MarkdownPath, (($lines -join "`n") + "`n"), $utf8WithoutBom)
    Protect-OpenClawDemoPortableFile -Path $MarkdownPath -Paths $Paths -GatewayToken $GatewayToken
}

function Write-OpenClawDemoFailureEvidence {
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$MarkdownPath,
        [Parameter(Mandatory)][string]$Message,
        [AllowNull()][pscustomobject]$Paths,
        [string]$GatewayToken
    )
    $safeMessage = if ($null -ne $Paths) { ConvertTo-OpenClawDemoPortableText -Text $Message -Paths $Paths -GatewayToken $GatewayToken } else { [regex]::Replace($Message, '(?i)\bsk-[A-Za-z0-9_-]{16,}\b', '<REDACTED_API_KEY>') }
    $failureReport = [pscustomobject][ordered]@{
        schema_version = '1.0'
        generated_at = [DateTime]::UtcNow.ToString('o')
        status = 'failed'
        claim = '可视化 OpenClaw × AgentGuard 演示验证未完成；不得声称该演示已验证完成。'
        error = $safeMessage
        secret_values_recorded = $false
        limitations = @('验证在完成前失败；本证据不代表 Gateway、MCP 或模型回合成功。')
    }
    if ($null -ne $Paths) {
        Write-OpenClawDemoPortableJsonFile -Path $ReportPath -Value $failureReport -Paths $Paths -GatewayToken $GatewayToken
        Write-OpenClawDemoVerificationMarkdown -Report $failureReport -MarkdownPath $MarkdownPath -Paths $Paths -GatewayToken $GatewayToken
    }
    else {
        Write-OpenClawDemoJsonFile -Path $ReportPath -Value $failureReport
        New-Item -ItemType Directory -Path (Split-Path -Parent $MarkdownPath) -Force | Out-Null
        Set-Content -LiteralPath $MarkdownPath -Value "# OpenClaw Control UI × AgentGuard 演示验证报告`n`n状态：`failed``n" -Encoding utf8
    }
}

$projectRoot = $null
$paths = $null
$gatewayToken = $null
$reportPath = $null
$markdownPath = $null

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $reportDirectory = Join-Path $projectRoot 'reports\e2e\openclaw'
    $reportPath = Join-Path $reportDirectory 'openclaw_agentguard_visual_demo.json'
    $markdownPath = Join-Path $reportDirectory 'openclaw_agentguard_visual_demo.md'
    $protocolReportPath = Join-Path $reportDirectory 'openclaw_agentguard_visual_demo_protocol_probe.json'
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath
    if (-not (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf)) { throw '项目内 OpenClaw 不存在。请先运行 setup 脚本。' }
    if (-not (Test-Path -LiteralPath $paths.Python -PathType Leaf)) { throw '项目 Python 环境不存在，无法验证 MCP 适配器。' }

    $config = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    $gateway = Get-OpenClawDemoPropertyValue -Object $config -Name 'gateway'
    $portValue = Get-OpenClawDemoPropertyValue -Object $gateway -Name 'port'
    if ($null -eq $portValue) { throw '隔离 Gateway 配置缺少端口。请重新运行 setup 和 start 脚本。' }
    $gatewayPort = [int]$portValue
    $servers = Get-OpenClawDemoPropertyValue -Object (Get-OpenClawDemoPropertyValue -Object $config -Name 'mcp') -Name 'servers'
    $definition = Get-OpenClawDemoPropertyValue -Object $servers -Name 'agentguard-notices'
    if ($null -eq $definition) { throw '隔离配置中没有 agentguard-notices。请先运行 setup 脚本。' }

    $gatewayToken = New-OpenClawDemoGatewayToken -TokenPath $paths.GatewayTokenPath
    $record = Get-OpenClawDemoGatewayProcessRecord -Paths $paths
    $recordCurrent = Test-OpenClawDemoGatewayProcessRunning `
        -Record $record `
        -ExpectedConfigHash (Get-OpenClawDemoFileSha256 -Path $paths.ConfigPath) `
        -ExpectedPort $gatewayPort `
        -ExpectedNodePath (Resolve-Path -LiteralPath $node).Path `
        -ExpectedOpenClawEntry (Resolve-Path -LiteralPath $paths.OpenClawEntry).Path `
        -ExpectedConfigPath $paths.ConfigPath

    $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $gatewayPort -GatewayToken $gatewayToken
    $mcpEnvironmentSnapshot = $null
    $locationPushed = $false
    try {
        $mcpEnvironmentSnapshot = Set-OpenClawDemoMcpEnvironment -Definition $definition
        Push-Location -LiteralPath $projectRoot
        $locationPushed = $true
        $steps = @()
        $steps += Invoke-OpenClawDemoCapturedCommand -Name 'gateway_health' -FilePath $node -Arguments @($paths.OpenClawEntry, 'gateway', 'health', '--port', "$gatewayPort", '--json') -RecordedCommand '& <NODE> <OPENCLAW_ENTRY> gateway health --port <PORT> --json' -Paths $paths -GatewayToken $gatewayToken
        $controlUi = Test-OpenClawDemoControlUi -Port $gatewayPort
        $steps += Invoke-OpenClawDemoCapturedCommand -Name 'mcp_list' -FilePath $node -Arguments @($paths.OpenClawEntry, 'mcp', 'list', '--json') -RecordedCommand '& <NODE> <OPENCLAW_ENTRY> mcp list --json' -Paths $paths -GatewayToken $gatewayToken
        $steps += Invoke-OpenClawDemoCapturedCommand -Name 'mcp_doctor_probe' -FilePath $node -Arguments @($paths.OpenClawEntry, 'mcp', 'doctor', 'agentguard-notices', '--probe', '--json') -RecordedCommand '& <NODE> <OPENCLAW_ENTRY> mcp doctor agentguard-notices --probe --json' -Paths $paths -GatewayToken $gatewayToken
        $steps += Invoke-OpenClawDemoCapturedCommand -Name 'mcp_probe' -FilePath $node -Arguments @($paths.OpenClawEntry, 'mcp', 'probe', 'agentguard-notices', '--json') -RecordedCommand '& <NODE> <OPENCLAW_ENTRY> mcp probe agentguard-notices --json' -Paths $paths -GatewayToken $gatewayToken
        $steps += Invoke-OpenClawDemoCapturedCommand -Name 'protocol_tools_list_schema' -FilePath $paths.Python -Arguments @('-m', 'integrations.openclaw_mcp.protocol_probe', '--skip-call', '--report', $protocolReportPath) -RecordedCommand '<PYTHON> -m integrations.openclaw_mcp.protocol_probe --skip-call --report <REPORT>' -Paths $paths -GatewayToken $gatewayToken
    }
    finally {
        if ($locationPushed) { Pop-Location }
        if ($null -ne $mcpEnvironmentSnapshot) { Restore-OpenClawDemoEnvironment -Snapshot $mcpEnvironmentSnapshot }
        Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
    }

    Protect-OpenClawDemoPortableFile -Path $protocolReportPath -Paths $paths -GatewayToken $gatewayToken
    $stepByName = @{}
    foreach ($step in @($steps)) { $stepByName[[string]$step.name] = $step }
    $healthStep = $stepByName['gateway_health']
    $listStep = $stepByName['mcp_list']
    $doctorStep = $stepByName['mcp_doctor_probe']
    $probeStep = $stepByName['mcp_probe']
    $protocolStep = $stepByName['protocol_tools_list_schema']
    $listPayload = ConvertFrom-OpenClawDemoJsonOutput -Text $listStep.stdout
    $doctorPayload = ConvertFrom-OpenClawDemoJsonOutput -Text $doctorStep.stdout
    $probePayload = ConvertFrom-OpenClawDemoJsonOutput -Text $probeStep.stdout
    $protocolPayload = if (Test-Path -LiteralPath $protocolReportPath -PathType Leaf) { try { Get-Content -LiteralPath $protocolReportPath -Raw | ConvertFrom-Json } catch { $null } } else { $null }

    [object[]]$mcpListServerNames = Get-OpenClawDemoMcpServerNames -Payload $listPayload
    $outputsValue = Get-OpenClawDemoPropertyValue -Object $protocolPayload -Name 'outputs'
    [object[]]$protocolOutputs = if ($null -eq $outputsValue) { @() } else { @($outputsValue) }
    $toolsResponse = $protocolOutputs | Where-Object { (Get-OpenClawDemoPropertyValue -Object $_ -Name 'id') -eq 2 } | Select-Object -First 1
    $toolsResult = Get-OpenClawDemoPropertyValue -Object $toolsResponse -Name 'result'
    $toolsValue = Get-OpenClawDemoPropertyValue -Object $toolsResult -Name 'tools'
    [object[]]$tools = if ($null -eq $toolsValue) { @() } else { @($toolsValue) }
    $tool = if (@($tools).Count -eq 1) { @($tools)[0] } else { $null }
    $inputSchema = Get-OpenClawDemoPropertyValue -Object $tool -Name 'inputSchema'
    $properties = Get-OpenClawDemoPropertyValue -Object $inputSchema -Name 'properties'
    $limitSchema = Get-OpenClawDemoPropertyValue -Object $properties -Name 'limit'
    $annotations = Get-OpenClawDemoPropertyValue -Object $tool -Name 'annotations'
    [object[]]$propertyNames = if ($null -eq $properties) { @() } else { @($properties.PSObject.Properties.Name) }
    $definitionFilterValue = Get-OpenClawDemoPropertyValue -Object (Get-OpenClawDemoPropertyValue -Object $definition -Name 'toolFilter') -Name 'include'
    [object[]]$definitionFilter = if ($null -eq $definitionFilterValue) { @() } else { @($definitionFilterValue | ForEach-Object { [string]$_ }) }
    $parallelValue = Get-OpenClawDemoPropertyValue -Object $definition -Name 'supportsParallelToolCalls'
    $probeToolsValue = Get-OpenClawDemoPropertyValue -Object $probePayload -Name 'tools'
    [object[]]$probeTools = if ($null -eq $probeToolsValue) { @() } else { @($probeToolsValue | ForEach-Object { [string]$_ }) }
    $probeDiagnosticsValue = Get-OpenClawDemoPropertyValue -Object $probePayload -Name 'diagnostics'
    [object[]]$probeDiagnostics = if ($null -eq $probeDiagnosticsValue) { @() } else { @($probeDiagnosticsValue) }
    $gatewayMode = Get-OpenClawDemoPropertyValue -Object $gateway -Name 'mode'
    $gatewayBind = Get-OpenClawDemoPropertyValue -Object $gateway -Name 'bind'
    $gatewayAuth = Get-OpenClawDemoPropertyValue -Object (Get-OpenClawDemoPropertyValue -Object $gateway -Name 'auth') -Name 'mode'
    $controlUiEnabled = Get-OpenClawDemoPropertyValue -Object (Get-OpenClawDemoPropertyValue -Object $gateway -Name 'controlUi') -Name 'enabled'

    $checks = [ordered]@{
        project_local_openclaw_runtime = (Test-OpenClawDemoExpectedVersion -Version (Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry))
        isolated_gateway_configuration = ($gatewayMode -eq 'local' -and $gatewayBind -eq 'loopback' -and $gatewayAuth -eq 'token' -and $controlUiEnabled -eq $true)
        gateway_process_record_current = ($recordCurrent -eq $true)
        gateway_health_passed = ($null -ne $healthStep -and $healthStep.exit_code -eq 0)
        control_ui_http_accessible = ($controlUi.reachable -eq $true -and $controlUi.status_code -eq 200 -and $controlUi.control_ui_marker_found -eq $true)
        mcp_list_json_parsed = ($null -ne $listPayload)
        mcp_list_has_only_registered_server = ($null -ne $listStep -and $listStep.exit_code -eq 0 -and @($mcpListServerNames).Count -eq 1 -and @($mcpListServerNames)[0] -eq 'agentguard-notices')
        mcp_doctor_live_probe_passed = ($null -ne $doctorStep -and $doctorStep.exit_code -eq 0 -and (Get-OpenClawDemoPropertyValue -Object $doctorPayload -Name 'ok') -eq $true)
        mcp_probe_found_only_allowed_tool = ($null -ne $probeStep -and $probeStep.exit_code -eq 0 -and @($probeTools).Count -eq 1 -and @($probeTools)[0] -eq 'agentguard-notices__list_notices' -and @($probeDiagnostics).Count -eq 0)
        config_has_only_list_notices_filter = (@($definitionFilter).Count -eq 1 -and @($definitionFilter)[0] -eq 'list_notices')
        config_disables_parallel_tool_calls = ($parallelValue -eq $false)
        schema_has_only_bounded_limit = (@($tools).Count -eq 1 -and (Get-OpenClawDemoPropertyValue -Object $tool -Name 'name') -eq 'list_notices' -and (Get-OpenClawDemoPropertyValue -Object $inputSchema -Name 'type') -eq 'object' -and (Get-OpenClawDemoPropertyValue -Object $inputSchema -Name 'additionalProperties') -eq $false -and @($propertyNames).Count -eq 1 -and @($propertyNames)[0] -eq 'limit' -and (Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'type') -eq 'integer' -and [int](Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'minimum') -eq 1 -and [int](Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'maximum') -eq 100)
        schema_marks_tool_read_only = ((Get-OpenClawDemoPropertyValue -Object $annotations -Name 'readOnlyHint') -eq $true -and (Get-OpenClawDemoPropertyValue -Object $annotations -Name 'destructiveHint') -eq $false)
        protocol_tools_list_schema_passed = ($null -ne $protocolStep -and $protocolStep.exit_code -eq 0 -and (Get-OpenClawDemoPropertyValue -Object $protocolPayload -Name 'status') -eq 'passed')
        every_recorded_command_exited_zero = (@($steps | Where-Object { $_.exit_code -ne 0 }).Count -eq 0)
        gateway_token_not_recorded = (-not (($steps | ConvertTo-Json -Depth 16) -match [regex]::Escape($gatewayToken)))
    }
    $passed = @($checks.Values | Where-Object { $_ -ne $true }).Count -eq 0
    $openclawVersion = Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry
    $nodeVersion = (& $node --version 2>&1 | Out-String).Trim()
    $report = [pscustomobject][ordered]@{
        schema_version = '1.0'
        generated_at = [DateTime]::UtcNow.ToString('o')
        status = if ($passed) { 'passed_with_declared_scope' } else { 'failed' }
        claim = if ($passed) { '项目内 OpenClaw Gateway 的 Control UI 已可访问；OpenClaw 已实际注册、诊断并发现唯一的 AgentGuard 只读 MCP 工具。未运行 relay/model 回合或 tools/call，不能表述为模型自主调用或生产接入完成。' } else { '可视化 OpenClaw × AgentGuard 演示验证存在失败项；不得声称该演示已验证完成。' }
        scope = [pscustomobject][ordered]@{ control_ui = 'gateway_http_page_verified'; openclaw_mcp_registration_and_tools_list = 'real_project_local_runtime'; protocol_schema = 'separate_tools_list_only_probe'; deterministic_low_risk_call_evidence = 'reports/e2e/openclaw/openclaw_mcp_integration.json'; relay_model_turn = 'not_run'; production_ready = $false }
        versions = [pscustomobject][ordered]@{ node = $nodeVersion; openclaw = $openclawVersion; adapter = '0.1.0'; requested_openclaw_version = $script:OpenClawDemoExpectedVersion }
        locations = [pscustomobject][ordered]@{ project_root = '<PROJECT_ROOT>'; openclaw_entry = '<PROJECT_ROOT>/third_party/runtime/openclaw-client/node_modules/openclaw/openclaw.mjs'; state_directory = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/state'; config_path = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/state/openclaw.json'; workspace_directory = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/workspace'; runtime_directory = '<PROJECT_ROOT>/integrations/openclaw_mcp/.e2e_state/visual-demo/runtime' }
        gateway = [pscustomobject][ordered]@{ mode = $gatewayMode; bind = $gatewayBind; port = $gatewayPort; control_ui_url = "http://127.0.0.1:$gatewayPort/"; control_ui_http = $controlUi; auth_mode = $gatewayAuth; process_record_current = $recordCurrent; gateway_token_recorded = $false }
        mcp = [pscustomobject][ordered]@{ server_name = 'agentguard-notices'; discovered_openclaw_tool = 'agentguard-notices__list_notices'; list_server_names = $mcpListServerNames; tool_filter_include = $definitionFilter; supports_parallel_tool_calls = $parallelValue; schema = [pscustomobject][ordered]@{ tool_name = Get-OpenClawDemoPropertyValue -Object $tool -Name 'name'; input_type = Get-OpenClawDemoPropertyValue -Object $inputSchema -Name 'type'; input_properties = $propertyNames; additional_properties = Get-OpenClawDemoPropertyValue -Object $inputSchema -Name 'additionalProperties'; limit_type = Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'type'; limit_minimum = Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'minimum'; limit_maximum = Get-OpenClawDemoPropertyValue -Object $limitSchema -Name 'maximum'; read_only_hint = Get-OpenClawDemoPropertyValue -Object $annotations -Name 'readOnlyHint'; destructive_hint = Get-OpenClawDemoPropertyValue -Object $annotations -Name 'destructiveHint' } }
        checks = $checks
        commands = $steps
        openclaw_mcp_list = $listPayload
        openclaw_mcp_doctor_probe = $doctorPayload
        openclaw_mcp_probe = $probePayload
        protocol_schema_report = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_visual_demo_protocol_probe.json'
        secret_values_recorded = $false
        limitations = @('Gateway is bound only to loopback and uses a local temporary token that is stored only below the Git-ignored visual-demo runtime directory and the child-process environment.', 'The Control UI HTTP response proves the page is served; this report deliberately does not transfer the Gateway token into a browser or execute an authenticated UI session.', 'OpenClaw mcp probe establishes a real MCP session and performs tools/list, but it does not perform tools/call.', 'The protocol probe uses --skip-call. The separate model-turn evidence is required before claiming a model-driven tool call.', 'This report does not record a model API key or model provider credential.')
    }
    Write-OpenClawDemoPortableJsonFile -Path $reportPath -Value $report -Paths $paths -GatewayToken $gatewayToken
    Write-OpenClawDemoVerificationMarkdown -Report $report -MarkdownPath $markdownPath -Paths $paths -GatewayToken $gatewayToken
    Protect-OpenClawDemoPortableFile -Path $protocolReportPath -Paths $paths -GatewayToken $gatewayToken
    if (-not (Test-OpenClawDemoSecretAbsent -PathsToCheck @($reportPath, $markdownPath, $protocolReportPath) -GatewayToken $gatewayToken)) { throw '脱敏检查失败：Gateway token 出现在可提交的验证证据中。' }
    [pscustomobject][ordered]@{ status = $report.status; report = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_visual_demo.json'; markdown = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_visual_demo.md'; protocol_schema_report = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_visual_demo_protocol_probe.json'; checks_passed = @($checks.Values | Where-Object { $_ -eq $true }).Count; checks_total = $checks.Count } | ConvertTo-Json -Depth 6
    if (-not $passed) { exit 1 }
}
catch {
    $failureRoot = if ($null -ne $projectRoot) { $projectRoot } else { (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path }
    if ([string]::IsNullOrWhiteSpace($reportPath)) { $reportPath = Join-Path $failureRoot 'reports\e2e\openclaw\openclaw_agentguard_visual_demo.json' }
    if ([string]::IsNullOrWhiteSpace($markdownPath)) { $markdownPath = Join-Path $failureRoot 'reports\e2e\openclaw\openclaw_agentguard_visual_demo.md' }
    Write-OpenClawDemoFailureEvidence -ReportPath $reportPath -MarkdownPath $markdownPath -Message $_.Exception.Message -Paths $paths -GatewayToken $gatewayToken
    $safeError = if ($null -ne $paths) { ConvertTo-OpenClawDemoPortableText -Text $_.Exception.Message -Paths $paths -GatewayToken $gatewayToken } else { [regex]::Replace($_.Exception.Message, '(?i)\bsk-[A-Za-z0-9_-]{16,}\b', '<REDACTED_API_KEY>') }
    Write-Error $safeError
    exit 1
}
