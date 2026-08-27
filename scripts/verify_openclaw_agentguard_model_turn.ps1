<#
.SYNOPSIS
Run and verify a real OpenClaw model-driven AgentGuard tool turn.

.DESCRIPTION
Uses the isolated Gateway and model SecretRef configuration. The model must
call the only allowed MCP tool with limit=2. Evidence is correlated across the
OpenClaw transcript, MCP result, AgentGuard audit and live OPA readiness.
#>

[CmdletBinding()]
param([string]$NodePath)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

function Get-DemoValue {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-DemoAuditRecords {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $records = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        try { $records += ConvertFrom-Json -InputObject $line } catch { continue }
    }
    return @($records)
}

function Write-DemoModelTurnMarkdown {
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][pscustomobject]$Paths,
        [string]$GatewayToken
    )
    $checks = Get-DemoValue -Object $Report -Name 'checks'
    $turn = Get-DemoValue -Object $Report -Name 'model_turn'
    $lines = @(
        '# OpenClaw × AgentGuard 真实模型回合报告',
        '',
        "- 生成时间：``$($Report.generated_at)``",
        "- 总体状态：``$($Report.status)``",
        "- 模型：``$($turn.provider)/$($turn.model)``",
        "- 模型回合退出码：``$($turn.exit_code)``",
        "- 模型发起工具调用：``$($turn.tool_call.name)``，``limit=$($turn.tool_call.limit)``",
        '',
        '## 模型回答',
        '',
        $turn.final_answer,
        '',
        '## 检查结果',
        '',
        '| 检查 | 结果 |',
        '|---|---:|'
    )
    foreach ($check in $checks.GetEnumerator()) {
        $lines += "| $($check.Name) | $(if ($check.Value -eq $true) { '通过' } else { '未通过' }) |"
    }
    $lines += @(
        '',
        '## 证据链',
        '',
        '- OpenClaw 新会话转录中存在模型 assistant 角色发起的唯一 MCP toolCall。',
        '- 对应 toolResult 返回 `executed_isolated`、2 条隔离测试公告和 `side_effect=false`。',
        '- AgentGuard 审计以同一 request_id 记录 `authorized` 与 `executed_isolated`，票据值未记录。',
        '- 调用期间 OPA 常驻服务健康，Gateway 仅绑定回环地址。',
        '',
        '## 范围边界',
        '',
        '- 本报告证明授权中转模型在本机隔离演示环境中真实发起了只读工具调用。',
        '- 使用回环静态测试身份与隔离合成数据，不代表生产身份、生产数据或生产就绪。',
        '- 模型 API Key、Gateway token、临时票据密钥和本机绝对路径均未写入报告。',
        ''
    )
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Protect-OpenClawDemoPortableFile -Path $Path -Paths $Paths -GatewayToken $GatewayToken
}

$projectRoot = $null
$paths = $null
$gatewayToken = $null
$modelApiKey = $null
$reportPath = $null
$markdownPath = $null

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath
    $reportPath = Join-Path $projectRoot 'reports\e2e\openclaw\openclaw_agentguard_model_turn.json'
    $markdownPath = Join-Path $projectRoot 'reports\e2e\openclaw\openclaw_agentguard_model_turn.md'
    if (-not (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf)) { throw '项目内 OpenClaw 不存在。' }
    if (-not (Test-OpenClawDemoModelApiKeyFile -Paths $paths)) { throw '隔离模型凭据不存在或格式错误。' }
    $config = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    $provider = $config.models.providers.PSObject.Properties[$script:OpenClawDemoModelProviderId].Value
    $modelReference = "$($script:OpenClawDemoModelProviderId)/$($script:OpenClawDemoModelId)"
    if ($config.agents.defaults.model.primary -ne $modelReference -or
        $provider.api -ne 'openai-completions' -or
        $provider.baseUrl -ne 'https://modelflare.dev/v1' -or
        $provider.apiKey.source -ne 'env' -or
        $provider.apiKey.id -ne $script:OpenClawDemoModelApiKeyEnvironmentVariable) {
        throw '隔离模型配置与固定测试 provider/model 不一致。'
    }
    $definition = $config.mcp.servers.'agentguard-notices'
    if (@($definition.toolFilter.include).Count -ne 1 -or @($definition.toolFilter.include)[0] -ne 'list_notices' -or
        $definition.supportsParallelToolCalls -ne $false) {
        throw 'MCP 工具过滤或并行调用安全设置不符合测试要求。'
    }
    if (-not (Test-OpenClawDemoAgentGuardReady -Port 8080)) { throw '本机 AgentGuard 演示服务未就绪。' }
    $readiness = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/readyz' -TimeoutSec 10
    $gatewayPort = [int]$config.gateway.port
    $gatewayToken = New-OpenClawDemoGatewayToken -TokenPath $paths.GatewayTokenPath
    $record = Get-OpenClawDemoGatewayProcessRecord -Paths $paths
    $gatewayRecordCurrent = Test-OpenClawDemoGatewayProcessRunning `
        -Record $record `
        -ExpectedConfigHash (Get-OpenClawDemoFileSha256 -Path $paths.ConfigPath) `
        -ExpectedPort $gatewayPort `
        -ExpectedNodePath (Resolve-Path -LiteralPath $node).Path `
        -ExpectedOpenClawEntry (Resolve-Path -LiteralPath $paths.OpenClawEntry).Path `
        -ExpectedConfigPath $paths.ConfigPath
    if (-not $gatewayRecordCurrent) { throw 'Gateway 进程记录与当前模型配置不一致；请重新运行 start 脚本。' }

    $auditPath = Join-Path $paths.AgentGuardStateDir 'enforcement_audit.jsonl'
    $baselineAudit = @(Get-DemoAuditRecords -Path $auditPath)
    $sessionId = [guid]::NewGuid().ToString()
    $prompt = '你必须调用 agentguard-notices__list_notices，参数 limit=2。只能依据该工具的真实返回结果回答；不要使用常识补充，不要声称执行了未发生的操作。请简洁列出两条公告。'
    $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $gatewayPort -GatewayToken $gatewayToken
    $startedAt = [DateTime]::UtcNow
    try {
        $cliOutput = (& $node $paths.OpenClawEntry agent `
            --session-id $sessionId `
            --message $prompt `
            --model $modelReference `
            --thinking off `
            --timeout 300 `
            --json 2>&1 | Out-String).Trim()
        $agentExitCode = $LASTEXITCODE
    }
    finally {
        Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
    }
    $finishedAt = [DateTime]::UtcNow
    $envLine = [System.IO.File]::ReadAllText($paths.ModelEnvironmentPath).Trim()
    $modelApiKey = $envLine.Substring($envLine.IndexOf('=') + 1)
    $safeCliOutput = $cliOutput.Replace($modelApiKey, '<REDACTED_API_KEY>').Replace($gatewayToken, '<REDACTED_GATEWAY_TOKEN>')
    $safeCliOutput = ConvertTo-OpenClawDemoPortableText -Text $safeCliOutput -Paths $paths -GatewayToken $gatewayToken
    try { $cliPayload = ConvertFrom-Json -InputObject $safeCliOutput }
    catch { throw "OpenClaw agent JSON 输出无法解析（退出码 $agentExitCode）。" }

    $sessionPath = Join-Path $paths.StateDir "agents\main\sessions\$sessionId.jsonl"
    if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) { throw 'OpenClaw 没有生成本次模型会话转录。' }
    $events = @()
    foreach ($line in Get-Content -LiteralPath $sessionPath) {
        try { $events += ConvertFrom-Json -InputObject $line } catch { throw '模型会话转录包含无效 JSON。' }
    }
    $toolCalls = @($events | Where-Object { $_.type -eq 'message' -and $_.message.role -eq 'assistant' } | ForEach-Object { $_.message.content } | Where-Object { $_.type -eq 'toolCall' })
    $toolResults = @($events | Where-Object { $_.type -eq 'message' -and $_.message.role -eq 'toolResult' })
    $toolCall = if (@($toolCalls).Count -eq 1) { @($toolCalls)[0] } else { $null }
    $toolResultEvent = if (@($toolResults).Count -eq 1) { @($toolResults)[0] } else { $null }
    $resultTextItem = if ($null -ne $toolResultEvent) { @($toolResultEvent.message.content | Where-Object { $_.type -eq 'text' } | Select-Object -First 1) } else { @() }
    $resultText = if (@($resultTextItem).Count -eq 1) { [string](@($resultTextItem)[0].text) } else { '' }
    $jsonStart = $resultText.IndexOf('{')
    $toolStructured = if ($jsonStart -ge 0) { try { ConvertFrom-Json -InputObject $resultText.Substring($jsonStart) } catch { $null } } else { $null }
    $turnMeta = $cliPayload.result.meta
    $finalAnswer = [string]$turnMeta.finalAssistantVisibleText

    $allAudit = @(Get-DemoAuditRecords -Path $auditPath)
    $newAudit = if (@($allAudit).Count -gt @($baselineAudit).Count) { @($allAudit | Select-Object -Skip (@($baselineAudit).Count)) } else { @() }
    $decisionRecords = @($newAudit | Where-Object { $_.event -eq 'enforcement_decision' -and $_.tool -eq 'database.query' -and $_.operation -eq 'query' })
    $auditPair = $null
    foreach ($requestId in @($decisionRecords.request_id | Sort-Object -Unique)) {
        $matching = @($decisionRecords | Where-Object { $_.request_id -eq $requestId })
        if (@($matching.result.status) -contains 'authorized' -and @($matching.result.status) -contains 'executed_isolated') {
            $auditPair = [pscustomobject]@{ request_id = $requestId; records = $matching }
            break
        }
    }
    $authorizedAudit = if ($null -ne $auditPair) { @($auditPair.records | Where-Object { $_.result.status -eq 'authorized' } | Select-Object -First 1) } else { @() }
    $executedAudit = if ($null -ne $auditPair) { @($auditPair.records | Where-Object { $_.result.status -eq 'executed_isolated' } | Select-Object -First 1) } else { @() }
    $rows = if ($null -ne $toolStructured) { @($toolStructured.rows) } else { @() }
    $answerGrounded = (@($rows).Count -eq 2)
    foreach ($row in $rows) {
        foreach ($value in @($row.title, $row.department, $row.published_at)) {
            if ([string]::IsNullOrWhiteSpace([string]$value) -or $finalAnswer.IndexOf([string]$value, [System.StringComparison]::Ordinal) -lt 0) { $answerGrounded = $false }
        }
    }

    $checks = [ordered]@{
        fixed_project_local_openclaw_version = (Test-OpenClawDemoExpectedVersion -Version (Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry))
        isolated_gateway_loaded_current_config = $gatewayRecordCurrent
        loopback_gateway_and_agentguard_only = ($config.gateway.bind -eq 'loopback' -and $definition.env.AGENTGUARD_MCP_BASE_URL -eq 'http://127.0.0.1:8080')
        model_secret_ref_configured = ($provider.apiKey.source -eq 'env' -and $provider.apiKey.id -eq $script:OpenClawDemoModelApiKeyEnvironmentVariable)
        model_call_succeeded = ($agentExitCode -eq 0 -and $cliPayload.status -eq 'ok' -and $turnMeta.executionTrace.attempts[0].result -eq 'success')
        configured_provider_and_model_used = ($turnMeta.agentMeta.provider -eq $script:OpenClawDemoModelProviderId -and $turnMeta.agentMeta.model -eq $script:OpenClawDemoModelId -and $turnMeta.executionTrace.fallbackUsed -eq $false)
        model_initiated_exactly_one_allowed_tool_call = (@($toolCalls).Count -eq 1 -and $toolCall.name -eq 'agentguard-notices__list_notices' -and [int]$toolCall.arguments.limit -eq 2)
        openclaw_tool_summary_matches_transcript = ($turnMeta.toolSummary.calls -eq 1 -and @($turnMeta.toolSummary.tools).Count -eq 1 -and @($turnMeta.toolSummary.tools)[0] -eq 'agentguard-notices__list_notices' -and $turnMeta.toolSummary.failures -eq 0)
        mcp_tool_result_succeeded = (@($toolResults).Count -eq 1 -and $toolResultEvent.message.toolName -eq $toolCall.name -and $toolResultEvent.message.isError -eq $false)
        result_is_two_read_only_isolated_rows = ($toolStructured.status -eq 'executed_isolated' -and $toolStructured.reason_code -eq 'G000_EXECUTED' -and [int]$toolStructured.row_count -eq 2 -and @($rows).Count -eq 2 -and $toolStructured.side_effect -eq $false)
        final_answer_grounded_in_tool_rows = $answerGrounded
        agentguard_authorized_and_executed_same_request = ($null -ne $auditPair -and @($authorizedAudit).Count -eq 1 -and @($executedAudit).Count -eq 1)
        agentguard_ticket_value_not_recorded = ($null -ne $auditPair -and @($auditPair.records | Where-Object {
                    $ticketValue = Get-DemoValue -Object $_.result -Name 'ticket'
                    $ticketValue -notin @($null, '', '***REDACTED***')
                }).Count -eq 0)
        opa_was_healthy_for_turn = ($readiness.ready -eq $true -and $readiness.dependencies.opa.healthy -eq $true -and $readiness.dependencies.opa.detail -match 'canary_effect=deny')
    }
    $passed = @($checks.Values | Where-Object { $_ -ne $true }).Count -eq 0
    $report = [pscustomobject][ordered]@{
        schema_version = '1.0'
        generated_at = [DateTime]::UtcNow.ToString('o')
        status = if ($passed) { 'passed_with_declared_scope' } else { 'failed' }
        claim = if ($passed) { '授权中转模型已在项目内 OpenClaw 真实回合中主动调用唯一允许的 AgentGuard 只读 MCP 工具；调用经过本机 AgentGuard、OPA、票据执行与隔离测试数据链。' } else { '真实模型回合存在失败检查，不得声称模型驱动工具调用已完成。' }
        scope = [pscustomobject][ordered]@{ identity = 'loopback_static_dev_test_only'; data = 'isolated_synthetic_notices'; production_ready = $false }
        configuration = [pscustomobject][ordered]@{ provider = $script:OpenClawDemoModelProviderId; base_url = $provider.baseUrl; model = $modelReference; api = $provider.api; credential = 'environment_secret_ref_in_git_ignored_state'; api_key_recorded = $false; gateway_token_recorded = $false; tool_filter_include = @($definition.toolFilter.include); supports_parallel_tool_calls = $definition.supportsParallelToolCalls }
        model_turn = [pscustomobject][ordered]@{
            command = '& <NODE> <OPENCLAW_ENTRY> agent --session-id <SESSION_ID> --message <FIXED_GROUNDED_PROMPT> --model modelflare/gpt-5.6-sol --thinking off --timeout 300 --json'
            started_at = $startedAt.ToString('o')
            finished_at = $finishedAt.ToString('o')
            duration_ms = [Math]::Round(($finishedAt - $startedAt).TotalMilliseconds, 3)
            exit_code = $agentExitCode
            session_id = $sessionId
            run_id = $cliPayload.runId
            provider = $turnMeta.agentMeta.provider
            model = $turnMeta.agentMeta.model
            fallback_used = $turnMeta.executionTrace.fallbackUsed
            tool_call = [pscustomobject][ordered]@{ name = $toolCall.name; limit = $toolCall.arguments.limit; transcript_role = 'assistant'; call_id = $toolCall.id }
            tool_result = [pscustomobject][ordered]@{ status = $toolStructured.status; reason_code = $toolStructured.reason_code; row_count = $toolStructured.row_count; rows = $rows; side_effect = $toolStructured.side_effect; is_error = $toolResultEvent.message.isError }
            final_answer = $finalAnswer
            usage = $turnMeta.agentMeta.usage
        }
        agentguard = [pscustomobject][ordered]@{ ready = $readiness.ready; opa_healthy = $readiness.dependencies.opa.healthy; opa_detail = $readiness.dependencies.opa.detail; audit_request_id = if ($null -ne $auditPair) { $auditPair.request_id } else { $null }; audit_statuses = if ($null -ne $auditPair) { @($auditPair.records.result.status) } else { @() }; audit_reason_codes = if ($null -ne $auditPair) { @($auditPair.records.result.reason_code) } else { @() }; ticket_value_recorded = $false }
        checks = $checks
        secret_values_recorded = $false
        limitations = @('The identity is a loopback static development identity, not a requester-scoped production OIDC token.', 'The notices are isolated synthetic SQLite rows, not production data.', 'The Gateway and AgentGuard service are bound to loopback for a same-machine demonstration.', 'Production still requires requester-scoped identity, TLS/mTLS, network isolation, HA state and authorized business credentials.')
    }
    Write-OpenClawDemoPortableJsonFile -Path $reportPath -Value $report -Paths $paths -GatewayToken $gatewayToken
    Write-DemoModelTurnMarkdown -Report $report -Path $markdownPath -Paths $paths -GatewayToken $gatewayToken
    $reportText = [System.IO.File]::ReadAllText($reportPath) + [System.IO.File]::ReadAllText($markdownPath)
    if ($reportText.IndexOf($gatewayToken, [System.StringComparison]::Ordinal) -ge 0 -or
        $reportText.IndexOf($modelApiKey, [System.StringComparison]::Ordinal) -ge 0 -or
        $reportText.IndexOf($projectRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw '报告脱敏检查失败；已停止成功声明。'
    }
    [pscustomobject][ordered]@{ status = $report.status; report = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_model_turn.json'; markdown = '<PROJECT_ROOT>/reports/e2e/openclaw/openclaw_agentguard_model_turn.md'; checks_passed = @($checks.Values | Where-Object { $_ -eq $true }).Count; checks_total = $checks.Count; api_key_recorded = $false } | ConvertTo-Json -Depth 5
    if (-not $passed) { exit 1 }
}
catch {
    $safeMessage = $_.Exception.Message
    if ($null -ne $paths) { $safeMessage = ConvertTo-OpenClawDemoPortableText -Text $safeMessage -Paths $paths -GatewayToken $gatewayToken }
    if (-not [string]::IsNullOrWhiteSpace($modelApiKey)) { $safeMessage = $safeMessage.Replace($modelApiKey, '<REDACTED_API_KEY>') }
    $safeMessage = [regex]::Replace($safeMessage, '(?i)\bsk-[A-Za-z0-9_-]{16,}\b', '<REDACTED_API_KEY>')
    if ($null -ne $paths -and -not [string]::IsNullOrWhiteSpace($reportPath)) {
        $failure = [pscustomobject][ordered]@{ schema_version = '1.0'; generated_at = [DateTime]::UtcNow.ToString('o'); status = 'failed'; error = $safeMessage; secret_values_recorded = $false }
        Write-OpenClawDemoPortableJsonFile -Path $reportPath -Value $failure -Paths $paths -GatewayToken $gatewayToken
    }
    Write-Error $safeMessage
    exit 1
}
