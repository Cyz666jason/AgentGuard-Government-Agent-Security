<#
.SYNOPSIS
Configure the approved model relay for the isolated OpenClaw demo.

.DESCRIPTION
The API key is accepted only as a SecureString prompt (or SecureString
parameter), then written to the Git-ignored OpenClaw state .env file.  The
tracked-safe OpenClaw JSON contains only an environment SecretRef.
#>

[CmdletBinding()]
param(
    [string]$NodePath,
    [string]$BaseUrl = 'https://modelflare.dev/v1',
    [string]$ModelId = 'gpt-5.6-sol',
    [SecureString]$ApiKey,
    [switch]$UseExistingCredential
)

. (Join-Path $PSScriptRoot 'openclaw_agentguard_demo.common.ps1')

try {
    $projectRoot = Get-OpenClawDemoProjectRoot
    $paths = Get-OpenClawDemoPaths -ProjectRoot $projectRoot
    $node = Resolve-OpenClawDemoNode -NodePath $NodePath
    if (-not (Test-Path -LiteralPath $paths.OpenClawEntry -PathType Leaf)) {
        throw '项目内 OpenClaw 不存在。请先运行 setup_openclaw_agentguard_demo.ps1。'
    }
    $version = Get-OpenClawDemoVersion -NodePath $node -OpenClawEntry $paths.OpenClawEntry
    if (-not (Test-OpenClawDemoExpectedVersion -Version $version)) {
        throw "项目内 OpenClaw 版本不是固定测试版本 $script:OpenClawDemoExpectedVersion。"
    }
    $uri = [uri]$BaseUrl
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment) -or
        $uri.AbsolutePath.TrimEnd('/') -ne '/v1') {
        throw '模型 Base URL 必须是以 /v1 结尾且不含凭据、查询参数或片段的绝对 HTTPS URL。'
    }
    if ($ModelId -ne $script:OpenClawDemoModelId) {
        throw "本次固定测试模型必须是 $script:OpenClawDemoModelId，不会静默改用其他模型。"
    }
    $null = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    Initialize-OpenClawDemoDirectories -Paths $paths

    if ($UseExistingCredential) {
        if ($null -ne $ApiKey) {
            throw '-UseExistingCredential 不能与 -ApiKey 同时使用。'
        }
        if (-not (Test-OpenClawDemoModelApiKeyFile -Paths $paths)) {
            throw '隔离状态中没有可复用的模型凭据。'
        }
        $null = Set-OpenClawDemoModelProviderConfiguration `
            -Paths $paths `
            -BaseUrl $uri.AbsoluteUri.TrimEnd('/') `
            -ProviderId $script:OpenClawDemoModelProviderId `
            -ModelId $ModelId
    }
    else {
        if ($null -eq $ApiKey) {
            $ApiKey = Read-Host -Prompt '请输入 ModelFlare API Key（输入不会显示）' -AsSecureString
        }
        if ($null -eq $ApiKey -or $ApiKey.Length -lt 16) {
            throw '模型 API Key 为空或长度异常。'
        }

        $bstr = [IntPtr]::Zero
        $plainApiKey = $null
        try {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
            $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            if ([string]::IsNullOrWhiteSpace($plainApiKey) -or $plainApiKey -match '[\r\n]') {
                throw '模型 API Key 格式无效。'
            }
            $null = Set-OpenClawDemoModelProviderConfiguration `
                -Paths $paths `
                -BaseUrl $uri.AbsoluteUri.TrimEnd('/') `
                -ProviderId $script:OpenClawDemoModelProviderId `
                -ModelId $ModelId
            Set-OpenClawDemoModelApiKeyFile -Paths $paths -ApiKey $plainApiKey
            $configText = [System.IO.File]::ReadAllText($paths.ConfigPath)
            if ($configText.IndexOf($plainApiKey, [System.StringComparison]::Ordinal) -ge 0) {
                throw '安全检查失败：模型 API Key 出现在 OpenClaw JSON 配置中。'
            }
        }
        finally {
            $plainApiKey = $null
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    if (-not (Test-OpenClawDemoModelApiKeyFile -Paths $paths)) {
        throw '模型 API Key 未正确写入隔离状态文件。'
    }
    $config = Get-OpenClawDemoConfig -ConfigPath $paths.ConfigPath
    $provider = $config.models.providers.PSObject.Properties[$script:OpenClawDemoModelProviderId].Value
    $modelReference = "$($script:OpenClawDemoModelProviderId)/$ModelId"
    $secretRefValid = ($provider.apiKey.source -eq 'env' -and
        $provider.apiKey.provider -eq 'default' -and
        $provider.apiKey.id -eq $script:OpenClawDemoModelApiKeyEnvironmentVariable)
    if (-not $secretRefValid -or $provider.api -ne 'openai-completions' -or
        $config.agents.defaults.model.primary -ne $modelReference) {
        throw '模型 provider 配置写入后未通过本地结构检查。'
    }

    $gatewayPort = [int]$config.gateway.port
    $gatewayToken = New-OpenClawDemoGatewayToken -TokenPath $paths.GatewayTokenPath
    $environmentSnapshot = Set-OpenClawDemoEnvironment -Paths $paths -GatewayPort $gatewayPort -GatewayToken $gatewayToken
    try {
        $modelListOutput = (& $node $paths.OpenClawEntry models list --provider $script:OpenClawDemoModelProviderId --json 2>&1 | Out-String).Trim()
        $modelListExitCode = $LASTEXITCODE
        if ($modelListExitCode -ne 0 -or $modelListOutput -notmatch [regex]::Escape($modelReference)) {
            throw 'OpenClaw 未能从隔离配置中发现指定模型。'
        }
        $secretsAuditOutput = (& $node $paths.OpenClawEntry secrets audit --check 2>&1 | Out-String).Trim()
        $secretsAuditExitCode = $LASTEXITCODE
        $expectedIsolatedEnvFinding = ($secretsAuditExitCode -eq 1 -and
            $secretsAuditOutput -match 'plaintext=1,\s*unresolved=0,\s*shadowed=0,\s*legacy=0' -and
            $secretsAuditOutput -match '\.env:\$env\.OPENAI_API_KEY' -and
            $secretsAuditOutput -notmatch 'models\.json')
        if ($secretsAuditExitCode -ne 0 -and -not $expectedIsolatedEnvFinding) {
            throw 'OpenClaw secrets audit 发现了隔离 .env 之外的凭据问题。'
        }
        $secretsAuditStatus = if ($secretsAuditExitCode -eq 0) { 'clean' } else { 'expected_isolated_env_plaintext_only' }
    }
    finally {
        Restore-OpenClawDemoEnvironment -Snapshot $environmentSnapshot
    }

    [pscustomobject][ordered]@{
        status = 'configured_and_locally_validated'
        provider = $script:OpenClawDemoModelProviderId
        base_url = $uri.AbsoluteUri.TrimEnd('/')
        model = $modelReference
        api = 'openai-completions'
        credential_storage = '<DEMO_STATE>/state/.env'
        config_credential = 'environment_secret_ref'
        api_key_recorded = $false
        global_openclaw_used = $false
        model_list_exit_code = $modelListExitCode
        secrets_audit_exit_code = $secretsAuditExitCode
        secrets_audit_status = $secretsAuditStatus
        gateway_restart_required = $true
        next_step = '.\scripts\start_openclaw_agentguard_demo.ps1'
    } | ConvertTo-Json -Depth 6
}
catch {
    $message = $_.Exception.Message
    if ($null -ne (Get-Variable -Name paths -ValueOnly -ErrorAction SilentlyContinue)) {
        $message = ConvertTo-OpenClawDemoPortableText -Text $message -Paths $paths
    }
    $message = [regex]::Replace($message, '(?i)\bsk-[A-Za-z0-9_-]{16,}\b', '<REDACTED_API_KEY>')
    Write-Error $message
    exit 1
}
