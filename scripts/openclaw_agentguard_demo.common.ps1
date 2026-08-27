# Shared helpers for the isolated OpenClaw Control UI demonstration.
#
# This file intentionally keeps the Gateway token out of tracked files and
# command-line arguments.  It is dot-sourced only by the three public demo
# scripts in this directory.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OpenClawDemoExpectedVersion = '2026.7.1-2'
$script:OpenClawDemoModelProviderId = 'modelflare'
$script:OpenClawDemoModelId = 'gpt-5.6-sol'
# OpenClaw 2026.7.1-2 recognizes known provider environment names when it
# persists the generated models.json marker.  Using the isolated state's
# OPENAI_API_KEY keeps the marker non-secret and makes `secrets audit --check`
# distinguish it from plaintext for this OpenAI-compatible relay.
$script:OpenClawDemoModelApiKeyEnvironmentVariable = 'OPENAI_API_KEY'

function Get-OpenClawDemoProjectRoot {
    [CmdletBinding()]
    param()

    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    $adapterRoot = Join-Path $projectRoot 'integrations\openclaw_mcp'
    if (-not (Test-Path -LiteralPath $adapterRoot -PathType Container)) {
        throw "无法从脚本位置识别项目根目录：$projectRoot"
    }
    return $projectRoot
}

function Get-OpenClawDemoPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectRoot
    )

    $demoRoot = Join-Path $ProjectRoot 'integrations\openclaw_mcp\.e2e_state\visual-demo'
    return [pscustomobject]@{
        ProjectRoot = $ProjectRoot
        RuntimeDir = Join-Path $ProjectRoot 'third_party\runtime\openclaw-client'
        OpenClawEntry = Join-Path $ProjectRoot 'third_party\runtime\openclaw-client\node_modules\openclaw\openclaw.mjs'
        Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
        DevSubject = Join-Path $ProjectRoot 'integrations\openclaw_mcp\dev-subject.example.json'
        DemoRoot = $demoRoot
        StateDir = Join-Path $demoRoot 'state'
        ConfigPath = Join-Path $demoRoot 'state\openclaw.json'
        WorkspaceDir = Join-Path $demoRoot 'workspace'
        HomeDir = Join-Path $demoRoot 'home'
        RuntimeStateDir = Join-Path $demoRoot 'runtime'
        LogDir = Join-Path $demoRoot 'logs'
        AgentGuardStateDir = Join-Path $demoRoot 'agentguard-state'
        GatewayTokenPath = Join-Path $demoRoot 'runtime\gateway-token.txt'
        GatewayProcessPath = Join-Path $demoRoot 'runtime\gateway-process.json'
        ModelEnvironmentPath = Join-Path $demoRoot 'state\.env'
        AgentGuardTicketSecretPath = Join-Path $demoRoot 'runtime\agentguard-ticket-secret.txt'
        AgentGuardProcessPath = Join-Path $demoRoot 'runtime\agentguard-process.json'
    }
}

function Initialize-OpenClawDemoDirectories {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths
    )

    foreach ($path in @(
        $Paths.DemoRoot,
        $Paths.StateDir,
        $Paths.WorkspaceDir,
        $Paths.HomeDir,
        $Paths.RuntimeStateDir,
        $Paths.LogDir,
        $Paths.AgentGuardStateDir
    )) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

function Resolve-OpenClawDemoNode {
    [CmdletBinding()]
    param(
        [string]$NodePath
    )

    if (-not [string]::IsNullOrWhiteSpace($NodePath)) {
        if (-not (Test-Path -LiteralPath $NodePath -PathType Leaf)) {
            throw "指定的 Node.js 文件不存在：$NodePath"
        }
        return (Resolve-Path -LiteralPath $NodePath).Path
    }

    $bundledNode = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
    if (Test-Path -LiteralPath $bundledNode -PathType Leaf) {
        return (Resolve-Path -LiteralPath $bundledNode).Path
    }

    throw '未找到 Codex bundled Node 运行时。请先确认该运行时已安装，或通过 -NodePath 显式传入已验证的 Node.js；不会自动改用 PATH 中的未验证 Node。'
}

function Resolve-OpenClawDemoPnpm {
    [CmdletBinding()]
    param(
        [string]$PnpmPath
    )

    if (-not [string]::IsNullOrWhiteSpace($PnpmPath)) {
        if (-not (Test-Path -LiteralPath $PnpmPath -PathType Leaf)) {
            throw "指定的 pnpm 文件不存在：$PnpmPath"
        }
        return (Resolve-Path -LiteralPath $PnpmPath).Path
    }

    $bundledPnpm = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pnpm.cmd'
    if (Test-Path -LiteralPath $bundledPnpm -PathType Leaf) {
        return (Resolve-Path -LiteralPath $bundledPnpm).Path
    }

    throw '项目内 OpenClaw 缺失且未找到 Codex bundled pnpm。请先确认 bundled runtime 已安装，或通过 -PnpmPath 显式传入 pnpm；不会自动改用 PATH 中的未验证 pnpm。'
}

function Get-OpenClawDemoVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NodePath,
        [Parameter(Mandatory)]
        [string]$OpenClawEntry
    )

    if (-not (Test-Path -LiteralPath $OpenClawEntry -PathType Leaf)) {
        throw "没有找到项目内 OpenClaw 入口文件：$OpenClawEntry"
    }
    $output = (& $NodePath $OpenClawEntry --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "项目内 OpenClaw 无法启动（退出码 $LASTEXITCODE）。"
    }
    return $output
}

function Test-OpenClawDemoExpectedVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Version
    )

    return $Version -match ('^OpenClaw\s+' + [regex]::Escape($script:OpenClawDemoExpectedVersion) + '(\s|\()')
}

function Install-OpenClawDemoRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NodePath,
        [Parameter(Mandatory)]
        [string]$PnpmPath,
        [Parameter(Mandatory)]
        [string]$RuntimeDir
    )

    New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
    $originalPath = $env:Path
    try {
        $env:Path = "$(Split-Path -Parent $NodePath);$originalPath"
        & $PnpmPath add `
            --dir $RuntimeDir `
            --ignore-workspace `
            --allow-build=openclaw `
            --allow-build=protobufjs `
            --allow-build=tree-sitter-bash `
            --allow-build='@google/genai' `
            "openclaw@$script:OpenClawDemoExpectedVersion"
        if ($LASTEXITCODE -ne 0) {
            throw 'OpenClaw 安装失败，已停止后续接入。'
        }
    }
    finally {
        $env:Path = $originalPath
    }
}

function Set-OpenClawDemoObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$Name,
        [AllowNull()]
        [object]$Value
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    else {
        $property.Value = $Value
    }
}

function Remove-OpenClawDemoObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        $Object.PSObject.Properties.Remove($Name)
    }
}

function Get-OrAddOpenClawDemoObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        $value = [pscustomobject]@{}
        Set-OpenClawDemoObjectProperty -Object $Object -Name $Name -Value $value
        return $value
    }
    if ($property.Value -is [string] -or $property.Value -is [ValueType]) {
        throw "演示配置中的 '$Name' 必须是对象。"
    }
    return $property.Value
}

function Write-OpenClawDemoJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $json = $Value | ConvertTo-Json -Depth 32
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, "$json`n", $utf8WithoutBom)
}

function Get-OpenClawDemoFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "无法计算不存在文件的 SHA-256：$Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-OpenClawDemoConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "未找到隔离 OpenClaw 配置：$ConfigPath。请先运行 setup 脚本。"
    }
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "隔离 OpenClaw 配置不是有效 JSON：$ConfigPath。$($_.Exception.Message)"
    }
    if ($null -eq $config) {
        throw "隔离 OpenClaw 配置为空：$ConfigPath"
    }
    return $config
}

function Write-OpenClawDemoConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [ValidateRange(1024, 65535)]
        [int]$GatewayPort
    )

    if (Test-Path -LiteralPath $Paths.ConfigPath -PathType Leaf) {
        $config = Get-OpenClawDemoConfig -ConfigPath $Paths.ConfigPath
    }
    else {
        $config = [pscustomobject]@{}
    }

    $gateway = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'gateway'
    $controlUi = Get-OrAddOpenClawDemoObjectProperty -Object $gateway -Name 'controlUi'
    $auth = Get-OrAddOpenClawDemoObjectProperty -Object $gateway -Name 'auth'
    $agents = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'agents'
    $defaults = Get-OrAddOpenClawDemoObjectProperty -Object $agents -Name 'defaults'
    $mcp = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'mcp'
    $servers = Get-OrAddOpenClawDemoObjectProperty -Object $mcp -Name 'servers'
    $tools = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'tools'

    # The visual demo is intentionally a single-server configuration.  Remove
    # inherited entries before OpenClaw reads the file so another team's MCP
    # server cannot silently become part of this evidence run.
    foreach ($serverName in @($servers.PSObject.Properties.Name)) {
        if ($serverName -ne 'agentguard-notices') {
            $servers.PSObject.Properties.Remove($serverName)
        }
    }

    Set-OpenClawDemoObjectProperty -Object $gateway -Name 'mode' -Value 'local'
    Set-OpenClawDemoObjectProperty -Object $gateway -Name 'bind' -Value 'loopback'
    Set-OpenClawDemoObjectProperty -Object $gateway -Name 'port' -Value $GatewayPort
    Set-OpenClawDemoObjectProperty -Object $controlUi -Name 'enabled' -Value $true
    Set-OpenClawDemoObjectProperty -Object $auth -Name 'mode' -Value 'token'
    # The token is intentionally supplied only through the child process environment.
    Remove-OpenClawDemoObjectProperty -Object $auth -Name 'token'
    Set-OpenClawDemoObjectProperty -Object $defaults -Name 'workspace' -Value $Paths.WorkspaceDir
    # The MCP server filter controls only MCP methods.  Restrict OpenClaw's
    # own built-in tools separately so an untrusted prompt cannot reach file,
    # process, browser, session, or other native capability surfaces.
    Set-OpenClawDemoObjectProperty -Object $tools -Name 'profile' -Value 'minimal'
    # `allow` is a further restriction of the selected profile.  `minimal`
    # contains only session_status, so use `alsoAllow` to add the single MCP
    # capability without re-enabling any native tool.
    Remove-OpenClawDemoObjectProperty -Object $tools -Name 'allow'
    Set-OpenClawDemoObjectProperty -Object $tools -Name 'alsoAllow' -Value @('agentguard-notices__list_notices')
    Set-OpenClawDemoObjectProperty -Object $tools -Name 'deny' -Value @(
        'group:fs',
        'group:runtime',
        'group:openclaw',
        'group:ui',
        'session_status'
    )

    Write-OpenClawDemoJsonFile -Path $Paths.ConfigPath -Value $config
    return $config
}

function Set-OpenClawDemoGatewayPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [ValidateRange(1024, 65535)]
        [int]$GatewayPort
    )

    $config = Get-OpenClawDemoConfig -ConfigPath $Paths.ConfigPath
    $gateway = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'gateway'
    Set-OpenClawDemoObjectProperty -Object $gateway -Name 'port' -Value $GatewayPort
    Write-OpenClawDemoJsonFile -Path $Paths.ConfigPath -Value $config
}

function Set-OpenClawDemoMcpServerOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [object]$Definition
    )

    $config = Get-OpenClawDemoConfig -ConfigPath $Paths.ConfigPath
    $mcp = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'mcp'
    $servers = Get-OrAddOpenClawDemoObjectProperty -Object $mcp -Name 'servers'
    foreach ($serverName in @($servers.PSObject.Properties.Name)) {
        if ($serverName -ne 'agentguard-notices') {
            $servers.PSObject.Properties.Remove($serverName)
        }
    }
    Set-OpenClawDemoObjectProperty -Object $servers -Name 'agentguard-notices' -Value $Definition
    Write-OpenClawDemoJsonFile -Path $Paths.ConfigPath -Value $config
    return $config
}

function Set-OpenClawDemoModelProviderConfiguration {
    <#
    .SYNOPSIS
    Add the single approved OpenAI-compatible model provider to the isolated
    visual-demo configuration.

    .DESCRIPTION
    The provider credential is intentionally a SecretRef.  The actual value is
    stored only in the ignored state .env file and is never written into this
    JSON configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [ValidatePattern('^https://[^/]+/v1$')]
        [string]$BaseUrl,
        [string]$ProviderId = $script:OpenClawDemoModelProviderId,
        [string]$ModelId = $script:OpenClawDemoModelId,
        [string]$ApiKeyEnvironmentVariable = $script:OpenClawDemoModelApiKeyEnvironmentVariable
    )

    $config = Get-OpenClawDemoConfig -ConfigPath $Paths.ConfigPath
    $agents = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'agents'
    $defaults = Get-OrAddOpenClawDemoObjectProperty -Object $agents -Name 'defaults'
    $models = Get-OrAddOpenClawDemoObjectProperty -Object $config -Name 'models'
    $providers = Get-OrAddOpenClawDemoObjectProperty -Object $models -Name 'providers'

    $modelReference = "$ProviderId/$ModelId"
    $provider = [pscustomobject]@{
        baseUrl = $BaseUrl
        apiKey = [pscustomobject]@{
            source = 'env'
            provider = 'default'
            id = $ApiKeyEnvironmentVariable
        }
        api = 'openai-completions'
        models = @(
            [pscustomobject]@{
                id = $ModelId
                name = $ModelId
            }
        )
    }
    Set-OpenClawDemoObjectProperty -Object $providers -Name $ProviderId -Value $provider
    Set-OpenClawDemoObjectProperty -Object $models -Name 'mode' -Value 'merge'
    Set-OpenClawDemoObjectProperty -Object $defaults -Name 'model' -Value ([pscustomobject]@{
        primary = $modelReference
    })
    $defaultModels = Get-OrAddOpenClawDemoObjectProperty -Object $defaults -Name 'models'
    Set-OpenClawDemoObjectProperty -Object $defaultModels -Name $modelReference -Value ([pscustomobject]@{
        alias = $ModelId
    })

    Write-OpenClawDemoJsonFile -Path $Paths.ConfigPath -Value $config
    return $config
}

function Set-OpenClawDemoModelApiKeyFile {
    <#
    .SYNOPSIS
    Persist a model API key exclusively in the Git-ignored isolated state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey,
        [string]$EnvironmentVariable = $script:OpenClawDemoModelApiKeyEnvironmentVariable
    )

    if ($ApiKey -match '[\r\n]') {
        throw '模型 API 密钥不能包含换行符。'
    }
    $parent = Split-Path -Parent $Paths.ModelEnvironmentPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $Paths.ModelEnvironmentPath,
        "$EnvironmentVariable=$ApiKey`n",
        $utf8WithoutBom
    )
    # Limit the local file to the current user where Windows ACLs are
    # available.  A failure here should not echo the credential or leave an
    # ambiguous configuration result.
    try {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $Paths.ModelEnvironmentPath /inheritance:r /grant:r "${currentIdentity}:(R,W)" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw '无法设置模型密钥文件的用户级 ACL。'
        }
    }
    catch {
        Remove-Item -LiteralPath $Paths.ModelEnvironmentPath -Force -ErrorAction SilentlyContinue
        throw '模型密钥文件权限设置失败；未保留该文件。'
    }
}

function Test-OpenClawDemoModelApiKeyFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [string]$EnvironmentVariable = $script:OpenClawDemoModelApiKeyEnvironmentVariable
    )

    if (-not (Test-Path -LiteralPath $Paths.ModelEnvironmentPath -PathType Leaf)) {
        return $false
    }
    $content = [System.IO.File]::ReadAllText($Paths.ModelEnvironmentPath)
    return $content -match ('^' + [regex]::Escape($EnvironmentVariable) + '=[^\r\n]+\r?\n?$')
}

function Set-OpenClawDemoEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [ValidateRange(1024, 65535)]
        [int]$GatewayPort,
        [string]$GatewayToken
    )

    $names = @(
        'OPENCLAW_STATE_DIR',
        'OPENCLAW_CONFIG_PATH',
        'OPENCLAW_HOME',
        'OPENCLAW_GATEWAY_PORT',
        'OPENCLAW_GATEWAY_TOKEN',
        $script:OpenClawDemoModelApiKeyEnvironmentVariable
    )
    $snapshot = @{}
    foreach ($name in $names) {
        $exists = Test-Path -LiteralPath "Env:$name"
        $snapshot[$name] = [pscustomobject]@{
            Exists = $exists
            Value = if ($exists) { (Get-Item -LiteralPath "Env:$name").Value } else { $null }
        }
    }

    $env:OPENCLAW_STATE_DIR = $Paths.StateDir
    $env:OPENCLAW_CONFIG_PATH = $Paths.ConfigPath
    $env:OPENCLAW_HOME = $Paths.HomeDir
    $env:OPENCLAW_GATEWAY_PORT = [string]$GatewayPort
    if ([string]::IsNullOrWhiteSpace($GatewayToken)) {
        Remove-Item -LiteralPath 'Env:OPENCLAW_GATEWAY_TOKEN' -ErrorAction SilentlyContinue
    }
    else {
        $env:OPENCLAW_GATEWAY_TOKEN = $GatewayToken
    }
    # The isolated state .env is the single credential source.  Do not let an
    # unrelated inherited shell value override it for a demo run.
    Remove-Item -LiteralPath ("Env:" + $script:OpenClawDemoModelApiKeyEnvironmentVariable) -ErrorAction SilentlyContinue
    return $snapshot
}

function Restore-OpenClawDemoEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Snapshot
    )

    foreach ($name in $Snapshot.Keys) {
        $saved = $Snapshot[$name]
        if ($saved.Exists) {
            Set-Item -LiteralPath "Env:$name" -Value $saved.Value
        }
        else {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        }
    }
}

function Assert-OpenClawDemoAgentGuardUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl
    )

    try {
        $uri = [uri]$BaseUrl
    }
    catch {
        throw "AGENTGUARD_MCP_BASE_URL 不是有效 URL：$BaseUrl"
    }
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http', 'https')) {
        throw 'AGENTGUARD_MCP_BASE_URL 必须是绝对 http(s) URL。'
    }
    if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment)) {
        throw 'AGENTGUARD_MCP_BASE_URL 不能包含用户名、密码、查询参数或片段；凭据必须使用受控身份文件或 OIDC。'
    }
    if ($uri.Scheme -eq 'http' -and -not $uri.IsLoopback) {
        throw '非回环 AgentGuard 地址必须使用 HTTPS。'
    }
    return $uri.AbsoluteUri.TrimEnd('/')
}

function New-OpenClawDemoMcpDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [string]$AgentGuardBaseUrl
    )

    if (-not (Test-Path -LiteralPath $Paths.Python -PathType Leaf)) {
        throw "未找到项目 Python 环境：$($Paths.Python)"
    }
    if (-not (Test-Path -LiteralPath $Paths.DevSubject -PathType Leaf)) {
        throw "未找到受控回环测试身份文件：$($Paths.DevSubject)"
    }
    return @{
        command = $Paths.Python
        args = @('-m', 'integrations.openclaw_mcp')
        cwd = $Paths.ProjectRoot
        env = @{
            AGENTGUARD_MCP_BASE_URL = $AgentGuardBaseUrl
            AGENTGUARD_MCP_IDENTITY_MODE = 'loopback_static_dev'
            AGENTGUARD_MCP_DEV_SUBJECT_FILE = $Paths.DevSubject
        }
        requestTimeoutMs = 20000
        connectionTimeoutMs = 8000
        supportsParallelToolCalls = $false
        toolFilter = @{ include = @('list_notices') }
    }
}

function New-OpenClawDemoAgentGuardTicketSecret {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Paths)

    if (Test-Path -LiteralPath $Paths.AgentGuardTicketSecretPath -PathType Leaf) {
        $existing = (Get-Content -LiteralPath $Paths.AgentGuardTicketSecretPath -Raw).Trim()
        if ($existing -match '^[0-9a-fA-F]{64,}$') { return }
    }
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $secretHex = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    [Array]::Clear($bytes, 0, $bytes.Length)
    [System.IO.File]::WriteAllText($Paths.AgentGuardTicketSecretPath, $secretHex, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $Paths.AgentGuardTicketSecretPath /inheritance:r /grant:r "${identity}:(R,W)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'ACL update failed' }
    }
    catch {
        Remove-Item -LiteralPath $Paths.AgentGuardTicketSecretPath -Force -ErrorAction SilentlyContinue
        throw 'AgentGuard 临时票据密钥文件权限设置失败；未保留该文件。'
    }
}

function Get-OpenClawDemoAgentGuardProcessRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Paths)
    if (-not (Test-Path -LiteralPath $Paths.AgentGuardProcessPath -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Paths.AgentGuardProcessPath -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Test-OpenClawDemoAgentGuardProcessIdentity {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory)][pscustomobject]$Paths,
        [int]$Port = 8080
    )
    if ($null -eq $Record) { return $false }
    foreach ($name in @('process_id', 'process_started_at', 'status', 'python_path', 'port', 'command')) {
        if ($null -eq $Record.PSObject.Properties[$name]) { return $false }
    }
    if ([string]($Record.status) -ne 'ready' -or [int]($Record.port) -ne $Port -or
        [string]($Record.python_path) -ne $Paths.Python -or
        [string]($Record.command) -ne '<PYTHON> -m service --host 127.0.0.1 --port <PORT> --opa-mode rest --manage-opa --state-dir <DEMO_STATE>/agentguard-state --enable-local-adapters') {
        return $false
    }
    try {
        $processId = [int]($Record.process_id)
        $process = Get-Process -Id $processId -ErrorAction Stop
        $recordedStart = $Record.process_started_at
        if ($recordedStart -is [DateTimeOffset]) { $expectedStart = $recordedStart.UtcDateTime }
        elseif ($recordedStart -is [DateTime]) { $expectedStart = $recordedStart.ToUniversalTime() }
        else { $expectedStart = ([DateTimeOffset]::Parse([string]$recordedStart)).UtcDateTime }
        if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $expectedStart).TotalSeconds) -gt 2) { return $false }
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop).CommandLine
        return (-not [string]::IsNullOrWhiteSpace($commandLine) -and
            $commandLine.IndexOf($Paths.Python, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $commandLine -match '(?i)-m\s+service\b' -and
            $commandLine -match ('(?i)--port\s+' + [regex]::Escape([string]$Port) + '\b') -and
            $commandLine.IndexOf($Paths.AgentGuardStateDir, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $commandLine -match '(?i)--enable-local-adapters\b')
    }
    catch { return $false }
}

function Test-OpenClawDemoAgentGuardReady {
    [CmdletBinding()]
    param([int]$Port = 8080)
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/readyz" -TimeoutSec 5
        return ($response.ready -eq $true)
    }
    catch { return $false }
}

function Start-OpenClawDemoAgentGuardBackend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Paths,
        [int]$Port = 8080,
        [int]$OpaPort = 8181
    )
    if (-not (Test-Path -LiteralPath $Paths.Python -PathType Leaf)) {
        throw "未找到项目 Python 环境：$($Paths.Python)"
    }
    $record = Get-OpenClawDemoAgentGuardProcessRecord -Paths $Paths
    $recordIdentityValid = Test-OpenClawDemoAgentGuardProcessIdentity -Record $record -Paths $Paths -Port $Port
    if ($recordIdentityValid) {
        if (Test-OpenClawDemoAgentGuardReady -Port $Port) {
            return [pscustomobject]@{ Status = 'already_running'; ProcessId = [int]($record.process_id); Port = $Port }
        }
        # The exact recorded demo backend is unhealthy (for example, its OPA
        # child stopped responding). Restart only this validated process tree.
        $staleProcessId = [int]($record.process_id)
        $childIds = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $staleProcessId" -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.ProcessId })
        foreach ($childId in $childIds) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $staleProcessId -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $staleProcessId -Timeout 10 -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Paths.AgentGuardProcessPath -Force -ErrorAction SilentlyContinue
        for ($attempt = 1; $attempt -le 20 -and (-not (Test-OpenClawDemoPortAvailable -Port $Port) -or -not (Test-OpenClawDemoPortAvailable -Port $OpaPort)); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not (Test-OpenClawDemoPortAvailable -Port $Port)) {
        throw "AgentGuard 演示端口 $Port 已被未验证的进程占用；不会停止或复用该进程。"
    }
    if (-not (Test-OpenClawDemoPortAvailable -Port $OpaPort)) {
        throw "OPA 演示端口 $OpaPort 已被未验证的进程占用；不会停止或复用该进程。"
    }
    New-OpenClawDemoAgentGuardTicketSecret -Paths $Paths
    $savedSecretFile = if (Test-Path Env:AGENTGUARD_TICKET_SECRET_FILE) { $env:AGENTGUARD_TICKET_SECRET_FILE } else { $null }
    $savedProbeWrites = if (Test-Path Env:AGENTGUARD_READINESS_PROBE_WRITES) { $env:AGENTGUARD_READINESS_PROBE_WRITES } else { $null }
    try {
        $env:AGENTGUARD_TICKET_SECRET_FILE = $Paths.AgentGuardTicketSecretPath
        $env:AGENTGUARD_READINESS_PROBE_WRITES = 'false'
        $process = Start-Process `
            -FilePath $Paths.Python `
            -ArgumentList @('-m', 'service', '--host', '127.0.0.1', '--port', $Port, '--opa-mode', 'rest', '--opa-base-url', "http://127.0.0.1:$OpaPort", '--manage-opa', '--state-dir', $Paths.AgentGuardStateDir, '--enable-local-adapters') `
            -WorkingDirectory $Paths.ProjectRoot `
            -RedirectStandardOutput (Join-Path $Paths.LogDir 'agentguard.stdout.log') `
            -RedirectStandardError (Join-Path $Paths.LogDir 'agentguard.stderr.log') `
            -WindowStyle Hidden `
            -PassThru
    }
    finally {
        if ($null -eq $savedSecretFile) { Remove-Item Env:AGENTGUARD_TICKET_SECRET_FILE -ErrorAction SilentlyContinue } else { $env:AGENTGUARD_TICKET_SECRET_FILE = $savedSecretFile }
        if ($null -eq $savedProbeWrites) { Remove-Item Env:AGENTGUARD_READINESS_PROBE_WRITES -ErrorAction SilentlyContinue } else { $env:AGENTGUARD_READINESS_PROBE_WRITES = $savedProbeWrites }
    }
    $ready = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        if (Test-OpenClawDemoAgentGuardReady -Port $Port) { $ready = $true; break }
        if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        $childIds = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)" -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.ProcessId })
        foreach ($childId in $childIds) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "AgentGuard 演示服务未就绪。请检查已忽略的日志目录：$($Paths.LogDir)"
    }
    $startedAt = (Get-Process -Id $process.Id).StartTime.ToUniversalTime().ToString('o')
    Write-OpenClawDemoJsonFile -Path $Paths.AgentGuardProcessPath -Value ([ordered]@{
        process_id = [int]$process.Id
        process_started_at = $startedAt
        recorded_at = [DateTime]::UtcNow.ToString('o')
        status = 'ready'
        python_path = $Paths.Python
        port = $Port
        opa_port = $OpaPort
        command = '<PYTHON> -m service --host 127.0.0.1 --port <PORT> --opa-mode rest --manage-opa --state-dir <DEMO_STATE>/agentguard-state --enable-local-adapters'
        secret_value_recorded = $false
    })
    return [pscustomobject]@{ Status = 'started'; ProcessId = [int]$process.Id; Port = $Port }
}

function Protect-OpenClawDemoGatewayTokenFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TokenPath
    )

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $TokenPath /inheritance:r /grant:r "${identity}:(R,W)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'ACL update failed' }
    }
    catch {
        Remove-Item -LiteralPath $TokenPath -Force -ErrorAction SilentlyContinue
        throw 'Gateway token 文件权限设置失败；未保留该文件。'
    }
}

function New-OpenClawDemoGatewayToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TokenPath
    )

    if (Test-Path -LiteralPath $TokenPath -PathType Leaf) {
        $existing = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
        if ($existing.Length -ge 32) {
            Protect-OpenClawDemoGatewayTokenFile -TokenPath $TokenPath
            return $existing
        }
    }

    $parent = Split-Path -Parent $TokenPath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Set-Content -LiteralPath $TokenPath -Value $token -NoNewline -Encoding ascii
    Protect-OpenClawDemoGatewayTokenFile -TokenPath $TokenPath
    return $token
}

function Test-OpenClawDemoPortAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1024, 65535)]
        [int]$Port
    )

    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    }
    catch [System.Net.Sockets.SocketException] {
        return $false
    }
    finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Select-OpenClawDemoGatewayPort {
    [CmdletBinding()]
    param(
        [ValidateRange(1024, 65535)]
        [int]$PreferredPort = 18789
    )

    if (Test-OpenClawDemoPortAvailable -Port $PreferredPort) {
        return $PreferredPort
    }

    $lastCandidate = [Math]::Min($PreferredPort + 100, 65535)
    for ($candidate = $PreferredPort + 1; $candidate -le $lastCandidate; $candidate++) {
        if (Test-OpenClawDemoPortAvailable -Port $candidate) {
            return $candidate
        }
    }

    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return [int](($listener.LocalEndpoint).Port)
    }
    finally {
        $listener.Stop()
    }
}

function Write-OpenClawDemoGatewayProcessRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [Parameter(Mandatory)]
        [int]$Port
        ,
        [Parameter(Mandatory)]
        [string]$NodePath
        ,
        [Parameter(Mandatory)]
        [string]$OpenClawEntry
        ,
        [ValidateSet('starting', 'ready', 'failed_to_become_ready')]
        [string]$Status = 'ready'
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    $processStartedAt = $null
    $processPath = $null
    if ($null -ne $process) {
        try {
            $processStartedAt = $process.StartTime.ToUniversalTime().ToString('o')
        }
        catch {
            $processStartedAt = $null
        }
        try {
            $processPath = $process.MainModule.FileName
        }
        catch {
            $processPath = $null
        }
    }
    Write-OpenClawDemoJsonFile -Path $Paths.GatewayProcessPath -Value ([ordered]@{
        process_id = $ProcessId
        port = $Port
        process_started_at = $processStartedAt
        recorded_at = [DateTime]::UtcNow.ToString('o')
        status = $Status
        config_sha256 = Get-OpenClawDemoFileSha256 -Path $Paths.ConfigPath
        node_path = $NodePath
        openclaw_entry = $OpenClawEntry
        process_path = $processPath
        command = '<NODE> <OPENCLAW_ENTRY> gateway run --bind loopback --port <PORT> --auth token'
        gateway_token_recorded = $false
    })
}

function Get-OpenClawDemoGatewayProcessRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Paths
    )

    if (-not (Test-Path -LiteralPath $Paths.GatewayProcessPath -PathType Leaf)) {
        return $null
    }
    try {
        return Get-Content -LiteralPath $Paths.GatewayProcessPath -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Test-OpenClawDemoGatewayProcessIdentity {
    <#
    .SYNOPSIS
    Prove that a recorded PID is the isolated demo Gateway before stopping it.

    .DESCRIPTION
    This deliberately ignores the current configuration hash, allowing a
    verified old demo process to be stopped after the config changes.  PID,
    start time, executable path, OpenClaw entry, port and complete Gateway
    command shape must still match.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Record,
        [Parameter(Mandatory)][string]$ExpectedNodePath,
        [Parameter(Mandatory)][string]$ExpectedOpenClawEntry
    )

    if ($null -eq $Record) { return $false }
    $requiredNames = @('process_id', 'port', 'process_started_at', 'status', 'node_path', 'openclaw_entry', 'command')
    foreach ($name in $requiredNames) {
        if ($null -eq $Record.PSObject.Properties[$name]) { return $false }
    }
    if ([string]($Record.status) -ne 'ready' -or
        [string]($Record.node_path) -ne $ExpectedNodePath -or
        [string]($Record.openclaw_entry) -ne $ExpectedOpenClawEntry -or
        [string]($Record.command) -ne '<NODE> <OPENCLAW_ENTRY> gateway run --bind loopback --port <PORT> --auth token') {
        return $false
    }
    try {
        $processId = [int]($Record.process_id)
        $port = [int]($Record.port)
        $process = Get-Process -Id $processId -ErrorAction Stop
        $recordedStart = $Record.process_started_at
        if ($recordedStart -is [DateTimeOffset]) {
            $expectedStart = $recordedStart.UtcDateTime
        }
        elseif ($recordedStart -is [DateTime]) {
            $expectedStart = $recordedStart.ToUniversalTime()
        }
        else {
            $expectedStart = ([DateTimeOffset]::Parse(
                [string]$recordedStart,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind
            )).UtcDateTime
        }
        if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $expectedStart).TotalSeconds) -gt 2) { return $false }
        $actualPath = $process.MainModule.FileName
        if (-not [string]::IsNullOrWhiteSpace($actualPath) -and
            -not [string]::Equals((Resolve-Path -LiteralPath $actualPath).Path, $ExpectedNodePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $commandLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop).CommandLine
        return (-not [string]::IsNullOrWhiteSpace($commandLine) -and
            $commandLine.IndexOf($ExpectedOpenClawEntry, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $commandLine -match '(?i)\bgateway\s+run\b' -and
            $commandLine -match '(?i)--bind\s+loopback\b' -and
            $commandLine -match ('(?i)--port\s+' + [regex]::Escape([string]$port) + '\b') -and
            $commandLine -match '(?i)--auth\s+token\b')
    }
    catch {
        return $false
    }
}

function Test-OpenClawDemoGatewayProcessRunning {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Record,
        [Parameter(Mandatory)]
        [string]$ExpectedConfigHash,
        [Parameter(Mandatory)]
        [int]$ExpectedPort,
        [Parameter(Mandatory)]
        [string]$ExpectedNodePath,
        [Parameter(Mandatory)]
        [string]$ExpectedOpenClawEntry,
        [Parameter(Mandatory)]
        [string]$ExpectedConfigPath
    )

    if ($null -eq $Record) {
        return $false
    }
    $processIdProperty = $Record.PSObject.Properties['process_id']
    $statusProperty = $Record.PSObject.Properties['status']
    $recordHashProperty = $Record.PSObject.Properties['config_sha256']
    $recordPortProperty = $Record.PSObject.Properties['port']
    $recordStartedProperty = $Record.PSObject.Properties['process_started_at']
    $recordNodeProperty = $Record.PSObject.Properties['node_path']
    $recordEntryProperty = $Record.PSObject.Properties['openclaw_entry']
    $recordCommandProperty = $Record.PSObject.Properties['command']
    if ($null -eq $processIdProperty -or $null -eq $recordHashProperty -or
        $null -eq $recordPortProperty -or $null -eq $recordStartedProperty -or
        $null -eq $recordNodeProperty -or $null -eq $recordEntryProperty -or
        $null -eq $recordCommandProperty) {
        return $false
    }
    if ($null -eq $statusProperty -or [string]($statusProperty.Value) -ne 'ready') {
        return $false
    }
    if ([string]($recordHashProperty.Value) -ne $ExpectedConfigHash -or
        [int]($recordPortProperty.Value) -ne $ExpectedPort -or
        [string]($recordNodeProperty.Value) -ne $ExpectedNodePath -or
        [string]($recordEntryProperty.Value) -ne $ExpectedOpenClawEntry -or
        [string]($recordCommandProperty.Value) -ne '<NODE> <OPENCLAW_ENTRY> gateway run --bind loopback --port <PORT> --auth token') {
        return $false
    }
    try {
        $configuredGateway = Get-OpenClawDemoPropertyValueForProcessRecord -Object (Get-OpenClawDemoConfig -ConfigPath $ExpectedConfigPath) -Name 'gateway'
        $configuredPort = Get-OpenClawDemoPropertyValueForProcessRecord -Object $configuredGateway -Name 'port'
        if ($null -eq $configuredPort -or [int]$configuredPort -ne $ExpectedPort) {
            return $false
        }
        $process = Get-Process -Id ([int]($processIdProperty.Value)) -ErrorAction Stop
        $actualStartedAt = $process.StartTime.ToUniversalTime()
        $recordStartedValue = $recordStartedProperty.Value
        if ($recordStartedValue -is [DateTimeOffset]) {
            $expectedStartedAt = $recordStartedValue.UtcDateTime
        }
        elseif ($recordStartedValue -is [DateTime]) {
            $expectedStartedAt = $recordStartedValue.ToUniversalTime()
        }
        else {
            $expectedStartedAt = ([DateTimeOffset]::Parse(
                [string]$recordStartedValue,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind
            )).UtcDateTime
        }
        if ([Math]::Abs(($actualStartedAt - $expectedStartedAt).TotalSeconds) -gt 2) {
            return $false
        }
        $actualPath = $null
        try {
            $actualPath = $process.MainModule.FileName
        }
        catch {
            $actualPath = $null
        }
        if (-not [string]::IsNullOrWhiteSpace($actualPath) -and
            -not [string]::Equals((Resolve-Path -LiteralPath $actualPath).Path, $ExpectedNodePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $commandLine = $null
        try {
            $commandLine = (Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = " + [int]($processIdProperty.Value)) -ErrorAction Stop).CommandLine
        }
        catch {
            return $false
        }
        if ([string]::IsNullOrWhiteSpace($commandLine) -or
            $commandLine.IndexOf($ExpectedOpenClawEntry, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $commandLine -notmatch '(?i)\bgateway\s+run\b' -or
            $commandLine -notmatch '(?i)--bind\s+loopback\b' -or
            $commandLine -notmatch ('(?i)--port\s+' + [regex]::Escape([string]$ExpectedPort) + '\b') -or
            $commandLine -notmatch '(?i)--auth\s+token\b') {
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-OpenClawDemoPropertyValueForProcessRecord {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Object,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Start-OpenClawDemoGatewayBackground {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NodePath,
        [Parameter(Mandatory)]
        [string]$OpenClawEntry,
        [Parameter(Mandatory)]
        [string]$ProjectRoot,
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [Parameter(Mandatory)]
        [int]$Port
    )

    $stdoutPath = Join-Path $Paths.LogDir 'gateway.stdout.log'
    $stderrPath = Join-Path $Paths.LogDir 'gateway.stderr.log'
    $process = Start-Process `
        -FilePath $NodePath `
        -ArgumentList @($OpenClawEntry, 'gateway', 'run', '--bind', 'loopback', '--port', $Port, '--auth', 'token') `
        -WorkingDirectory $ProjectRoot `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -WindowStyle Hidden `
        -PassThru
    return $process
}

function Wait-OpenClawDemoGatewayHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NodePath,
        [Parameter(Mandatory)]
        [string]$OpenClawEntry,
        [Parameter(Mandatory)]
        [int]$Port,
        [ValidateRange(1, 90)]
        [int]$Attempts = 45
    )

    # `openclaw gateway health` is deliberately executed by the verification
    # script and preserved in its evidence.  It can take noticeable CLI startup
    # time on Windows, so the launcher uses the unauthenticated static Control
    # UI page only to determine that its just-created loopback Gateway is ready.
    # This avoids leaving slow health CLI children behind while the user starts
    # an interactive demo.
    $url = "http://127.0.0.1:$Port/"
    $lastOutput = ''
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing
            if ($response.StatusCode -eq 200 -and $response.Content -match 'OpenClaw Control') {
                return [pscustomobject]@{
                    Healthy = $true
                    Attempts = $attempt
                    ExitCode = 0
                    Output = 'Control UI HTTP 200'
                }
            }
            $lastOutput = "Control UI returned HTTP $($response.StatusCode)."
        }
        catch {
            $lastOutput = $_.Exception.Message
        }
        if ($attempt -lt $Attempts) {
            Start-Sleep -Seconds 1
        }
    }
    return [pscustomobject]@{
        Healthy = $false
        Attempts = $Attempts
        ExitCode = 1
        Output = $lastOutput
    }
}

function ConvertTo-OpenClawDemoPortableText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text,
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [string]$GatewayToken
    )

    if ($null -eq $Text) {
        return ''
    }
    $result = $Text
    $pathReplacements = @(
        @{ Value = $Paths.ProjectRoot; Replacement = '<PROJECT_ROOT>' },
        @{ Value = $Paths.DemoRoot; Replacement = '<DEMO_STATE>' },
        @{ Value = $Paths.StateDir; Replacement = '<DEMO_STATE>/state' },
        @{ Value = $Paths.ConfigPath; Replacement = '<DEMO_STATE>/state/openclaw.json' },
        @{ Value = $Paths.WorkspaceDir; Replacement = '<DEMO_STATE>/workspace' },
        @{ Value = $Paths.HomeDir; Replacement = '<DEMO_STATE>/home' },
        @{ Value = $Paths.RuntimeStateDir; Replacement = '<DEMO_STATE>/runtime' },
        @{ Value = $Paths.LogDir; Replacement = '<DEMO_STATE>/logs' },
        @{ Value = $Paths.GatewayTokenPath; Replacement = '<DEMO_STATE>/runtime/gateway-token.txt' },
        @{ Value = $Paths.GatewayProcessPath; Replacement = '<DEMO_STATE>/runtime/gateway-process.json' },
        @{ Value = $Paths.OpenClawEntry; Replacement = '<OPENCLAW_ENTRY>' },
        @{ Value = $Paths.Python; Replacement = '<PYTHON>' },
        @{ Value = $Paths.DevSubject; Replacement = '<PROJECT_ROOT>/integrations/openclaw_mcp/dev-subject.example.json' },
        @{ Value = $env:USERPROFILE; Replacement = '<USER_PROFILE>' },
        @{ Value = $env:TEMP; Replacement = '<TEMP>' }
    )
    foreach ($replacement in $pathReplacements) {
        if (-not [string]::IsNullOrWhiteSpace($replacement.Value)) {
            $result = $result.Replace($replacement.Value, $replacement.Replacement)
            $result = $result.Replace($replacement.Value.Replace('\', '/'), $replacement.Replacement)
            # JSON serialisation doubles backslashes inside string values.
            $result = $result.Replace($replacement.Value.Replace('\', '\\'), $replacement.Replacement)
            $result = $result.Replace($replacement.Value.Replace('\', '\\/'), $replacement.Replacement)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($GatewayToken)) {
        $result = $result.Replace($GatewayToken, '<REDACTED_GATEWAY_TOKEN>')
    }
    # Keep common bearer/API token forms out of portable evidence as a second
    # line of defence if a child process unexpectedly echoes a credential.
    $result = [regex]::Replace($result, '(?i)(Bearer\s+)[A-Za-z0-9._~+\-/=]{16,}', '$1<REDACTED_TOKEN>')
    $result = [regex]::Replace($result, '(?i)\bsk-[A-Za-z0-9_-]{16,}\b', '<REDACTED_API_KEY>')
    return $result
}

function Write-OpenClawDemoPortableJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object]$Value,
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [string]$GatewayToken
    )

    $json = $Value | ConvertTo-Json -Depth 64
    $portable = ConvertTo-OpenClawDemoPortableText -Text $json -Paths $Paths -GatewayToken $GatewayToken
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, "$portable`n", $utf8WithoutBom)
}

function Protect-OpenClawDemoPortableFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [pscustomobject]$Paths,
        [string]$GatewayToken
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    $raw = [System.IO.File]::ReadAllText($Path)
    $portable = ConvertTo-OpenClawDemoPortableText -Text $raw -Paths $Paths -GatewayToken $GatewayToken
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $portable, $utf8WithoutBom)
}

function Test-OpenClawDemoSecretAbsent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$PathsToCheck,
        [string]$GatewayToken
    )

    if ([string]::IsNullOrWhiteSpace($GatewayToken)) {
        return $true
    }
    foreach ($path in $PathsToCheck) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            if ([System.IO.File]::ReadAllText($path).IndexOf($GatewayToken, [System.StringComparison]::Ordinal) -ge 0) {
                return $false
            }
        }
    }
    return $true
}
