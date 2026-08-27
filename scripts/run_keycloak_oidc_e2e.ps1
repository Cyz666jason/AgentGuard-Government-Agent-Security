$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$downloads = Join-Path $projectRoot "third_party\downloads"
$runtime = Join-Path $projectRoot "third_party\runtime"
$jreZip = Join-Path $downloads "OpenJDK21U-jre_x64_windows_hotspot.zip"
$keycloakZip = Join-Path $downloads "keycloak-26.7.1.zip"
$jreRoot = Join-Path $runtime "jre21"
$keycloakRuntime = Join-Path $runtime "keycloak"

if (-not (Test-Path -LiteralPath $jreZip)) {
    throw "Missing portable Java 21: $jreZip"
}
if (-not (Test-Path -LiteralPath $keycloakZip)) {
    throw "Missing Keycloak 26.7.1: $keycloakZip"
}
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
if (-not (Test-Path -LiteralPath $jreRoot)) {
    New-Item -ItemType Directory -Force -Path $jreRoot | Out-Null
    Expand-Archive -LiteralPath $jreZip -DestinationPath $jreRoot -Force
}
if (-not (Test-Path -LiteralPath $keycloakRuntime)) {
    New-Item -ItemType Directory -Force -Path $keycloakRuntime | Out-Null
    Expand-Archive -LiteralPath $keycloakZip -DestinationPath $keycloakRuntime -Force
}
$javaExe = Get-ChildItem -LiteralPath $jreRoot -Filter java.exe -Recurse | Select-Object -First 1
$kcBat = Get-ChildItem -LiteralPath $keycloakRuntime -Filter kc.bat -Recurse | Select-Object -First 1
if (-not $javaExe -or -not $kcBat) {
    throw "Portable Java or Keycloak extraction is incomplete"
}
$javaHome = Split-Path -Parent (Split-Path -Parent $javaExe.FullName)
$keycloakHome = Split-Path -Parent (Split-Path -Parent $kcBat.FullName)
$h2Dir = Join-Path $keycloakHome "data\h2"
$resolvedHome = [System.IO.Path]::GetFullPath($keycloakHome).TrimEnd('\') + '\'
$resolvedH2 = [System.IO.Path]::GetFullPath($h2Dir)
if (-not $resolvedH2.StartsWith($resolvedHome, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean an H2 path outside the Keycloak test runtime"
}
if (Test-Path -LiteralPath $h2Dir) {
    Remove-Item -LiteralPath $h2Dir -Recurse -Force
}
$importDir = Join-Path $keycloakHome "data\import"
New-Item -ItemType Directory -Force -Path $importDir | Out-Null
$officePassword = "Of-$([Guid]::NewGuid().ToString('N'))!9a"
$financePassword = "Fi-$([Guid]::NewGuid().ToString('N'))!9a"
$approverPassword = "Ap-$([Guid]::NewGuid().ToString('N'))!9a"
$realmTemplate = Get-Content -LiteralPath (Join-Path $projectRoot "identity\keycloak\agentguard-realm.json") -Raw -Encoding UTF8
$realmRuntime = $realmTemplate.Replace('__OFFICE_TEST_PASSWORD__', $officePassword).Replace('__FINANCE_TEST_PASSWORD__', $financePassword).Replace('__APPROVER_TEST_PASSWORD__', $approverPassword)
$runtimeRealmPath = Join-Path $importDir "agentguard-realm.json"
$realmRuntime | Set-Content -LiteralPath $runtimeRealmPath -Encoding UTF8

$env:JAVA_HOME = $javaHome
$env:KC_BOOTSTRAP_ADMIN_USERNAME = "agentguard-admin"
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = "Ad-$([Guid]::NewGuid().ToString('N'))!9a"
$env:AGENTGUARD_KEYCLOAK_OFFICE_PASSWORD = $officePassword
$env:AGENTGUARD_KEYCLOAK_FINANCE_PASSWORD = $financePassword
$env:AGENTGUARD_KEYCLOAK_APPROVER_PASSWORD = $approverPassword
$logDir = Join-Path $projectRoot "reports\e2e\identity"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdout = Join-Path $logDir "keycloak_stdout.log"
$stderr = Join-Path $logDir "keycloak_stderr.log"
$process = Start-Process -FilePath $kcBat.FullName -ArgumentList @(
    "start-dev",
    "--http-port=18080",
    "--hostname=127.0.0.1",
    "--import-realm"
) -WorkingDirectory (Split-Path -Parent $kcBat.FullName) -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        try {
            $discovery = Invoke-RestMethod -Uri "http://127.0.0.1:18080/realms/agentguard/.well-known/openid-configuration" -TimeoutSec 2
            if ($discovery.issuer -eq "http://127.0.0.1:18080/realms/agentguard") {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $ready) {
        throw "Keycloak was not ready within 120 seconds; inspect reports/e2e/identity/keycloak_stderr.log"
    }
    & (Join-Path $projectRoot ".venv\Scripts\python.exe") (Join-Path $projectRoot "identity\run_keycloak_e2e.py")
    if ($LASTEXITCODE -ne 0) {
        throw "Keycloak OIDC end-to-end test failed"
    }
} finally {
    $ownedJava = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq "java.exe" -and $_.CommandLine -like "*$keycloakHome*"
    }
    foreach ($item in $ownedJava) {
        Stop-Process -Id $item.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTGUARD_KEYCLOAK_OFFICE_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTGUARD_KEYCLOAK_FINANCE_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTGUARD_KEYCLOAK_APPROVER_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:KC_BOOTSTRAP_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $runtimeRealmPath) {
        Remove-Item -LiteralPath $runtimeRealmPath -Force
    }
}
