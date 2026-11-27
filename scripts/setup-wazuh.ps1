# ==============================================================================
# Q-Shields Wazuh Single-Node Fresh Install & Startup Helper (Windows PowerShell)
# ==============================================================================

$ErrorActionPreference = "Stop"

function Invoke-DockerQuiet {
    param([string[]]$DockerArgs)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & docker @DockerArgs 2>$null
        return @{
            ExitCode = $LASTEXITCODE
            Output   = ($output -join "`n")
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot ".env"
$EnvExample = Join-Path $RepoRoot ".env.example"
$ComposeFile = Join-Path $RepoRoot "docker-compose.wazuh.yml"
$CertsDir = Join-Path $RepoRoot "wazuh\certs"

Write-Host "=== Q-Shields Wazuh Stack Setup (Windows Docker Desktop) ===" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker CLI tidak ditemukan. Pastikan Docker Desktop sudah terpasang dan berjalan."
    exit 1
}

$composeVer = Invoke-DockerQuiet @("compose", "version")
if ($composeVer.ExitCode -ne 0) {
    Write-Error "Docker Compose v2 tidak tersedia ('docker compose')."
    exit 1
}

if (-not (Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null
}

# 1. Salin .env.example ke .env jika belum ada
if (-not (Test-Path $EnvFile)) {
    if (-not (Test-Path $EnvExample)) {
        Write-Error "File .env.example tidak ditemukan di $EnvExample"
        exit 1
    }
    Copy-Item $EnvExample $EnvFile
    Write-Host "[INFO] File .env dibuat dari .env.example." -ForegroundColor Yellow
} else {
    Write-Host "[INFO] Menggunakan file .env yang sudah ada." -ForegroundColor Green
}

# 2. Validasi variabel wajib Wazuh di .env
$EnvMap = @{}
foreach ($rawLine in Get-Content $EnvFile) {
    $line = $rawLine.Trim()
    if (-not $line -or $line.StartsWith("#")) { continue }
    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { continue }
    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
        $val = $val.Substring(1, $val.Length - 2)
    }
    $EnvMap[$key] = $val
}

$RequiredVars = @("INDEXER_USERNAME", "INDEXER_PASSWORD", "API_USERNAME", "API_PASSWORD")
foreach ($varName in $RequiredVars) {
    if (-not $EnvMap.ContainsKey($varName) -or [string]::IsNullOrWhiteSpace($EnvMap[$varName])) {
        Write-Error "Variabel wajib '$varName' kosong atau belum didefinisikan di $EnvFile."
        exit 1
    }
    if ($EnvMap[$varName].StartsWith("CHANGE_ME")) {
        Write-Error "Variabel '$varName' di .env masih menggunakan placeholder ($($EnvMap[$varName])). Untuk fresh install Wazuh 4.9.2, gunakan default dari .env.example (mis. INDEXER_PASSWORD=SecretPassword)."
        exit 1
    }
}
Write-Host "[OK] Seluruh variabel wajib Wazuh pada .env valid." -ForegroundColor Green

# 3. Bersihkan network wazuh_net lama/yatim agar tidak memicu warning project mismatch
$netInspect = Invoke-DockerQuiet @("network", "inspect", "wazuh_net")
if ($netInspect.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($netInspect.Output)) {
    $netObj = ($netInspect.Output | ConvertFrom-Json)[0]
    $netProject = if ($netObj.Labels) { $netObj.Labels.'com.docker.compose.project' } else { $null }
    if ($netProject -ne "qshields-wazuh") {
        $attachedCount = if ($netObj.Containers) { @($netObj.Containers.PSObject.Properties).Count } else { 0 }
        if ($attachedCount -eq 0) {
            Write-Host "[INFO] Menghapus network wazuh_net lama (project='$netProject') agar dibuat ulang bersih untuk 'qshields-wazuh'..." -ForegroundColor Yellow
            $rmNet = Invoke-DockerQuiet @("network", "rm", "wazuh_net")
            if ($rmNet.ExitCode -ne 0) {
                Write-Host "[WARN] Tidak dapat menghapus network wazuh_net lama; Compose akan mencoba memakai network yang ada." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN] Network wazuh_net sudah ada (project='$netProject') dan sedang dipakai $attachedCount container." -ForegroundColor Yellow
            Write-Host "       Jika ingin bersih penuh, jalankan 'docker compose -f docker-compose.app.yml down' terlebih dahulu." -ForegroundColor Yellow
        }
    }
}

# 4. Atur vm.max_map_count=262144 di backend WSL2 Docker Desktop
Write-Host "[INFO] Mengatur vm.max_map_count=262144 di Docker Desktop (WSL2)..." -ForegroundColor Cyan
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
$wslExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($wslExit -ne 0) {
    Write-Error "Gagal mengatur vm.max_map_count melalui 'wsl -d docker-desktop'. Pastikan Docker Desktop berbasis WSL2 sudah berjalan."
    exit 1
}

# 5. Jalankan stack Wazuh (sertifikat TLS dibuat otomatis oleh service wazuh.certs bila belum ada)
Write-Host "[INFO] Menjalankan Docker Compose stack Wazuh (name: qshields-wazuh)..." -ForegroundColor Cyan
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose --env-file "$EnvFile" -f "$ComposeFile" up -d
$upExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($upExit -ne 0) {
    Write-Host "[ERROR] Stack Wazuh gagal start. Menampilkan log terakhir qshields-wazuh-certs & qshields-wazuh-indexer:" -ForegroundColor Red
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    Write-Host "--- qshields-wazuh-certs ---" -ForegroundColor DarkYellow
    docker logs --tail 40 qshields-wazuh-certs 2>&1 | ForEach-Object { "$_" }
    Write-Host "--- qshields-wazuh-indexer ---" -ForegroundColor DarkYellow
    docker logs --tail 60 qshields-wazuh-indexer 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = $prevEap
    exit 1
}

# 6. Tunggu hingga seluruh service Wazuh berstatus healthy
$Services = @(
    "qshields-wazuh-indexer",
    "qshields-wazuh-manager",
    "qshields-wazuh-dashboard"
)
$TimeoutSeconds = 420
$IntervalSeconds = 10
$Elapsed = 0

Write-Host "[INFO] Menunggu seluruh container Wazuh berstatus 'healthy' (maks $TimeoutSeconds detik)..." -ForegroundColor Cyan
while ($true) {
    $certsRes = Invoke-DockerQuiet @("inspect", "qshields-wazuh-certs")
    if ($certsRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($certsRes.Output)) {
        $certsObj = ($certsRes.Output | ConvertFrom-Json)[0]
        if ($certsObj.State.Status -eq "exited" -and $certsObj.State.ExitCode -ne 0) {
            Write-Host "[ERROR] Container init qshields-wazuh-certs gagal (exit $($certsObj.State.ExitCode)). Log:" -ForegroundColor Red
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            docker logs --tail 40 qshields-wazuh-certs 2>&1 | ForEach-Object { "$_" }
            $ErrorActionPreference = $prevEap
            exit 1
        }
    }

    $allHealthy = $true
    $parts = @()
    foreach ($svc in $Services) {
        $svcRes = Invoke-DockerQuiet @("inspect", $svc)
        $health = "not-found"
        if ($svcRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($svcRes.Output)) {
            $svcObj = ($svcRes.Output | ConvertFrom-Json)[0]
            $health = if ($svcObj.State.Health) { $svcObj.State.Health.Status } else { $svcObj.State.Status }
        }
        $parts += "$svc=$health"
        if ($health -ne "healthy") {
            $allHealthy = $false
        }
    }

    Write-Host ("[WAIT {0}s] {1}" -f $Elapsed, ($parts -join " "))

    if ($allHealthy) {
        Write-Host ""
        Write-Host "[SUCCESS] Seluruh container Wazuh berstatus healthy!" -ForegroundColor Green
        Write-Host "  - Wazuh Dashboard : https://localhost:5601"
        Write-Host "  - Wazuh Manager API (local debug): https://127.0.0.1:55000"
        Write-Host "  - Langkah berikutnya untuk aplikasi Q-Shields:"
        Write-Host "      docker compose --env-file .env -f docker-compose.app.yml up -d --build"
        exit 0
    }

    if ($Elapsed -ge $TimeoutSeconds) {
        Write-Host "[ERROR] Timeout menunggu container Wazuh menjadi healthy setelah $TimeoutSeconds detik." -ForegroundColor Red
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        docker compose --env-file "$EnvFile" -f "$ComposeFile" ps 2>&1 | ForEach-Object { "$_" }
        docker logs --tail 60 qshields-wazuh-indexer 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $prevEap
        exit 1
    }

    Start-Sleep -Seconds $IntervalSeconds
    $Elapsed += $IntervalSeconds
}