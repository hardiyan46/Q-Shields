# ==============================================================================
# Q-Shields Wazuh Single-Node Fresh Install & Startup Helper (Windows PowerShell)
# ==============================================================================

$ErrorActionPreference = "Stop"

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

docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) {
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
$netInspect = docker network inspect wazuh_net 2>$null
if ($LASTEXITCODE -eq 0 -and $netInspect) {
    $netProject = docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' wazuh_net 2>$null
    if ($netProject -ne "qshields-wazuh") {
        $attachedCount = docker network inspect -f '{{len .Containers}}' wazuh_net 2>$null
        if ($attachedCount -eq "0") {
            Write-Host "[INFO] Menghapus network wazuh_net lama (project='$netProject') agar dibuat ulang bersih untuk 'qshields-wazuh'..." -ForegroundColor Yellow
            docker network rm wazuh_net | Out-Null
        } else {
            Write-Host "[WARN] Network wazuh_net sudah ada (project='$netProject') dan sedang dipakai $attachedCount container." -ForegroundColor Yellow
            Write-Host "       Jika ingin bersih penuh, jalankan 'docker compose -f docker-compose.app.yml down' terlebih dahulu." -ForegroundColor Yellow
        }
    }
}

# 4. Atur vm.max_map_count=262144 di backend WSL2 Docker Desktop
Write-Host "[INFO] Mengatur vm.max_map_count=262144 di Docker Desktop (WSL2)..." -ForegroundColor Cyan
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
if ($LASTEXITCODE -ne 0) {
    Write-Error "Gagal mengatur vm.max_map_count melalui 'wsl -d docker-desktop'. Pastikan Docker Desktop berbasis WSL2 sudah berjalan."
    exit 1
}

# 5. Jalankan stack Wazuh (sertifikat TLS dibuat otomatis oleh service wazuh.certs bila belum ada)
Write-Host "[INFO] Menjalankan Docker Compose stack Wazuh (name: qshields-wazuh)..." -ForegroundColor Cyan
docker compose --env-file "$EnvFile" -f "$ComposeFile" up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Stack Wazuh gagal start. Menampilkan 60 baris log terakhir qshields-wazuh-indexer:" -ForegroundColor Red
    docker logs --tail 60 qshields-wazuh-indexer 2>$null
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
    $certsStatus = docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' qshields-wazuh-certs 2>$null
    if ($certsStatus -and $certsStatus.StartsWith("exited:") -and $certsStatus -ne "exited:0") {
        Write-Host "[ERROR] Container init qshields-wazuh-certs gagal ($certsStatus). Log:" -ForegroundColor Red
        docker logs --tail 40 qshields-wazuh-certs
        exit 1
    }

    $allHealthy = $true
    $parts = @()
    foreach ($svc in $Services) {
        $health = docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $svc 2>$null
        if (-not $health) { $health = "not-found" }
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
        docker compose --env-file "$EnvFile" -f "$ComposeFile" ps
        docker logs --tail 60 qshields-wazuh-indexer 2>$null
        exit 1
    }

    Start-Sleep -Seconds $IntervalSeconds
    $Elapsed += $IntervalSeconds
}