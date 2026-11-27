#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Q-Shields Wazuh Single-Node Fresh Install & Startup Helper (Linux)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.wazuh.yml"
CERTS_DIR="${REPO_ROOT}/wazuh/certs"

echo "=== Q-Shields Wazuh Stack Setup (Linux) ==="

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] Docker CLI tidak ditemukan. Pastikan Docker Engine sudah terpasang." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[ERROR] Docker Compose v2 tidak tersedia ('docker compose')." >&2
  exit 1
fi

mkdir -p "${CERTS_DIR}"

# 1. Salin .env.example ke .env jika belum ada
if [ ! -f "${ENV_FILE}" ]; then
  if [ ! -f "${ENV_EXAMPLE}" ]; then
    echo "[ERROR] File ${ENV_EXAMPLE} tidak ditemukan." >&2
    exit 1
  fi
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"
  echo "[INFO] File .env dibuat dari .env.example."
else
  echo "[INFO] Menggunakan file .env yang sudah ada."
fi

# Helper membaca nilai variabel dari .env tanpa mengeksekusi isi shell lain
read_env_var() {
  local key="$1"
  local line
  line="$(grep -E "^[[:space:]]*${key}=" "${ENV_FILE}" | tail -n 1 || true)"
  line="${line#*=}"
  line="${line%$'\r'}"
  line="${line#\"}"
  line="${line%\"}"
  line="${line#\'}"
  line="${line%\'}"
  printf '%s' "${line}"
}

# 2. Validasi variabel wajib Wazuh di .env
REQUIRED_VARS=("INDEXER_USERNAME" "INDEXER_PASSWORD" "API_USERNAME" "API_PASSWORD")
for var_name in "${REQUIRED_VARS[@]}"; do
  var_val="$(read_env_var "${var_name}")"
  if [ -z "${var_val}" ]; then
    echo "[ERROR] Variabel wajib '${var_name}' kosong atau belum didefinisikan di ${ENV_FILE}." >&2
    exit 1
  fi
  if [[ "${var_val}" == CHANGE_ME* ]]; then
    echo "[ERROR] Variabel '${var_name}' di .env masih menggunakan placeholder (${var_val})." >&2
    echo "        Untuk fresh install image Wazuh 4.9.2, gunakan nilai default .env.example (mis. INDEXER_PASSWORD=SecretPassword)." >&2
    exit 1
  fi
done
echo "[OK] Seluruh variabel wajib Wazuh pada .env valid."

# 3. Bersihkan network wazuh_net yatim (misal dari project lama / docker network create manual) jika sedang tidak dipakai
if docker network inspect wazuh_net >/dev/null 2>&1; then
  net_project="$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' wazuh_net 2>/dev/null || true)"
  if [ "${net_project}" != "qshields-wazuh" ]; then
    attached_count="$(docker network inspect -f '{{len .Containers}}' wazuh_net 2>/dev/null || echo 0)"
    if [ "${attached_count}" = "0" ]; then
      echo "[INFO] Menghapus network wazuh_net lama (project='${net_project:-manual}') agar dibuat ulang bersih untuk 'qshields-wazuh'..."
      docker network rm wazuh_net >/dev/null
    else
      echo "[WARN] Network wazuh_net sudah ada (project='${net_project:-manual}') dan sedang dipakai ${attached_count} container."
      echo "       Jika terjadi konflik, hentikan stack lain dulu (mis. docker compose -f docker-compose.app.yml down) lalu ulangi."
    fi
  fi
fi

# 4. Atur vm.max_map_count=262144 untuk OpenSearch / Wazuh Indexer
CURRENT_MAP_COUNT="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if [ "${CURRENT_MAP_COUNT}" -lt 262144 ]; then
  echo "[INFO] Mengatur vm.max_map_count=262144 (saat ini: ${CURRENT_MAP_COUNT})..."
  if [ "${EUID}" -eq 0 ]; then
    sysctl -w vm.max_map_count=262144
  else
    sudo sysctl -w vm.max_map_count=262144
  fi
else
  echo "[OK] vm.max_map_count sudah memenuhi syarat (${CURRENT_MAP_COUNT})."
fi

# 5. Jalankan stack Wazuh (sertifikat TLS dibuat otomatis oleh service wazuh.certs bila belum ada)
echo "[INFO] Menjalankan Docker Compose stack Wazuh (name: qshields-wazuh)..."
if ! docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d; then
  echo "[ERROR] Stack Wazuh gagal start. Menampilkan log terakhir qshields-wazuh-indexer:" >&2
  docker logs --tail 60 qshields-wazuh-indexer >&2 || true
  exit 1
fi

# 6. Tunggu hingga seluruh service Wazuh berstatus healthy
SERVICES=(
  "qshields-wazuh-indexer"
  "qshields-wazuh-manager"
  "qshields-wazuh-dashboard"
)
TIMEOUT_SECONDS=420
INTERVAL_SECONDS=10
ELAPSED=0

echo "[INFO] Menunggu seluruh container Wazuh berstatus 'healthy' (maks ${TIMEOUT_SECONDS} detik)..."
while true; do
  certs_status="$(docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' qshields-wazuh-certs 2>/dev/null || echo 'missing:0')"
  if [[ "${certs_status}" == exited:* ]] && [ "${certs_status}" != "exited:0" ]; then
    echo "[ERROR] Container init qshields-wazuh-certs gagal (${certs_status}). Log:" >&2
    docker logs --tail 40 qshields-wazuh-certs >&2 || true
    exit 1
  fi

  all_healthy=true
  status_summary=""
  for svc in "${SERVICES[@]}"; do
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${svc}" 2>/dev/null || echo 'not-found')"
    status_summary="${status_summary} ${svc}=${health}"
    if [ "${health}" != "healthy" ]; then
      all_healthy=false
    fi
  done

  echo "[WAIT ${ELAPSED}s]${status_summary}"

  if [ "${all_healthy}" = true ]; then
    echo ""
    echo "[SUCCESS] Seluruh container Wazuh berstatus healthy!"
    echo "  - Wazuh Dashboard : https://localhost:5601"
    echo "  - Wazuh Manager API (local debug): https://127.0.0.1:55000"
    echo "  - Langkah berikutnya untuk aplikasi Q-Shields:"
    echo "      docker compose --env-file .env -f docker-compose.app.yml up -d --build"
    exit 0
  fi

  if [ "${ELAPSED}" -ge "${TIMEOUT_SECONDS}" ]; then
    echo "[ERROR] Timeout menunggu container Wazuh menjadi healthy setelah ${TIMEOUT_SECONDS} detik." >&2
    docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" ps >&2 || true
    docker logs --tail 60 qshields-wazuh-indexer >&2 || true
    exit 1
  fi

  sleep "${INTERVAL_SECONDS}"
  ELAPSED=$((ELAPSED + INTERVAL_SECONDS))
done