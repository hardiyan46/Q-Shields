#!/usr/bin/env bash
set -euo pipefail

# Helper untuk membuat sertifikat TLS internal Wazuh ke ./wazuh/certs/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

mkdir -p "${REPO_ROOT}/wazuh/certs"
docker compose -f "${REPO_ROOT}/docker-compose.wazuh-certs.yml" run --rm generator

# Pastikan root-ca-manager.pem tersedia jika generator hanya menulis root-ca.pem
if [ ! -f "${REPO_ROOT}/wazuh/certs/root-ca-manager.pem" ] && [ -f "${REPO_ROOT}/wazuh/certs/root-ca.pem" ]; then
  cp "${REPO_ROOT}/wazuh/certs/root-ca.pem" "${REPO_ROOT}/wazuh/certs/root-ca-manager.pem"
fi

chown 0:1000 "${REPO_ROOT}/wazuh/certs/"*.pem "${REPO_ROOT}/wazuh/certs/"*.key 2>/dev/null || true
chmod 0640 "${REPO_ROOT}/wazuh/certs/"*.pem "${REPO_ROOT}/wazuh/certs/"*.key 2>/dev/null || true
echo "Sertifikat TLS Wazuh berhasil dibuat di ${REPO_ROOT}/wazuh/certs/"