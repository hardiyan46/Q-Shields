# Q-Shields

**Q-Shields** adalah platform manajemen kerentanan (*CVE patching*), kepatuhan *hardening* (CIS Benchmark / Wazuh SCA), dan remediasi berbantuan AI lokal (**LangGraph + Ollama**) lintas OS (**Linux, Windows, macOS**) dengan persetujuan berjenjang (*Human-in-the-Loop*), *pre-change backup*, dan kemampuan *rollback*.

## Arsitektur Container Terpisah

Q-Shields memisahkan Compose project agar kedua stack berjalan terisolasi tanpa konflik atau peringatan *orphan container*:

| Compose File | Project Name (`name:`) | Layanan | Jaringan |
| :--- | :--- | :--- | :--- |
| `docker-compose.wazuh.yml` | `qshields-wazuh` | `wazuh.certs` (init), `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` | `wazuh_net` |
| `docker-compose.app.yml` | `qshields-app` | `postgres`, `backend`, `ollama`, `frontend` | `qshields_net` (khusus `backend` juga terhubung ke `wazuh_net`) |

---

## Fresh Install Stack Wazuh (Satu Perintah)

Skrip setup otomatis akan:
1. Menyalin `.env.example` menjadi `.env` jika `.env` belum tersedia, serta memvalidasi variabel wajib Wazuh (`INDEXER_USERNAME`, `INDEXER_PASSWORD`, `API_USERNAME`, `API_PASSWORD`).
2. Mengatur parameter kernel `vm.max_map_count=262144` untuk OpenSearch / Wazuh Indexer.
3. Menjalankan `docker compose --env-file .env -f docker-compose.wazuh.yml up -d` (sertifikat TLS internal dibuat otomatis sekali oleh init container `wazuh.certs` ke `./wazuh/certs/` jika `root-ca.pem` belum ada).
4. Menunggu hingga `qshields-wazuh-indexer`, `qshields-wazuh-manager`, dan `qshields-wazuh-dashboard` berstatus `healthy`.

### Windows (Docker Desktop + WSL2)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-wazuh.ps1
```

### Linux

```bash
chmod +x ./scripts/setup-wazuh.sh
./scripts/setup-wazuh.sh
```

> **Catatan Production:** Image bawaan `wazuh/wazuh-indexer:4.9.2` menggunakan password default `SecretPassword` untuk user `admin`. Sebelum dipakai di lingkungan produksi, ganti password melalui `wazuh-passwords-tool.sh` / `securityadmin.sh` serta perbarui `.env`.

---

## Menjalankan Aplikasi Q-Shields

Setelah stack Wazuh berjalan (atau setelah membuat network manual `docker network create wazuh_net` jika ingin menjalankan mode mock `WAZUH_USE_MOCK=true` tanpa Wazuh):

```bash
docker compose --env-file .env -f docker-compose.app.yml up -d --build
```

- **Q-Shields Dashboard (Next.js):** http://localhost:3000
- **Q-Shields Backend API (FastAPI):** http://localhost:8000/docs
- **Wazuh Dashboard:** https://localhost:5601

## Pengujian Fresh Install dari Kondisi Bersih

Untuk memastikan proses *fresh install* bekerja bersih dari awal:

```bash
docker compose -f docker-compose.wazuh.yml down -v
# Opsional: hapus ./wazuh/certs untuk menguji generate sertifikat TLS otomatis
# Linux: rm -rf ./wazuh/certs/* && ./scripts/setup-wazuh.sh
# Windows: Remove-Item .\wazuh\certs\* -Force; .\scripts\setup-wazuh.ps1
```
