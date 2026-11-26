# Product Requirements Document (PRD) — Q-Shields Phase 1 (MVP)

**Proyek:** Q-Shields (`https://github.com/hardiyan46/Q-Shields`)  
**Fase:** Phase 1 — Minimum Viable Product (MVP)  
**Metodologi Pengembangan:** Vibe Coding (Contract-First & Mock-First)  
**Lingkungan Target:** Internal On-Premise / Private Corporate Network (Berbasis Docker)  
**Status Dokumen:** Final Draft (Ready for Vibe Coding Execution)  

---

## Daftar Isi

1. [Ringkasan Eksekutif & Masalah yang Diselesaikan](#1-ringkasan-eksekutif--masalah-yang-diselesaikan)
2. [User Personas & RBAC Matrix](#2-user-personas--rbac-matrix)
3. [Scope Phase 1 (In-Scope vs Out-of-Scope)](#3-scope-phase-1-in-scope-vs-out-of-scope)
4. [End-to-End User Flows](#4-end-to-end-user-flows)
5. [Functional & Non-Functional Requirements](#5-functional--non-functional-requirements)
6. [Desain Skema Database PostgreSQL](#6-desain-skema-database-postgresql)
7. [Rencana Sprint Vibe Coding Phase 1](#7-rencana-sprint-vibe-coding-phase-1)
8. [Lampiran: Referensi Arsitektur Docker & Kontrak Data](#8-lampiran-referensi-arsitektur-docker--kontrak-data)

---

## 1. Ringkasan Eksekutif & Masalah yang Diselesaikan

### 1.1 Latar Belakang & Masalah Utama
Tim Security Operations dan IT Infrastructure di lingkungan internal perusahaan sering menghadapi kesenjangan operasional antara **deteksi kerentanan/kepatuhan** dengan **eksekusi perbaikan (remediasi)** di ratusan hingga ribuan endpoint (Linux & Windows):

1. **Banjir Temuan Tanpa Jalur Remediasi Cepat:** Agent keamanan seperti Wazuh mampu mendeteksi ribuan CVE dan penyimpangan *CIS Benchmark / Security Configuration Assessment (SCA)*, namun penyusunan skrip perbaikan masih dilakukan secara manual oleh engineer.
2. **Risiko Kerusakan Sistem Saat Remediasi:** Eksekusi skrip hardening atau patching secara langsung tanpa mekanisme cadangan kondisi awal (*pre-change backup*) dan prosedur pemulihan (*rollback*) berisiko memutus layanan produksi atau merusak konfigurasi sistem.
3. **Kurangnya Kontrol *Human-in-the-Loop* & Auditabilitas:** Skrip yang dijalankan secara ad-hoc via SSH/WinRM sulit dilacak siapa yang membuat, siapa yang menyetujui, apa perubahan persisnya, dan bagaimana membatalkannya saat terjadi insiden.
4. **Kebijakan Privasi Data Internal:** Informasi topologi server, daftar CVE internal, hostname, dan konfigurasi sensitif dilarang dikirim ke API LLM publik (cloud eksternal).

### 1.2 Solusi: Q-Shields Phase 1 (MVP)
**Q-Shields** adalah platform keamanan endpoint internal berbasis web untuk **Vulnerability Assessment (CVE)**, **Hardening / Compliance (CIS Benchmark / SCA)**, dan **AI-Assisted Remediation dengan Human-in-the-Loop Approval**.

Platform ini menggabungkan deteksi **Wazuh** (Agent + Manager), penyimpanan terstruktur di **PostgreSQL**, orkestrasi AI lokal menggunakan **Python FastAPI + LangGraph + Ollama** (100% di jaringan internal), serta antarmuka modern **Next.js (App Router) + TypeScript + Tailwind CSS + shadcn/ui**.

Setiap skrip remediasi yang dihasilkan AI **wajib** menyertakan prosedur **Pre-Change Backup** (mencadangkan file konfigurasi/registry/daftar paket beserta checksum ke direktori backup unik per job) dan **auto-revert** jika validasi gagal, serta menghasilkan **`rollback_script` terpisah**. Tanpa jaminan `has_pre_backup = true`, tombol **Approve** di UI akan terkunci secara permanen (*hard-locked*).

### 1.3 Arsitektur Stack & Prinsip Vibe Coding
Karena Phase 1 dibangun secara bertahap melalui **vibe coding** (bukan coding fullstack manual dari nol), PRD ini menetapkan empat pilar disiplin agar pengembangan tidak macet di tengah jalan:

| Prinsip | Implementasi Teknis di Q-Shields |
| :--- | :--- |
| **1. Pemisahan Stack Docker** | Stack **Wazuh** (`docker-compose.wazuh.yml`) dan stack aplikasi **Q-Shields** (`docker-compose.qshields.yml`: PostgreSQL, Ollama, FastAPI Backend, Next.js Frontend) dijalankan terpisah dan berkomunikasi melalui Docker external network (`qshields-net`) dan REST API/TLS. Jika aplikasi Q-Shields di-restart saat vibe coding, Wazuh Manager tidak ikut terganggu. |
| **2. Contract-First Development** | Seluruh pertukaran data antar komponen (API FastAPI ↔ Next.js, LangGraph ↔ Ollama Structured Output, Wazuh Adapter ↔ Database) harus mengikuti skema Pydantic/JSON dan TypeScript interface yang didefinisikan sebelum generasi kode UI/fitur. |
| **3. Mock-First Integration** | Fitur sinkronisasi Wazuh dan generasi skrip AI wajib dibangun dengan *adapter pattern* (`WAZUH_MODE=mock\|live`, `LLM_MODE=mock\|ollama`) sehingga UI dan alur approval dapat diuji penuh menggunakan mock data deterministik sebelum terhubung ke container Wazuh dan Ollama live. |
| **4. Schema Readiness (Phase 2 & 3)** | Skema database PostgreSQL sejak Phase 1 sudah menyediakan kolom dan tabel cadangan untuk fitur Phase 2 (Static Analyzer & Canary Deployment) dan Phase 3 (Sysmon/eBPF Telemetry, Sigma Rules, EDR Actions) guna mencegah *breaking schema migration*. |

```mermaid
flowchart LR
    subgraph Wazuh_Stack ["Docker Stack 1: Wazuh Infrastructure"]
        WA["Wazuh Agent (Linux / Windows)"] -->|"Events / SCA / Syscollector"| WM["Wazuh Manager & API"]
    end

    subgraph QShields_Stack ["Docker Stack 2: Q-Shields Application"]
        FE["Next.js App Router + shadcn/ui"] <-->|"REST API + JWT"| BE["FastAPI + LangGraph"]
        BE <-->|"Local Inference (No Internet)"| OLL["Ollama (Local LLM)"]
        BE <-->|"SQL (Relational + Audit Log)"| PG[("PostgreSQL")]
        BE <-->|"LDAP / LDAPS (ldap3)"| DC["Corporate Domain Controller / AD"]
    end

    BE <-->|"REST API / Active Response via qshields-net"| WM
```

---

## 2. User Personas & RBAC Matrix

### 2.1 User Personas

| Persona | Role Sistem | Deskripsi & Tanggung Jawab Utama |
| :--- | :--- | :--- |
| **Security / IT Operator** | `OPERATOR` | Engineer harian yang memantau status endpoint, memicu sinkronisasi temuan CVE/SCA dari Wazuh, meminta AI (LangGraph + Ollama) membuat draf skrip remediasi & rollback, dan mengeksekusi job yang sudah disetujui. **Tidak berhak** menyetujui (*approve*) skrip miliknya sendiri maupun orang lain. |
| **Security Lead / Change Approver** | `APPROVER` | Penanggung jawab *Change Advisory / Security Review* yang memeriksa kesesuaian skrip remediasi, validasi keberadaan *pre-change backup*, meninjau `rollback_script`, serta memberikan keputusan **Approve** atau **Reject** (disertai catatan alasan). |
| **Platform Administrator** | `ADMIN` | Pengelola infrastruktur Q-Shields: mengelola akun user lokal, mengonfigurasi integrasi Domain Controller / LDAP, mengatur pemetaan grup LDAP ke role sistem (`ldap_group_mappings`), meninjau seluruh audit log, serta memiliki akses penuh operasional. |

### 2.2 RBAC Permission Matrix

| Kemampuan / Aksi Sistem | `OPERATOR` | `APPROVER` | `ADMIN` | Catatan Keamanan |
| :--- | :---: | :---: | :---: | :--- |
| Login (Local Account atau LDAP/AD) | ✅ | ✅ | ✅ | Audit log tercatat untuk setiap percobaan login. |
| Lihat Dashboard, Endpoints, CVE & SCA Findings | ✅ | ✅ | ✅ | Read-only pada inventori dan temuan. |
| Trigger Sinkronisasi Data Wazuh (Mock/Live) | ✅ | ✅ | ✅ | Tercatat siapa pemicunya di `audit_logs`. |
| Generate AI Remediation + Rollback Script | ✅ | ❌ | ✅ | `APPROVER` fokus pada review agar ada *separation of duties*. |
| Lihat Detail Job, Script, Backup Targets & Logs | ✅ | ✅ | ✅ | Semua role internal dapat mengaudit detail job. |
| **Approve / Reject Remediation Job** | ❌ | ✅ | ✅ | **Wajib** `has_pre_backup = true` (terkunci di UI & API jika `false`). |
| Eksekusi Job (`APPROVED` → `EXECUTING`) | ✅ | ❌ | ✅ | Hanya job berstatus `APPROVED` yang bisa dieksekusi. |
| Trigger Manual Rollback (`COMPLETED`/`FAILED` → `ROLLED_BACK`) | ✅ | ✅ | ✅ | Memicu `rollback_script` menggunakan `backup_path` job terkait. |
| Kelola User Lokal (Create/Disable/Reset Password) | ❌ | ❌ | ✅ | Password lokal di-hash (Argon2id/bcrypt). |
| Kelola Mapping Grup LDAP → Role & Konfigurasi Sistem | ❌ | ❌ | ✅ | Grup LDAP tak dikenal jatuh ke role terendah (`OPERATOR`). |
| Lihat & Ekspor Audit Log | ❌ | ✅ (Read) | ✅ (Read/Export) | Audit log bersifat *append-only* (tidak bisa diubah/dihapus via UI/API). |

### 2.3 Kebijakan Autentikasi Ganda (Local + Domain Controller / LDAP)
1. **Akun Lokal (`auth_provider = 'LOCAL'`):**
   - Dibuat oleh `ADMIN` melalui panel User Management (atau *initial admin seed* via environment variable saat bootstrap container pertama kali).
   - Password wajib memenuhi standar kompleksitas minimal dan disimpan dalam bentuk hash kriptografis (`Argon2id` atau `bcrypt`), **tidak pernah** *plaintext*.
2. **Akun Domain Controller / LDAP (`auth_provider = 'LDAP'`):**
   - Backend menggunakan library Python `ldap3` untuk melakukan koneksi (LDAPS/StartTLS direkomendasikan) dan verifikasi kredensial (*bind*) langsung ke Active Directory / LDAP perusahaan.
   - **Dilarang keras menyimpan password LDAP ke database PostgreSQL** (kolom `password_hash` wajib `NULL` untuk user `LDAP`).
   - Saat login LDAP berhasil untuk pertama kalinya (*Just-In-Time Provisioning*), sistem membuat/memperbarui baris user di tabel `users` dengan metadata non-sensitif (`username`, `display_name`, `email`, `external_dn`, `last_synced_ldap_groups`).
3. **Pemetaan Grup LDAP ke Role & Default Role Terendah:**
   - Saat login LDAP berhasil, backend membaca atribut grup pengguna (`memberOf`) dan mencocokkannya dengan tabel `ldap_group_mappings` berdasarkan prioritas tertinggi (`ADMIN` > `APPROVER` > `OPERATOR`).
   - **Fallback Rule:** Jika user berhasil autentikasi di LDAP namun **tidak ada satu pun grup yang cocok** di `ldap_group_mappings` (atau atribut grup kosong), sistem **wajib memberikan role terendah secara default (`OPERATOR`)**, bukan menolak secara diam-diam tanpa jejak atau memberi hak akses tinggi. Perubahan mapping grup berlaku otomatis pada login berikutnya.

---

## 3. Scope Phase 1 (In-Scope vs Out-of-Scope)

### 3.1 In-Scope (Dibangun & Diselesaikan di Phase 1)
1. **Infrastruktur Docker Terpisah:**
   - Setup terpisah `docker-compose.wazuh.yml` (Wazuh Manager, Indexer/Dashboard bawaan Wazuh jika diperlukan) dan `docker-compose.qshields.yml` (PostgreSQL, Ollama, FastAPI, Next.js).
2. **Autentikasi & Otorisasi (Local + LDAP + RBAC):**
   - Login hybrid (pilih/deteksi provider `LOCAL` atau `LDAP`), JWT session dengan expiry terukur, RBAC untuk `OPERATOR`, `APPROVER`, `ADMIN`, serta UI manajemen user lokal dan LDAP group mapping.
3. **Wazuh Ingestion & Asset Visibility (Mock → Live):**
   - Sinkronisasi daftar endpoint/agent (OS, IP, versi agent, status koneksi), daftar CVE per endpoint, dan hasil pemeriksaan CIS Benchmark / SCA per endpoint ke tabel relasional PostgreSQL.
4. **AI-Assisted Remediation & Pre-Change Backup Engine:**
   - Alur kerja **LangGraph** memanggil **Ollama** lokal untuk menghasilkan paket remediasi terstruktur (Bash untuk Linux, PowerShell untuk Windows) yang terdiri dari:
     - `remediation_script`: wajib diawali blok **Pre-Change Backup** (menyalin file target/registry/daftar paket ke direktori unik job + menghitung SHA-256 checksum) dan diakhiri **blok validasi + auto-revert** jika validasi gagal.
     - `rollback_script`: skrip mandiri yang memulihkan sistem persis dari `backup_path` job tersebut.
     - `backup_targets` & `backup_path` & `has_pre_backup`.
5. **Human-in-the-Loop Approval Queue:**
   - Antarmuka peninjauan skrip (syntax view, target endpoint, ringkasan risiko, target backup).
   - **Hard-lock Tombol Approve:** UI menonaktifkan tombol Approve jika `has_pre_backup === false` dan API menolak `POST /jobs/{id}/approve` dengan HTTP `400/422`.
6. **Controlled Execution & Rollback:**
   - Eksekusi job berstatus `APPROVED` ke endpoint via Wazuh Active Response (atau Mock Runner saat pengembangan), pembaruan status real-time/polling ke PostgreSQL (`EXECUTING` → `COMPLETED` / `FAILED` / `ROLLED_BACK`), serta eksekusi manual `rollback_script`.
7. **Relational Audit Trail:**
   - Seluruh aksi penting (login, sync, generate script, approve/reject, execute, rollback, ubah user/LDAP mapping) dicatat ke tabel relasional terindeks `audit_logs` di PostgreSQL.

### 3.2 Out-of-Scope di Phase 1 (Kesiapan Arsitektur & Skema untuk Phase 2 & 3)
Fitur-fitur berikut **TIDAK** diimplementasikan logika eksekusinya di Phase 1, tetapi **kolom, enum, dan tabel cadangannya sudah disiapkan** di PostgreSQL dan kontrak arsitektur:

| Fase Masa Depan | Fitur Out-of-Scope Phase 1 | Kesiapan yang Ditanam Sejak Phase 1 |
| :--- | :--- | :--- |
| **Phase 2: Pre-Approval Safety & Gradual Rollout** | 1. **Static Code Analyzer Otomatis** (`ShellCheck` untuk skrip Bash, `PSScriptAnalyzer` untuk skrip PowerShell) sebelum approval.<br>2. **Canary Deployment** (uji coba otomatis ke 1 PC/server canary terlebih dahulu dan verifikasi sehat sebelum push massal ke grup endpoint). | - Kolom `static_analysis_status`, `static_analysis_report` (JSONB), `analyzed_at` pada tabel `remediation_jobs`.<br>- Kolom `is_canary_eligible` pada tabel `endpoints`.<br>- Kolom `deployment_strategy` (`SINGLE`/`CANARY_FIRST`/`BATCH`), `canary_endpoint_id`, `canary_job_id`, dan `target_group_id` pada `remediation_jobs`. |
| **Phase 3: Real-Time Telemetry & Active EDR** | 1. **Telemetri Real-Time** berbasis `Sysmon` (Windows) dan `eBPF` (Linux).<br>2. **Deteksi Sigma Rules** terhadap event telemetri.<br>3. **Aksi Cepat EDR** (*Isolate Host*, *Kill Process*, *Quarantine File*). | - Kolom `isolation_status` dan `telemetry_agent_version` pada `endpoints`.<br>- Kolom opsional `sigma_rule_id` pada `findings`.<br>- Tabel cadangan terstruktur `telemetry_events` (dengan indeks waktu & rule) dan `edr_actions` (untuk mencatat perintah *Isolate Host*, *Kill Process*, *Quarantine File* beserta status eksekusinya). |

---

## 4. End-to-End User Flows

### 4.1 Flow A: Sinkronisasi Data Wazuh (Mock → Live)
1. `OPERATOR` (atau scheduler periodik opsional) menekan tombol **"Sync Wazuh Data"** di UI atau memanggil `POST /api/v1/sync/wazuh`.
2. Backend memeriksa konfigurasi `WAZUH_MODE`:
   - Jika `mock`: membaca dataset JSON deterministik dari direktori fixture lokal.
   - Jika `live`: mengautentikasi ke Wazuh Manager API (JWT token) melalui jaringan `qshields-net`, mengambil daftar agents, CVE vulnerabilities (`/vulnerability/{agent_id}`), dan hasil SCA/CIS (`/sca/{agent_id}`).
3. Backend melakukan *upsert* secara idempotent ke tabel `endpoints` dan `findings` di PostgreSQL.
4. Sistem mencatat ringkasan sinkronisasi (jumlah endpoint baru/diperbarui, temuan baru/terselesaikan) ke `audit_logs` dan mengembalikan ringkasan ke UI.

```mermaid
sequenceDiagram
    actor Op as Operator
    participant UI as Next.js UI
    participant API as FastAPI Backend
    participant Adapter as Wazuh Adapter (Mock/Live)
    participant DB as PostgreSQL

    Op->>UI: Klik "Sync Wazuh"
    UI->>API: POST /api/v1/sync/wazuh
    API->>Adapter: fetch_agents_cve_sca()
    Adapter-->>API: Normalized Endpoints & Findings
    API->>DB: Upsert endpoints & findings (Idempotent)
    API->>DB: Insert audit_logs (SYNC_WAZUH)
    API-->>UI: 200 OK (Summary Counts)
```

### 4.2 Flow B: Generate Script Remediasi + Pre-Change Backup (LangGraph + Ollama)
1. `OPERATOR` memilih satu temuan (CVE atau SCA/CIS check yang gagal) pada endpoint tertentu, lalu mengklik **"Generate Remediation"**.
2. Backend membuat record awal di `remediation_jobs` dengan status `GENERATING` dan menjalankan graph **LangGraph** yang memiliki node terstruktur:
   - **Node 1 (`context_builder`):** Mengambil detail temuan, OS/distro endpoint, dan aturan kontrak keamanan.
   - **Node 2 (`script_generator`):** Memanggil Ollama lokal (atau Mock LLM jika `LLM_MODE=mock`) dengan *structured JSON output* untuk menghasilkan:
     - `remediation_script` (wajib mencakup blok pre-change backup ke `backup_path` unik per job, misal `/var/backups/q-shields/<job_id>/` atau `C:\ProgramData\Q-Shields\backups\<job_id>\`, pencatatan checksum SHA-256, langkah remediasi, langkah validasi pasca-perubahan, dan **auto-revert** jika validasi gagal).
     - `rollback_script` (skrip mandiri yang membaca manifest/file dari `backup_path` tersebut untuk mengembalikan kondisi semula).
     - `backup_targets` (daftar path file/registry/paket yang dibackup).
   - **Node 3 (`safety_validator`):** Memeriksa secara programatik apakah:
     - `backup_path` valid dan unik per `job_id`,
     - `backup_targets` tidak kosong,
     - `remediation_script` memuat instruksi pre-backup dan logika auto-revert,
     - `rollback_script` tidak kosong dan merujuk ke `backup_path` yang sama.
3. Jika semua pemeriksaan lolos, `has_pre_backup` disetel `true` dan status job menjadi `PENDING_APPROVAL`. Jika gagal validasi parser (atau backup tidak terverifikasi), `has_pre_backup` disetel `false` (status `DRAFT_UNSAFE` atau `PENDING_APPROVAL` terkunci) agar **tidak pernah** bisa disetujui.

```mermaid
flowchart TD
    A["Operator pilih Finding & Endpoint"] --> B["LangGraph: context_builder"]
    B --> C["LangGraph: script_generator via Ollama Lokal"]
    C --> D["LangGraph: safety_validator"]
    D -->|"Backup path, targets, auto-revert & rollback_script valid"| E["has_pre_backup = true\nStatus: PENDING_APPROVAL"]
    D -->|"Salah satu komponen pre-backup tidak valid"| F["has_pre_backup = false\nTombol Approve TERKUNCI"]
```

### 4.3 Flow C: Approval Queue (*Human-in-the-Loop*)
1. `APPROVER` membuka halaman **Approval Queue** dan memilih job berstatus `PENDING_APPROVAL`.
2. UI menampilkan:
   - Informasi target endpoint (hostname, OS, IP) dan detail temuan CVE/SCA.
   - Indikator status Pre-Backup (`has_pre_backup`), `backup_path`, dan daftar `backup_targets`.
   - Tab kode terpisah: **Remediation Script** (highlight blok backup & auto-revert) dan **Rollback Script**.
3. **Aturan Kunci UI & API:**
   - Jika `has_pre_backup === false`, tombol **Approve** di UI berada dalam status `disabled` disertai banner peringatan eksplisit: *"Approval terkunci: Pre-change backup belum terverifikasi pada skrip ini."*
   - Jika `has_pre_backup === true`, `APPROVER` dapat menekan **Approve** (status menjadi `APPROVED`, `approved_by` & `approved_at` tersimpan) atau **Reject** (wajib mengisi `rejection_reason`, status menjadi `REJECTED`).
   - Backend memvalidasi ulang `has_pre_backup === true` dan memastikan user memiliki role `APPROVER` atau `ADMIN` (serta *optional/recommended rule*: `approved_by != created_by` untuk *separation of duties* kecuali override oleh `ADMIN` yang tercatat di audit log).

### 4.4 Flow D: Eksekusi, Validasi & Rollback
1. `OPERATOR` (atau `ADMIN`) membuka job berstatus `APPROVED` dan mengklik **"Execute Remediation"**.
2. Status berubah menjadi `EXECUTING`. Backend mengirimkan payload instruksi ke endpoint melalui Wazuh Active Response (atau Mock Runner).
3. Di endpoint, skrip berjalan secara berurutan:
   - **Tahap 1 (Pre-Change Backup):** Membuat direktori `backup_path` unik per job, menyalin `backup_targets` (file konfigurasi / ekspor registry / daftar paket terinstal), menyimpan manifest + checksum SHA-256. Jika tahap backup gagal, skrip **berhenti seketika** tanpa mengubah sistem (`FAILED`).
   - **Tahap 2 (Apply Remediation):** Menerapkan konfigurasi hardening / patch.
   - **Tahap 3 (Post-Change Validation):** Memeriksa apakah layanan tetap berjalan dan konfigurasi sesuai target.
     - Jika validasi **berhasil**: status job dicatat `COMPLETED` dan `execution_logs` tersimpan.
     - Jika validasi **gagal**: skrip otomatis menjalankan prosedur **auto-revert** dari `backup_path`, mengembalikan sistem ke kondisi semula, dan melaporkan status `ROLLED_BACK` (beserta pesan error penyebab auto-revert).
4. **Manual Rollback:** Untuk job berstatus `COMPLETED` (misal ditemukan efek samping operasional belakangan) atau `FAILED` (jika perubahan parsial terjadi), `OPERATOR`/`APPROVER`/`ADMIN` dapat menekan **"Trigger Rollback"** untuk mengeksekusi `rollback_script` yang merujuk ke `backup_path` job tersebut. Setelah berhasil dipulihkan, status job diperbarui menjadi `ROLLED_BACK`.

```mermaid
stateDiagram-v2
    [*] --> GENERATING
    GENERATING --> PENDING_APPROVAL: Validasi AI Selesai
    PENDING_APPROVAL --> REJECTED: Approver Reject
    PENDING_APPROVAL --> APPROVED: Approver Approve (Wajib has_pre_backup=true)
    APPROVED --> EXECUTING: Operator Execute
    EXECUTING --> COMPLETED: Pre-Backup + Apply + Validasi Sukses
    EXECUTING --> ROLLED_BACK: Validasi Gagal -> Auto-Revert Sukses
    EXECUTING --> FAILED: Pre-Backup Gagal / Auto-Revert Gagal
    COMPLETED --> ROLLED_BACK: Manual Trigger Rollback Sukses
    FAILED --> ROLLED_BACK: Manual Trigger Rollback Sukses
```

### 4.5 Flow E: Login Manual (Local) & Domain Controller / LDAP
1. User membuka halaman `/login`, memasukkan `username` dan `password`, serta memilih metode login (`Auto/LDAP` atau `Local Account`).
2. **Jika `LOCAL`:**
   - Backend mencari user pada tabel `users` dengan `auth_provider = 'LOCAL'` dan `is_active = true`.
   - Memverifikasi hash password (Argon2id/bcrypt). Jika cocok, menerbitkan JWT access token berisi `user_id`, `username`, dan `role`.
3. **Jika `LDAP`:**
   - Backend menggunakan `ldap3` untuk melakukan koneksi aman ke Domain Controller internal dan melakukan bind menggunakan kredensial user. **Password LDAP langsung dibuang dari memori setelah bind dan tidak pernah ditulis ke database atau log.**
   - Jika bind gagal → kembalikan `401 Unauthorized` dan catat kegagalan di `audit_logs`.
   - Jika bind berhasil → ambil `distinguishedName`, `displayName`, `mail`, dan daftar grup `memberOf` dari direktori LDAP.
   - Cocokkan daftar grup terhadap tabel `ldap_group_mappings`:
     - Jika ada satu atau lebih grup cocok → pilih role dengan privilege tertinggi di antara yang cocok (`ADMIN` > `APPROVER` > `OPERATOR`).
     - Jika **tidak ada grup yang cocok** → tetapkan role terendah default: **`OPERATOR`**.
   - Lakukan *upsert* user ke tabel `users` (`auth_provider = 'LDAP'`, `password_hash = NULL`, `role = resolved_role`), catat `LOGIN_LDAP_SUCCESS` di `audit_logs`, dan terbitkan JWT token.

---

## 5. Functional & Non-Functional Requirements

### 5.1 Functional Requirements (FR)

| ID | Kategori | Deskripsi Kebutuhan | Acceptance Criteria (Terukur) |
| :--- | :--- | :--- | :--- |
| **FR-01** | Auth & RBAC | Sistem mendukung pembuatan akun lokal oleh `ADMIN` dan login hybrid menggunakan akun lokal (`PostgreSQL`) maupun Domain Controller / LDAP (`ldap3`). | - User lokal dapat dibuat, dinonaktifkan, dan login dengan verifikasi hash password.<br>- User LDAP dapat login via `ldap3` tanpa menyimpan password LDAP di kolom mana pun di PostgreSQL (`password_hash IS NULL`).<br>- Jika grup LDAP user tidak terdaftar di `ldap_group_mappings`, user otomatis mendapat role `OPERATOR`. |
| **FR-02** | RBAC Enforcement | Setiap endpoint API dan komponen UI wajib menegakkan izin akses berdasarkan role (`OPERATOR`, `APPROVER`, `ADMIN`). | - Request API di luar izin role mengembalikan HTTP `403 Forbidden`.<br>- `OPERATOR` tidak melihat tombol aktif untuk Approve/Reject dan User Management. |
| **FR-03** | Wazuh Sync (Mock & Live) | Sistem dapat menarik inventori endpoint, CVE, dan hasil scan SCA/CIS Benchmark dari Wazuh Manager (atau mode Mock) ke PostgreSQL. | - Tersedia toggle konfigurasi `WAZUH_MODE=mock\|live`.<br>- Sinkronisasi berulang pada data sama tidak menghasilkan duplikasi baris di `endpoints` dan `findings` (idempotent). |
| **FR-04** | Dashboard & Findings View | Pengguna dapat memfilter dan melihat daftar endpoint, CVE berdasarkan severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), dan SCA checks yang berstatus `FAILED`. | - Halaman Dashboard menampilkan ringkasan metrik akurat dari query SQL PostgreSQL.<br>- Filter berdasarkan OS, severity, dan status kepatuhan berjalan dalam < 1 detik untuk 1.000+ temuan. |
| **FR-05** | AI Remediation Generator | Backend menggunakan LangGraph + Ollama lokal untuk menghasilkan paket remediasi berisi `remediation_script`, `rollback_script`, `backup_targets`, `backup_path`, dan `has_pre_backup`. | - Tidak ada panggilan keluar ke internet/API LLM publik.<br>- Output AI diparsing sesuai skema Pydantic ketat.<br>- `backup_path` bersifat unik per `job_id` (mis. `/var/backups/q-shields/<job_id>/`). |
| **FR-06** | Pre-Change Backup Guard | Sistem memaksa setiap skrip remediasi melakukan backup kondisi awal + checksum sebelum perubahan diterapkan, dan mengunci approval jika tidak valid. | - Jika `has_pre_backup = false`, tombol **Approve** di UI dalam keadaan `disabled`.<br>- Pemanggilan langsung `POST /api/v1/jobs/{id}/approve` saat `has_pre_backup = false` ditolak backend dengan HTTP `422 Unprocessable Entity`. |
| **FR-07** | Approval Queue | `APPROVER` dan `ADMIN` dapat meninjau detail skrip remediasi & rollback lalu menyetujui (`APPROVED`) atau menolak (`REJECTED` dengan alasan wajib). | - Penolakan tanpa alasan (`rejection_reason` kosong) ditolak oleh API.<br>- Keputusan approval menyimpan `approved_by`, `approved_at`, dan entri `audit_logs`. |
| **FR-08** | Execution, Auto-Revert & Rollback | Sistem dapat mengeksekusi job `APPROVED`, mendeteksi kegagalan validasi pasca-eksekusi untuk melakukan auto-revert, serta mendukung manual rollback ke status `ROLLED_BACK`. | - Pre-backup gagal → perubahan tidak diterapkan, status `FAILED`.<br>- Validasi gagal → skrip memulihkan file/konfigurasi dari `backup_path`, status menjadi `ROLLED_BACK`.<br>- Tombol **Trigger Rollback** pada job `COMPLETED`/`FAILED` menjalankan `rollback_script` dan memperbarui status menjadi `ROLLED_BACK`. |
| **FR-09** | Relational Audit Log | Semua peristiwa keamanan dan perubahan state dicatat ke tabel PostgreSQL `audit_logs` secara terstruktur dan terindeks. | - Mencakup `actor_user_id`, `action`, `resource_type`, `resource_id`, `metadata` (JSONB), `ip_address`, dan `created_at`.<br>- Tidak ada endpoint API untuk `UPDATE` atau `DELETE` baris `audit_logs`. |

### 5.2 Non-Functional Requirements (NFR)

| ID | Kategori | Deskripsi Kebutuhan | Acceptance Criteria (Terukur) |
| :--- | :--- | :--- | :--- |
| **NFR-01** | Data Privacy & Network Isolation | Seluruh pemrosesan AI (Ollama) dan data keamanan (PostgreSQL, Wazuh) berjalan 100% di jaringan internal Docker tanpa akses internet wajib saat runtime. | - Container `ollama`, `backend`, dan `postgres` tidak memerlukan outbound internet untuk menjalankan fitur inti.<br>- Koneksi ke LDAP mendukung LDAPS/TLS (`LDAP_USE_SSL=true`). |
| **NFR-02** | Security & Credential Hygiene | Kredensial sensitif (JWT secret, DB password, Wazuh API password, LDAP bind service password) dikelola melalui environment variables / Docker secrets. | - Password user lokal di-hash menggunakan Argon2id/bcrypt.<br>- Password user LDAP tidak pernah tersimpan di database maupun tercetak di stdout/log container. |
| **NFR-03** | Reliability & Timeout Control | Orkestrasi LangGraph/Ollama dan eksekusi Wazuh harus memiliki timeout dan mekanisme *graceful error handling*. | - Timeout inferensi Ollama dikonfigurasi eksplisit (mis. 120 detik) dengan status error jelas jika gagal.<br>- Eksekusi skrip di endpoint memiliki batas waktu agar worker backend tidak *hang*. |
| **NFR-04** | Database Performance & Indexing | Database PostgreSQL menggunakan tabel relasional terstruktur dengan indeks pada kolom filter utama (bukan data stream / time-series unstructured). | - Indeks tersedia pada `endpoints(wazuh_agent_id)`, `findings(endpoint_id, severity, status)`, `remediation_jobs(status, has_pre_backup)`, dan `audit_logs(created_at, actor_user_id)`. |
| **NFR-05** | Maintainability (Vibe Coding Ready) | Kode backend memisahkan layer Router, Service, Adapter, dan Schema; frontend memisahkan API client dan komponen shadcn/ui. | - Dokumentasi OpenAPI (`/docs` / `/openapi.json`) otomatis terbuat dari FastAPI dan sinkron dengan tipe TypeScript di frontend. |
| **NFR-06** | Docker Stack Decoupling | Stack Wazuh dan stack Q-Shields dapat dijalankan, di-stop, dan di-build ulang secara independen. | - Menjalankan `docker compose -f docker-compose.qshields.yml up -d --build` tidak me-restart container di `docker-compose.wazuh.yml`. |

---

## 6. Desain Skema Database PostgreSQL

Seluruh data aplikasi, konfigurasi RBAC/LDAP, pekerjaan remediasi, dan audit log disimpan pada **PostgreSQL** dalam bentuk tabel relasional terstruktur (bukan data stream). Skema di bawah ini sudah mencakup kebutuhan **Phase 1** serta kolom dan tabel cadangan untuk **Phase 2** dan **Phase 3**.

### 6.1 Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    users ||--o{ remediation_jobs : "creates / approves"
    users ||--o{ audit_logs : "performs"
    endpoints ||--o{ findings : "has"
    findings ||--o{ remediation_jobs : "remediated by"
    endpoints ||--o{ remediation_jobs : "targets"
    remediation_jobs ||--o{ job_execution_logs : "records"
    endpoints ||--o{ telemetry_events : "(Phase 3) emits"
    endpoints ||--o{ edr_actions : "(Phase 3) receives"
    users ||--o{ edr_actions : "(Phase 3) triggers"

    users {
        uuid id PK
        varchar username UK
        varchar auth_provider
        varchar password_hash
        varchar external_dn
        varchar role
        boolean is_active
    }

    ldap_group_mappings {
        uuid id PK
        varchar ldap_group_dn UK
        varchar assigned_role
        int priority
    }

    endpoints {
        uuid id PK
        varchar wazuh_agent_id UK
        varchar hostname
        varchar os_family
        varchar status
        boolean is_canary_eligible "Phase 2"
        varchar isolation_status "Phase 3"
    }

    findings {
        uuid id PK
        uuid endpoint_id FK
        varchar source_type
        varchar external_ref_id
        varchar severity
        varchar status
        varchar sigma_rule_id "Phase 3"
    }

    remediation_jobs {
        uuid id PK
        uuid endpoint_id FK
        uuid finding_id FK
        text remediation_script
        text rollback_script
        varchar backup_path
        jsonb backup_targets
        boolean has_pre_backup
        varchar status
        varchar static_analysis_status "Phase 2"
        varchar deployment_strategy "Phase 2"
    }

    job_execution_logs {
        uuid id PK
        uuid job_id FK
        varchar stage
        int exit_code
        text stdout
        text stderr
    }

    audit_logs {
        uuid id PK
        uuid actor_user_id FK
        varchar action
        varchar resource_type
        varchar resource_id
        jsonb metadata
        timestamptz created_at
    }
```

### 6.2 Spesifikasi DDL PostgreSQL (Siap Migrasi Alembic/SQL)

```sql
-- Ekstensi UUID
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==========================================
-- 1. AUTHENTICATION, RBAC & LDAP MAPPING
-- ==========================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(150),
    email VARCHAR(255),
    auth_provider VARCHAR(20) NOT NULL CHECK (auth_provider IN ('LOCAL', 'LDAP')),
    -- Wajib NULL jika auth_provider = 'LDAP' (dilarang simpan password LDAP)
    password_hash TEXT,
    -- Metadata non-sensitif dari Domain Controller / AD
    external_dn TEXT,
    last_synced_ldap_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
    role VARCHAR(20) NOT NULL DEFAULT 'OPERATOR' CHECK (role IN ('OPERATOR', 'APPROVER', 'ADMIN')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_local_has_password CHECK (
        (auth_provider = 'LOCAL' AND password_hash IS NOT NULL) OR
        (auth_provider = 'LDAP' AND password_hash IS NULL)
    )
);

CREATE INDEX idx_users_auth_provider ON users(auth_provider);
CREATE INDEX idx_users_role ON users(role);

CREATE TABLE ldap_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ldap_group_dn TEXT NOT NULL UNIQUE,
    ldap_group_cn VARCHAR(150) NOT NULL,
    assigned_role VARCHAR(20) NOT NULL CHECK (assigned_role IN ('OPERATOR', 'APPROVER', 'ADMIN')),
    priority INT NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==========================================
-- 2. ENDPOINTS & FINDINGS (WAZUH INVENTORY)
-- ==========================================

CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wazuh_agent_id VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os_family VARCHAR(20) NOT NULL CHECK (os_family IN ('LINUX', 'WINDOWS')),
    os_name VARCHAR(150),
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    connection_status VARCHAR(30) NOT NULL DEFAULT 'DISCONNECTED',
    last_seen_at TIMESTAMPTZ,
    -- Kolom cadangan Phase 2 (Canary Deployment)
    is_canary_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    environment_tier VARCHAR(30) NOT NULL DEFAULT 'PRODUCTION',
    -- Kolom cadangan Phase 3 (Real-time Telemetry & EDR)
    isolation_status VARCHAR(20) NOT NULL DEFAULT 'NONE' CHECK (isolation_status IN ('NONE', 'ISOLATING', 'ISOLATED')),
    telemetry_agent_version VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_endpoints_os_family ON endpoints(os_family);
CREATE INDEX idx_endpoints_connection_status ON endpoints(connection_status);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    source_type VARCHAR(20) NOT NULL CHECK (source_type IN ('CVE', 'SCA_CIS', 'SIGMA')), -- SIGMA untuk Phase 3
    external_ref_id VARCHAR(150) NOT NULL, -- mis: CVE-2024-1234 atau SCA-CIS-5.2.4
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'IGNORED')),
    affected_package VARCHAR(255),
    remediation_hint TEXT,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Kolom cadangan Phase 3 (Sigma Rules)
    sigma_rule_id VARCHAR(128),
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (endpoint_id, source_type, external_ref_id)
);

CREATE INDEX idx_findings_endpoint_status ON findings(endpoint_id, status);
CREATE INDEX idx_findings_severity_status ON findings(severity, status);
CREATE INDEX idx_findings_source_type ON findings(source_type);

-- ==========================================
-- 3. REMEDIATION JOBS, PRE-BACKUP & ROLLBACK
-- ==========================================

CREATE TABLE remediation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id),
    approved_by UUID REFERENCES users(id),
    target_os VARCHAR(20) NOT NULL CHECK (target_os IN ('LINUX', 'WINDOWS')),
    script_type VARCHAR(20) NOT NULL CHECK (script_type IN ('BASH', 'POWERSHELL')),
    ai_model_used VARCHAR(100),
    ai_summary TEXT,

    -- Skrip & Kontrol Pre-Change Backup (Wajib Phase 1)
    remediation_script TEXT NOT NULL,
    validation_script TEXT,
    rollback_script TEXT NOT NULL,
    backup_path VARCHAR(512) NOT NULL,
    backup_targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    backup_checksum VARCHAR(128),
    has_pre_backup BOOLEAN NOT NULL DEFAULT FALSE,

    -- Status Lifecycle (Mencakup ROLLED_BACK)
    status VARCHAR(30) NOT NULL DEFAULT 'GENERATING' CHECK (
        status IN (
            'GENERATING',
            'PENDING_APPROVAL',
            'APPROVED',
            'REJECTED',
            'EXECUTING',
            'COMPLETED',
            'FAILED',
            'ROLLED_BACK'
        )
    ),
    rejection_reason TEXT,
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    rolled_back_at TIMESTAMPTZ,

    -- Kolom cadangan Phase 2 (Static Analyzer & Canary Deployment)
    static_analysis_status VARCHAR(20) NOT NULL DEFAULT 'NOT_RUN' CHECK (
        static_analysis_status IN ('NOT_RUN', 'PASSED', 'WARNING', 'FAILED')
    ),
    static_analysis_report JSONB,
    analyzed_at TIMESTAMPTZ,
    deployment_strategy VARCHAR(20) NOT NULL DEFAULT 'SINGLE' CHECK (
        deployment_strategy IN ('SINGLE', 'CANARY_FIRST', 'BATCH')
    ),
    canary_endpoint_id UUID REFERENCES endpoints(id),
    canary_job_id UUID REFERENCES remediation_jobs(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_jobs_status ON remediation_jobs(status);
CREATE INDEX idx_jobs_has_pre_backup ON remediation_jobs(has_pre_backup);
CREATE INDEX idx_jobs_endpoint_id ON remediation_jobs(endpoint_id);
CREATE INDEX idx_jobs_created_by ON remediation_jobs(created_by);

CREATE TABLE job_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
    stage VARCHAR(30) NOT NULL CHECK (
        stage IN ('PRE_BACKUP', 'REMEDIATION', 'VALIDATION', 'AUTO_REVERT', 'MANUAL_ROLLBACK')
    ),
    exit_code INT,
    stdout TEXT,
    stderr TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_job_exec_logs_job_id ON job_execution_logs(job_id, executed_at);

-- ==========================================
-- 4. STRUCTURED RELATIONAL AUDIT LOGS
-- ==========================================

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(100) NOT NULL,
    actor_role VARCHAR(20),
    action VARCHAR(64) NOT NULL, -- contoh: LOGIN_LOCAL, LOGIN_LDAP, SYNC_WAZUH, GENERATE_JOB, APPROVE_JOB, REJECT_JOB, EXECUTE_JOB, ROLLBACK_JOB
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'SUCCESS' CHECK (status IN ('SUCCESS', 'FAILURE', 'DENIED')),
    ip_address INET,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_user_id, created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- ==========================================
-- 5. TABEL CADANGAN PHASE 3 (TELEMETRI & EDR)
-- ==========================================

CREATE TABLE telemetry_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    source_sensor VARCHAR(20) NOT NULL CHECK (source_sensor IN ('SYSMON', 'EBPF')),
    event_type VARCHAR(64) NOT NULL,
    sigma_rule_id VARCHAR(128),
    severity VARCHAR(20) NOT NULL DEFAULT 'INFO',
    process_name VARCHAR(255),
    process_pid INT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_telemetry_endpoint_time ON telemetry_events(endpoint_id, occurred_at DESC);
CREATE INDEX idx_telemetry_sigma_rule ON telemetry_events(sigma_rule_id);

CREATE TABLE edr_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    triggered_by UUID NOT NULL REFERENCES users(id),
    action_type VARCHAR(30) NOT NULL CHECK (action_type IN ('ISOLATE_HOST', 'UNISOLATE_HOST', 'KILL_PROCESS', 'QUARANTINE_FILE')),
    target_artifact TEXT NOT NULL, -- PID / file path / host identifier
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED')),
    result_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_edr_actions_endpoint ON edr_actions(endpoint_id, created_at DESC);
```

---

## 7. Rencana Sprint Vibe Coding Phase 1

Urutan sprint di bawah dirancang khusus untuk **vibe coding** agar setiap lapisan memiliki fondasi kontrak yang kokoh, dapat diverifikasi secara terpisah (*mock-first*), dan **tidak macet** akibat dependensi eksternal (Wazuh/AD/Ollama) di awal pembangunan.

### Sprint 0: Fondasi Repo, Docker Terpisah & Kontrak Data
- **Tujuan:** Menyiapkan kerangka monorepo/folder, pemisahan file Compose, database PostgreSQL, dan skema kontrak API.
- **Deliverables:**
  - Struktur direktori (`/backend`, `/frontend`, `/infra`, `/docs`).
  - `infra/docker-compose.wazuh.yml` (stack Wazuh terpisah) & `infra/docker-compose.qshields.yml` (`postgres`, `ollama`, `backend`, `frontend`) terhubung via external network `qshields-net`.
  - Migrasi SQL/Alembic awal sesuai Bab 6 PRD ini.
  - Skeleton FastAPI (`/health`) dan Next.js App Router + Tailwind + shadcn/ui.
- **Anti-Stuck Guardrail:** Gunakan `.env.example` yang lengkap dan *mock flags* (`WAZUH_MODE=mock`, `LLM_MODE=mock`, `LDAP_ENABLED=false`) agar seluruh stack langsung menyala lokal tanpa perlu Active Directory atau Wazuh live terlebih dahulu.

### Sprint 1: Autentikasi Local + LDAP (`ldap3`), RBAC & Audit Log
- **Tujuan:** Mengamankan seluruh akses sejak awal sebelum membangun fitur bisnis.
- **Deliverables:**
  - Model `User`, `LdapGroupMapping`, `AuditLog` + seeding initial `ADMIN` lokal.
  - Endpoint `POST /api/v1/auth/login` (mendukung `LOCAL` dengan Argon2id/bcrypt dan `LDAP` via `ldap3` tanpa menyimpan password LDAP).
  - Resolver grup LDAP ke role RBAC dengan fallback wajib ke role terendah (`OPERATOR`).
  - Middleware RBAC FastAPI + halaman `/login` dan `/admin/users` (kelola user lokal & mapping grup LDAP) di Next.js.
- **Definition of Done:** Login local & mock/test LDAP berhasil, user tanpa grup LDAP cocok otomatis mendapat role `OPERATOR`, dan `audit_logs` merekam event login.

### Sprint 2: Wazuh Connector (Mock → Live) & Dashboard Inventory
- **Tujuan:** Menampilkan data endpoint, CVE, dan SCA/CIS Benchmark di UI dari PostgreSQL.
- **Deliverables:**
  - Adapter `WazuhClient` dengan interface seragam untuk mode `mock` (fixture JSON realistis Linux & Windows) dan mode `live` (Wazuh Manager REST API).
  - Endpoint `POST /api/v1/sync/wazuh`, `GET /api/v1/endpoints`, dan `GET /api/v1/findings`.
  - Halaman UI Next.js: **Dashboard Overview**, **Endpoints Inventory**, dan **Findings Explorer** (filter CVE/SCA, severity, status).
- **Definition of Done:** Sinkronisasi mock data mengisi PostgreSQL secara idempotent dan seluruh tabel/filter UI berfungsi mulus.

### Sprint 3: AI Remediation Engine (LangGraph + Ollama + Pre-Backup Contract)
- **Tujuan:** Menghasilkan skrip remediasi & rollback yang aman dan selalu mematuhi aturan *pre-change backup*.
- **Deliverables:**
  - Workflow **LangGraph** (`context_builder` → `script_generator` → `safety_validator`).
  - Prompt template khusus Linux (Bash) dan Windows (PowerShell) yang mewajibkan blok Pre-Change Backup (`backup_path` unik per job, `backup_targets`, SHA-256) + post-validation + auto-revert + `rollback_script` terpisah.
  - Mode `LLM_MODE=mock` untuk pengujian deterministik + mode `LLM_MODE=ollama` untuk inferensi lokal.
  - Endpoint `POST /api/v1/jobs/generate`.
- **Definition of Done:** Output AI selalu tervalidasi ke kolom `backup_path`, `backup_targets`, `rollback_script`, dan `has_pre_backup`. Pengujian negatif membuktikan skrip tanpa blok backup menghasilkan `has_pre_backup = false`.

### Sprint 4: Approval Queue UI & Execution / Rollback Runner
- **Tujuan:** Menyelesaikan siklus *Human-in-the-Loop*, eksekusi terkontrol, auto-revert, dan manual rollback.
- **Deliverables:**
  - Halaman **Approval Queue** dan **Job Detail** (menampilkan diff/kode `remediation_script`, `rollback_script`, dan status `has_pre_backup`).
  - **Hard-lock tombol Approve** di Next.js jika `has_pre_backup === false` + validasi ulang di endpoint `POST /api/v1/jobs/{id}/approve`.
  - Endpoint `POST /api/v1/jobs/{id}/reject`, `POST /api/v1/jobs/{id}/execute`, dan `POST /api/v1/jobs/{id}/rollback`.
  - Execution runner (mode `mock` dan Wazuh Active Response `live`) yang menyimpan stdout/stderr ke `job_execution_logs` dan memperbarui status menjadi `COMPLETED`, `FAILED`, atau `ROLLED_BACK`.
- **Definition of Done:** Siklus penuh *Generate → Lock Check → Approve → Execute → Auto-Revert/Manual Rollback* berjalan end-to-end dengan jejak lengkap di `job_execution_logs` dan `audit_logs`.

### Sprint 5: Integrasi Live Stack, Hardening & UAT Internal
- **Tujuan:** Beralih dari mode `mock` ke mode `live` bersama Wazuh Manager, Ollama, dan Domain Controller internal.
- **Deliverables:**
  - Uji konektivitas antar Docker stack (`qshields-net`), pull model Ollama lokal (mis. `qwen2.5-coder` / `llama3.1` sesuai kapasitas GPU/CPU internal), dan verifikasi Wazuh Active Response pada 1 VM uji Linux & 1 VM uji Windows.
  - Uji penetrasi ringan terhadap kontrol RBAC, validasi bypass `has_pre_backup`, dan keamanan kredensial LDAP.
  - Panduan deployment internal (`docs/DEPLOYMENT.md`) dan skenario UAT.
- **Definition of Done:** Seluruh Acceptance Criteria `FR-01` s.d. `FR-09` dan `NFR-01` s.d. `NFR-06` lulus di lingkungan staging Docker internal.

---

## 8. Lampiran: Referensi Arsitektur Docker & Kontrak Data

### 8.1 Pemisahan Docker Compose (Konseptual)
- **External Network Bersama:**
  ```bash
  docker network create qshields-net
  ```
- **Stack 1 (`infra/docker-compose.wazuh.yml`):** Menjalankan `wazuh.manager` (dan komponen Wazuh lain yang dibutuhkan) yang terhubung ke `qshields-net`.
- **Stack 2 (`infra/docker-compose.qshields.yml`):** Menjalankan `postgres`, `ollama`, `qshields-backend` (FastAPI + LangGraph), dan `qshields-frontend` (Next.js) pada `qshields-net`.

### 8.2 Kontrak Output Terstruktur AI (LangGraph → FastAPI)
Berikut kontrak JSON standar yang wajib dihasilkan oleh node `script_generator` sebelum lolos `safety_validator`:

```json
{
  "target_os": "LINUX",
  "script_type": "BASH",
  "ai_summary": "Menonaktifkan SSH root login di /etc/ssh/sshd_config dan me-reload sshd.",
  "backup_path": "/var/backups/q-shields/job-550e8400-e29b-41d4-a716-446655440000",
  "backup_targets": [
    "/etc/ssh/sshd_config"
  ],
  "remediation_script": "#!/usr/bin/env bash\nset -euo pipefail\nBACKUP_DIR=\"/var/backups/q-shields/job-550e8400-e29b-41d4-a716-446655440000\"\nmkdir -p \"$BACKUP_DIR\"\ncp -a /etc/ssh/sshd_config \"$BACKUP_DIR/sshd_config.bak\"\nsha256sum \"$BACKUP_DIR/sshd_config.bak\" > \"$BACKUP_DIR/manifest.sha256\"\n# Apply change + validate + auto-revert on failure...",
  "validation_script": "#!/usr/bin/env bash\nsshd -t && grep -Eq '^PermitRootLogin\\s+no' /etc/ssh/sshd_config",
  "rollback_script": "#!/usr/bin/env bash\nset -euo pipefail\nBACKUP_DIR=\"/var/backups/q-shields/job-550e8400-e29b-41d4-a716-446655440000\"\nsha256sum -c \"$BACKUP_DIR/manifest.sha256\"\ncp -a \"$BACKUP_DIR/sshd_config.bak\" /etc/ssh/sshd_config\nsystemctl reload sshd"
}
```
