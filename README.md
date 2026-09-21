# PostgreSQL 18 mTLS + pgcrypto Demo

Demo การเชื่อมต่อ PostgreSQL 18 ด้วย **mTLS** (mutual TLS) จาก PHP web app รันผ่าน nginx + php-fpm โดยข้อมูล sensitive เข้ารหัสด้วย **pgcrypto** (`pgp_sym_encrypt` / AES-256)

## สถาปัตยกรรม

```
                       ┌──────────────────── backend (internal, ไม่มีเน็ตออก) ────────────────────┐
                       │                                                                          │
Browser ──8180/8444──> │  Web App Portal (nginx + php-fpm)  ──mTLS:5432 (CN=webapp)──> PostgreSQL │
                       │        │                                                          ▲      │
                       │        └── proxy /api.php ──TLS──┐                                │      │
                       │                                  ▼                                │      │
API client ──8446────> │              API APP (nginx + php-fpm)  ──mTLS:5432 (CN=apiapp)───┘      │
                       │                                                                          │
                       │  Web App Portal ──TLS:9443──> garage-tls ──unix socket──> Garage (S3)    │
                       └──────────────────────────────────────────────────────────────────────────┘
```

- **mTLS** ระหว่าง PHP กับ PostgreSQL (client cert required, `sslmode=verify-full`) — เว็บพอร์ทัลและ API ใช้ **client cert คนละใบ** (`CN=webapp` / `CN=apiapp`) map เป็น `appuser` ผ่าน `db/pg_ident.conf`
- **pgcrypto** เข้ารหัสฟิลด์ `name`, `email`, `phone` ด้วย `pgp_sym_encrypt` (AES-256) + HMAC สำหรับค้นหา
- **Object storage** (Garage) เข้ารหัสด้วย **SSE-C** และเข้าถึงได้เฉพาะเว็บพอร์ทัล — API ไม่มีสิทธิ์และไม่มี S3 config
- **API APP แยก container/ image ของตัวเอง**: image มีแค่ `api.php`, `crud.php`, `db.php`, `mask.php` ไม่มีหน้า UI และเปิดเฉพาะ TLS

### พอร์ต

| พอร์ต (host) | บริการ |
|---|---|
| `8180` | Web App Portal (HTTP — redirect ไป HTTPS) |
| `8444` | Web App Portal (HTTPS, TLS 1.3 + PQC hybrid) |
| `8446` | **API APP** (HTTPS, cert `CN=api` ออกโดย DemoCA) |

ทุกพอร์ตผูกกับ `127.0.0.1`/`[::1]` เท่านั้น ส่วน PostgreSQL, Garage และ garage-tls ไม่เปิดพอร์ตออก host เลย

## ขั้นตอนการรัน

### 1. ตั้งค่า `.env`

```bash
cp .env.example .env
```

แล้วเติมค่าให้ครบทุกบรรทัดที่เว้นว่างไว้ (สุ่มค่าได้ด้วย `openssl rand -base64 32` ส่วน `GARAGE_RPC_SECRET` ต้องเป็น hex — ใช้ `openssl rand -hex 32`)

### 2. สร้างใบรับรอง (CA + server cert + client cert)

```bash
chmod +x certs/generate-certs.sh
./certs/generate-certs.sh
```

สคริปต์จะสร้าง:
- `db/certs/` — CA, server cert, server key (สำหรับ PostgreSQL)
- `web/certs/` — CA, client cert, client key (สำหรับ PHP)

### 3. รันด้วย Docker Compose

```bash
docker compose up --build
```

### 4. เปิดเว็บ

```
http://localhost:8180
```

## ฟีเจอร์ของแอป

- **เพิ่มผู้ใช้** — กรอกชื่อ, email, เบอร์โทร → ข้อมูลถูกเข้ารหัส AES-256 ก่อนเก็บ
- **ดูรายการ** — แสดงข้อมูลหลังถอดรหัสด้วย `pgp_sym_decrypt`
- **แก้ไข** — อัปเดตข้อมูล (เข้ารหัสใหม่)
- **ลบ** — ลบผู้ใช้

## ไฟล์สำคัญ

| ไฟล์ | รายละเอียด |
|------|-----------|
| `docker-compose.yml` | 5 services: `db` (postgres:18), `web` (พอร์ทัล), `api` (REST API), `garage` + `garage-tls` (object storage) |
| `.env` | รหัสผ่าน + pgcrypto encryption key (ไม่ขึ้น git — ดูตัวอย่างที่ `.env.example`) |
| `certs/generate-certs.sh` | สคริปต์สร้าง CA, server cert, client cert |
| `db/postgresql.conf` | เปิด SSL + ระบุ cert files |
| `db/pg_hba.conf` | บังคับ `hostssl` + `clientcert=verify-full` |
| `db/init.sql` | สร้าง `pgcrypto` extension + ตาราง `users` |
| `Dockerfile` | image ของเว็บพอร์ทัล: PHP 8.3 + nginx + pdo_pgsql (ไม่รวม `api.php`) |
| `api/Dockerfile` | image ของ API APP: PHP 8.3 + nginx + pdo_pgsql เฉพาะไฟล์ที่ API ใช้ |
| `api/nginx.conf` | TLS-only, เสิร์ฟเฉพาะ `/api.php/*` + `/health` path อื่นตอบ 404 |
| `api/entrypoint.sh` | เตรียม client cert (`CN=apiapp`) + session dir แยกจากเว็บพอร์ทัล |
| `db/pg_ident.conf` | map CN ของ client cert (`webapp`, `apiapp`) → `appuser` |
| `web/html/db.php` | PDO connection ด้วย `sslmode=verify-full` + client cert |
| `web/html/crud.php` | CRUD functions พร้อม `pgp_sym_encrypt`/`pgp_sym_decrypt` |
| `web/html/index.php` | UI (TailwindCSS) สำหรับเพิ่ม/แก้ไข/ลบ/ดูผู้ใช้ |

## ทดสอบว่า mTLS ทำงาน

ลองเชื่อมต่อ PostgreSQL โดยไม่ใช้ client cert จะถูกปฏิเสธ:

```bash
docker exec -it pg18-demo-db psql -U appuser -d appdb -h localhost
# จะ fail เพราะไม่มี client cert
```

ดู log ของ PostgreSQL:

```bash
docker logs pg18-demo-db 2>&1 | grep SSL
```

## ทดสอบ REST API

API รันเป็น service แยก เรียกได้ 2 ทาง:

```bash
# 1) เรียกตรงที่ API APP (cert ออกโดย DemoCA)
curl --cacert api/certs/ca.crt https://localhost:8446/health
curl --cacert api/certs/ca.crt -H "Authorization: Bearer <token>" \
     https://localhost:8446/api.php/users

# 2) ผ่านเว็บพอร์ทัล (reverse proxy ไป API ด้วย TLS + proxy_ssl_verify)
curl -k -H "Authorization: Bearer <token>" https://localhost:8444/api.php/users
```

API token เริ่มต้นเป็น token แบบใช้ครั้งเดียว อายุ 10 นาที (สร้างตอน seed) — ออก token ใหม่ได้ที่หน้า Settings ของเว็บพอร์ทัล

## หมายเหตุ

- Encryption key เก็บใน `.env` (สำหรับ demo เท่านั้น — production ควรใช้ KMS)
- เว็บพอร์ทัลกับ API แชร์ volume `/tmp` เพื่อให้ key rotation ที่ทำจากพอร์ทัลมีผลกับ API ด้วย (ในระบบจริงคือหน้าที่ของ KMS) — cert และ session directory แยกกันคนละชุด
- PostgreSQL 18 image ใช้ `postgres:18` (official Docker Hub)
- ทุกอย่างรันใน Docker ไม่ต้องติดตั้งอะไรบน host นอกจาก Docker
