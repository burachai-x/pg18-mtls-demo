# PostgreSQL 18 mTLS + pgcrypto Demo

Demo การเชื่อมต่อ PostgreSQL 18 ด้วย **mTLS** (mutual TLS) จาก PHP web app รันผ่าน nginx + php-fpm โดยข้อมูล sensitive เข้ารหัสด้วย **pgcrypto** (`pgp_sym_encrypt` / AES-256)

## สถาปัตยกรรม

```
                      ┌───────────────────── backend (internal, ไม่มีเน็ตออก) ─────────────────────┐
                      │                                                                            │
Browser ──80/443────> │  Web App Portal (nginx + php-fpm)  ──mTLS:5432 (CN=webapp)──> PostgreSQL   │
                      │       │                                                            ▲       │
                      │       └── proxy /api.php ──TLS:443──┐                              │       │
                      │                                     ▼                              │       │
API client ──8443───> │             API APP (nginx + php-fpm)  ──mTLS:5432 (CN=apiapp)─────┘       │
                      │                                                                            │
                      │  Web App Portal ──TLS:443──> garage-tls ──unix socket──> Garage (Object    │
                      │                                                           Storage, SSE-C)  │
                      └────────────────────────────────────────────────────────────────────────────┘
```

- **ยืนยันตัวตนสองปัจจัยที่ชั้นฐานข้อมูล** — ทุก connection ต้องมีทั้ง **client certificate** ที่ออกโดย DemoCA **และ** รหัสผ่าน SCRAM ของ role นั้น (`pg_hba`: `scram-sha-256` + `clientcert=verify-full`) ฝั่ง client ใช้ `sslmode=verify-full` จึงตรวจ server cert ด้วยอีกทาง
- เว็บพอร์ทัลและ API ใช้ **client cert คนละใบและ role คนละตัว** — `CN=webapp` ล็อกอินเป็น role `webapp`, `CN=apiapp` เป็น role `apiapp` (`clientcert=verify-full` บังคับให้ CN ตรงกับชื่อ role) ทั้งคู่เป็นสมาชิกของ role `appuser` ที่ถือสิทธิ์ตาราง
- **pgcrypto** เข้ารหัสฟิลด์ `name`, `email`, `phone` ด้วย `pgp_sym_encrypt` (AES-256) + HMAC สำหรับค้นหา
- **Object storage** (Garage) เข้ารหัสด้วย **SSE-C** และเข้าถึงได้เฉพาะเว็บพอร์ทัล — API ไม่มีสิทธิ์และไม่มี S3 config
- **API APP แยก container/ image ของตัวเอง**: image มีแค่ `api.php`, `crud.php`, `db.php`, `mask.php` ไม่มีหน้า UI และเปิดเฉพาะ TLS

### พอร์ต

| พอร์ต (host) | บริการ | ตัวแปรใน `.env` |
|---|---|---|
| `80` | Web App Portal (HTTP — redirect ไป HTTPS) | `HTTP_PORT` |
| `443` | Web App Portal (HTTPS, TLS 1.3 + PQC hybrid) | `HTTPS_PORT` |
| `8443` | **API APP** (HTTPS, cert `CN=api` ออกโดย DemoCA) | `API_PORT` |

ภายในเครือข่าย backend: **Object Storage = 443** (garage-tls), **Database = 5432** ตามผังด้านบน — ทั้งสองตัวไม่เปิดพอร์ตออก host เลย
ส่วนพอร์ตที่เปิดออก host ผูกกับ `127.0.0.1`/`[::1]` เท่านั้น

> API ใช้ `8443` เพราะพอร์ทัลถือ `443` บน host อยู่แล้ว (ภายใน container ทั้งคู่ฟัง `443`)
> ถ้าเครื่องมีอะไรใช้ 80/443 อยู่ ให้แก้ `HTTP_PORT` / `HTTPS_PORT` ใน `.env` แล้ว `docker compose up -d` ใหม่
> — container ผูก `:80`/`:443` ได้โดยไม่ต้องขอ capability `NET_BIND_SERVICE` เพราะตั้ง `net.ipv4.ip_unprivileged_port_start=0` ไว้ใน compose

## ขั้นตอนการรัน

ต้องมีบนเครื่อง: **Docker + Docker Compose**, `openssl`, `python3` (ใช้ตอน `setup.sh` สร้าง `.env`) — ตัวแอปทั้งหมดรันใน container

### เริ่มเร็ว (3 คำสั่ง)

```bash
git clone https://github.com/burachai-x/pg18-mtls-demo.git
cd pg18-mtls-demo
./setup.sh && docker compose up --build -d
```

`setup.sh` จะสร้าง `.env` พร้อมสุ่มความลับให้ทุกค่า (ไม่เขียนทับถ้ามีอยู่แล้ว) และออกใบรับรองทั้งสองชุด —
ของ PostgreSQL/API (DemoCA) และของ Garage TLS sidecar (CA ภายในอีกใบ) รันซ้ำได้ ถ้าอยากออกใบรับรองใหม่ใช้ `./setup.sh --force`

ครั้งแรกใช้เวลาราว 2 นาที (database init + seed) ตรวจว่าพร้อมด้วย:

```bash
docker compose ps          # db ต้องขึ้น (healthy)
```

จากนั้น:

| URL | ใช้ทำอะไร |
|---|---|
| `https://localhost` | เว็บพอร์ทัล (self-signed — ต้องกดยอมรับคำเตือน) |
| `https://localhost:8443/health` | เช็คว่า API APP พร้อม |
| `http://localhost` | redirect ไป HTTPS |

รหัสผ่านเข้าเว็บคือค่า `SETTINGS_ADMIN_PASSWORD` ในไฟล์ `.env`:

```bash
grep SETTINGS_ADMIN_PASSWORD .env
```

### ทำเอง (ถ้าไม่อยากใช้ setup.sh)

```bash
cp .env.example .env            # แล้วเติมค่าที่เว้นว่างเอง
                                # (openssl rand -base64 32; GARAGE_RPC_SECRET ใช้ openssl rand -hex 32)
./certs/generate-certs.sh       # db/certs, web/certs (CN=webapp), api/certs (CN=apiapp + CN=api)
./garage/tls/generate-garage-certs.sh   # garage/tls/certs (CA แยกของ object storage)
docker compose up --build
```

> ใบรับรองทั้งสองสคริปต์ออก CA ใหม่ทุกครั้งที่รัน แล้วลบ CA private key ทิ้ง — ถ้ารันซ้ำต้องรันครบชุดและ restart container ที่ mount ใบรับรองนั้น

## หน้าต่าง ๆ ในเว็บพอร์ทัล

ทุกหน้าต้อง login ด้วย `SETTINGS_ADMIN_PASSWORD` ก่อน

| หน้า | ทำอะไร |
|---|---|
| `index.php` | CRUD ผู้ใช้ — เพิ่ม/แก้ไข/ลบ/ดู (เข้ารหัส AES-256 ก่อนเก็บ, ถอดรหัสตอนแสดง) |
| `search.php` | ค้นหาข้อมูลที่เข้ารหัส — เทียบด้วย HMAC (ตรงตัว) กับแบบถอดรหัสทีละแถว |
| `upload.php` | อัปโหลดไฟล์เข้า object storage พร้อม SSE-C |
| `key-rotation.php` | หมุนคีย์ pgcrypto — เข้ารหัสข้อมูลทั้งตารางใหม่ + บันทึกประวัติคีย์ |
| `audit.php` | Audit log ของทุก action (รวม `API_CREATE` / `API_UPDATE` / `API_DELETE`) |
| `inspect.php` | วางข้อมูลใน DB (ciphertext + raw hex), ข้อมูลที่ถอดรหัสแล้ว และแบบ masked ไว้เทียบกัน |
| `backup.php` | ดาวน์โหลด backup ที่ข้อมูลยังเข้ารหัสอยู่ (ไฟล์ secrets แยกต่างหาก) + วิเคราะห์ไฟล์ backup |
| `mtls-test.php` | ทดลองต่อ PostgreSQL ทั้งแบบมีและไม่มี client cert ให้เห็นว่าฝั่งไม่มี cert ถูกปฏิเสธ |
| `sse-c-test.php` | ทดสอบ SSE-C 3 กรณี: คีย์ถูก → ได้ไฟล์ต้นฉบับ, ไม่ส่งคีย์ → ได้ ciphertext, คีย์ผิด → AccessDenied |
| `api-test.php` | ยิง REST API จากหน้าเว็บ (ผ่าน reverse proxy ไป API APP) |
| `settings.php` | login/logout, ออกและปิดใช้งาน API token, ตั้งค่า masking |

## ไฟล์สำคัญ

| ไฟล์ | รายละเอียด |
|------|-----------|
| `docker-compose.yml` | 5 services: `db` (postgres:18), `web` (พอร์ทัล), `api` (REST API), `garage` + `garage-tls` (object storage) |
| `.env` | รหัสผ่าน + pgcrypto encryption key (ไม่ขึ้น git — ดูตัวอย่างที่ `.env.example`) |
| `setup.sh` | เตรียม `.env` + ใบรับรองทั้งหมดให้พร้อมรันในคำสั่งเดียว |
| `certs/generate-certs.sh` | ออก DemoCA + cert ของ PostgreSQL, เว็บพอร์ทัล (CN=webapp) และ API (CN=apiapp, CN=api) |
| `garage/tls/generate-garage-certs.sh` | ออก CA ภายในอีกใบ + cert ของ garage-tls (คนละ trust domain กับ DemoCA) |
| `db/postgresql.conf` | เปิด SSL + ระบุ cert files |
| `db/pg_hba.conf` | บังคับ `hostssl` + `scram-sha-256` + `clientcert=verify-full` (cert + รหัสผ่าน) |
| `db/init.sql` | สร้าง `pgcrypto` extension + ตาราง `users` |
| `Dockerfile` | image ของเว็บพอร์ทัล: PHP 8.3 + nginx + pdo_pgsql (ไม่รวม `api.php`) |
| `api/Dockerfile` | image ของ API APP: PHP 8.3 + nginx + pdo_pgsql เฉพาะไฟล์ที่ API ใช้ |
| `api/nginx.conf` | TLS-only บน `:443` เสิร์ฟเฉพาะ `/api.php/*` + `/health` path อื่นตอบ 404 |
| `api/entrypoint.sh` | เตรียม client cert (`CN=apiapp`) + session dir แยกจากเว็บพอร์ทัล |
| `db/init-user.sh` | สร้าง role `appuser` (ถือสิทธิ์, ล็อกอินไม่ได้) + `webapp` / `apiapp` (ล็อกอิน, รหัสผ่านคนละตัว) |
| `web/html/db.php` | PDO connection ด้วย `sslmode=verify-full` + client cert |
| `web/html/crud.php` | CRUD functions พร้อม `pgp_sym_encrypt`/`pgp_sym_decrypt` |
| `web/html/index.php` | UI (TailwindCSS) สำหรับเพิ่ม/แก้ไข/ลบ/ดูผู้ใช้ |

## ทดสอบว่า mTLS ทำงาน

ลองเชื่อมต่อ PostgreSQL โดยไม่ใช้ client cert จะถูกปฏิเสธ:

```bash
docker exec -it pg18-demo-db psql -U webapp -d appdb -h 127.0.0.1
# FATAL: connection requires a valid client certificate
```

และถึงมี cert ถูกต้อง ถ้ารหัสผ่านผิดก็เข้าไม่ได้ (ปัจจัยที่สอง):

```bash
docker exec -e PGPASSWORD=wrong pg18-demo-web sh -c \
  'PGSSLMODE=verify-full PGSSLROOTCERT=/tmp/pg-certs/ca.crt \
   PGSSLCERT=/tmp/pg-certs/client.crt PGSSLKEY=/tmp/pg-certs/client.key \
   psql -h db -U webapp -d appdb -c "select 1"'
# FATAL: password authentication failed for user "webapp"
```

หน้า `mtls-test.php` ในเว็บรันชุดทดสอบนี้ให้ครบทุกกรณี (ไม่มี cert / cert ปลอม / CA ผิด / รหัสผ่านผิด)

ดู log ของ PostgreSQL:

```bash
docker logs pg18-demo-db 2>&1 | grep SSL
```

## ทดสอบ REST API

API รันเป็น service แยก เรียกได้ 2 ทาง:

```bash
# 1) เรียกตรงที่ API APP (cert ออกโดย DemoCA)
curl --cacert api/certs/ca.crt https://localhost:8443/health
curl --cacert api/certs/ca.crt -H "Authorization: Bearer <token>" \
     https://localhost:8443/api.php/users

# 2) ผ่านเว็บพอร์ทัล (reverse proxy ไป API ด้วย TLS + proxy_ssl_verify)
curl -k -H "Authorization: Bearer <token>" https://localhost/api.php/users
```

### เอา `<token>` มาจากไหน

1. เปิด `https://localhost` แล้ว login ด้วยค่า `SETTINGS_ADMIN_PASSWORD` ใน `.env`
2. ไปหน้า **Settings → API Tokens** ใส่ชื่อ label แล้วกดสร้าง
3. ระบบจะแสดง token (`tok_…`) **ครั้งเดียว** — คัดลอกเก็บไว้ทันที เพราะฐานข้อมูลเก็บแค่ SHA-256 hash

token ที่ seed ให้ตอนติดตั้งเป็นแบบ **ใช้ครั้งเดียว อายุ 10 นาที** จึงใช้ทดสอบซ้ำไม่ได้

## หยุด / ล้างข้อมูล

```bash
docker compose down        # หยุด container แต่เก็บข้อมูลไว้
docker compose down -v     # หยุด + ลบ volume ทั้งหมด (ข้อมูล, ไฟล์ใน object storage, คีย์ที่หมุนไว้)
```

> `down -v` แล้วเริ่มใหม่จะ seed ข้อมูลตัวอย่างชุดใหม่ให้เอง แต่ไฟล์ที่เคยอัปโหลดและคีย์ที่หมุนไปแล้วจะหายถาวร

## หมายเหตุ

- Encryption key เก็บใน `.env` (สำหรับ demo เท่านั้น — production ควรใช้ KMS)
- เว็บพอร์ทัลกับ API แชร์ volume `/tmp` เพื่อให้ key rotation ที่ทำจากพอร์ทัลมีผลกับ API ด้วย (ในระบบจริงคือหน้าที่ของ KMS) — cert และ session directory แยกกันคนละชุด
- PostgreSQL 18 image ใช้ `postgres:18` (official Docker Hub)
- ทุกอย่างรันใน Docker ไม่ต้องติดตั้งอะไรบน host นอกจาก Docker
