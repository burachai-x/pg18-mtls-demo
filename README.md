# PostgreSQL 18 mTLS + pgcrypto Demo

Demo การเชื่อมต่อ PostgreSQL 18 ด้วย **mTLS** (mutual TLS) จาก PHP web app รันผ่าน nginx + php-fpm โดยข้อมูล sensitive เข้ารหัสด้วย **pgcrypto** (`pgp_sym_encrypt` / AES-256)

## สถาปัตยกรรม

```
Browser ──HTTP:8180──> nginx + php-fpm ──mTLS:5432──> PostgreSQL 18
```

- **mTLS** เฉพาะระหว่าง PHP กับ PostgreSQL (client cert required, `sslmode=verify-full`)
- **pgcrypto** เข้ารหัสฟิลด์ `email` และ `phone` ด้วย `pgp_sym_encrypt` (AES-256)
- เว็บเปิดพอร์ต **8180**

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
| `docker-compose.yml` | 2 services: `db` (postgres:18) + `web` (nginx + php-fpm) |
| `.env` | รหัสผ่าน + pgcrypto encryption key (ไม่ขึ้น git — ดูตัวอย่างที่ `.env.example`) |
| `certs/generate-certs.sh` | สคริปต์สร้าง CA, server cert, client cert |
| `db/postgresql.conf` | เปิด SSL + ระบุ cert files |
| `db/pg_hba.conf` | บังคับ `hostssl` + `clientcert=verify-full` |
| `db/init.sql` | สร้าง `pgcrypto` extension + ตาราง `users` |
| `web/Dockerfile` | PHP 8.3 + nginx + pdo_pgsql + client certs |
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

## หมายเหตุ

- Encryption key เก็บใน `.env` (สำหรับ demo เท่านั้น — production ควรใช้ KMS)
- PostgreSQL 18 image ใช้ `postgres:18` (official Docker Hub)
- ทุกอย่างรันใน Docker ไม่ต้องติดตั้งอะไรบน host นอกจาก Docker
