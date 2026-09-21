-- Seed 10 sample users (all fields encrypted with pgp_sym_encrypt + HMAC for search)
-- Key comes from PGCRYPTO_KEY env var via psql variable (set by 00-init-user.sh)
\i /tmp/crypto_key_var.sql

INSERT INTO users (name_encrypted, email_encrypted, phone_encrypted, email_hmac, phone_hmac, created_at) VALUES
(pgp_sym_encrypt('สมชาย ใจดี', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('somchai.jaidee@gmail.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0812345678', :'crypto_key', 'cipher-algo=aes256'), hmac('somchai.jaidee@gmail.com', :'crypto_key', 'sha256'), hmac('0812345678', :'crypto_key', 'sha256'), '2024-01-15 09:30:00+07'),
(pgp_sym_encrypt('สมหญิง รักไทย', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('somying.rakthai@hotmail.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0898765432', :'crypto_key', 'cipher-algo=aes256'), hmac('somying.rakthai@hotmail.com', :'crypto_key', 'sha256'), hmac('0898765432', :'crypto_key', 'sha256'), '2024-02-20 14:15:00+07'),
(pgp_sym_encrypt('วิชัย สุขสันต์', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('wichai.suksan@company.co.th', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0623456789', :'crypto_key', 'cipher-algo=aes256'), hmac('wichai.suksan@company.co.th', :'crypto_key', 'sha256'), hmac('0623456789', :'crypto_key', 'sha256'), '2024-03-05 11:00:00+07'),
(pgp_sym_encrypt('ปนัสญา ศรีสุวรรณ', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('panasaya.srisuwan@email.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0912345678', :'crypto_key', 'cipher-algo=aes256'), hmac('panasaya.srisuwan@email.com', :'crypto_key', 'sha256'), hmac('0912345678', :'crypto_key', 'sha256'), '2024-03-18 16:45:00+07'),
(pgp_sym_encrypt('ธีรพงศ์ เจริญสุข', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('theerapong.charoen@gmail.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0876543210', :'crypto_key', 'cipher-algo=aes256'), hmac('theerapong.charoen@gmail.com', :'crypto_key', 'sha256'), hmac('0876543210', :'crypto_key', 'sha256'), '2024-04-01 08:20:00+07'),
(pgp_sym_encrypt('นภาพร แสงจันทร์', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('napaporn.saengchan@yahoo.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0855551234', :'crypto_key', 'cipher-algo=aes256'), hmac('napaporn.saengchan@yahoo.com', :'crypto_key', 'sha256'), hmac('0855551234', :'crypto_key', 'sha256'), '2024-04-22 13:30:00+07'),
(pgp_sym_encrypt('กิตติพงศ์ พลายงาม', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('kittipong.plaiyngam@org.co.th', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0987654321', :'crypto_key', 'cipher-algo=aes256'), hmac('kittipong.plaiyngam@org.co.th', :'crypto_key', 'sha256'), hmac('0987654321', :'crypto_key', 'sha256'), '2024-05-10 10:10:00+07'),
(pgp_sym_encrypt('อรุณรัตน์ ทองดี', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('arunrat.thongdee@gmail.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0634567890', :'crypto_key', 'cipher-algo=aes256'), hmac('arunrat.thongdee@gmail.com', :'crypto_key', 'sha256'), hmac('0634567890', :'crypto_key', 'sha256'), '2024-05-28 15:50:00+07'),
(pgp_sym_encrypt('ภาณุพงศ์ วงศ์ไพบูลย์', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('panupong.wongpaiboon@email.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0823456789', :'crypto_key', 'cipher-algo=aes256'), hmac('panupong.wongpaiboon@email.com', :'crypto_key', 'sha256'), hmac('0823456789', :'crypto_key', 'sha256'), '2024-06-12 09:00:00+07'),
(pgp_sym_encrypt('ศิริพร มั่นคง', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('siriporn.mankong@hotmail.com', :'crypto_key', 'cipher-algo=aes256'), pgp_sym_encrypt('0945678901', :'crypto_key', 'cipher-algo=aes256'), hmac('siriporn.mankong@hotmail.com', :'crypto_key', 'sha256'), hmac('0945678901', :'crypto_key', 'sha256'), '2024-06-30 17:25:00+07');

-- Seed initial key history
INSERT INTO key_history (key_label, key_hash, rotated_at, rotated_by) VALUES
('initial-key-v1', encode(digest(:'crypto_key', 'sha256'), 'hex'), '2024-01-01 00:00:00+07', 'system');

-- Generate random API token and write to a file (not to PG log — prevents exposure via docker logs)
DO $$
DECLARE
    generated_token TEXT;
BEGIN
    generated_token := 'tok_' || encode(gen_random_bytes(24), 'hex');
    -- One-time bootstrap token: expires in 10 minutes, disabled on first use
    INSERT INTO api_tokens (token_hash, label, is_active, expires_at) VALUES
    (encode(digest(generated_token, 'sha256'), 'hex'), 'Initial API Token (one-time, 10min expiry)', true, now() + interval '10 minutes');
    -- Write token to a file via temp table + COPY
    -- Permission is set to 600 via \! chmod after COPY (COPY defaults to 644)
    -- Synchronous cleanup: sleep 60 + rm below (no background process = no zombie)
    -- Token is one-time use (used_at set on first API call) and expires in 10 minutes
    -- Read with: docker exec pg18-demo-db cat /tmp/initial_api_token (within 60s of file appearing)
    EXECUTE 'CREATE TEMP TABLE _token_out (t TEXT)';
    EXECUTE 'INSERT INTO _token_out VALUES ($1)' USING generated_token;
    EXECUTE 'COPY _token_out TO ''/tmp/initial_api_token''';
    DROP TABLE _token_out;
END $$;

-- Set restrictive permissions on token file (COPY creates 644 by default)
\! chmod 600 /tmp/initial_api_token

-- Synchronous cleanup: wait 60s for admin to retrieve token, then delete.
-- This runs only during fresh init (seed.sql doesn't run on restart).
-- Adds 60s to fresh init but avoids background process zombie under runuser.
-- Token also has one-time use (used_at) + 10-minute expiry in DB as backup.
\! echo "[seed] Token file ready at /tmp/initial_api_token — waiting 60s for retrieval..."
\! sleep 60
\! rm -f /tmp/initial_api_token
\! echo "[seed] Deleted /tmp/initial_api_token (auto-cleanup)"

-- Seed application settings
-- Secrets are NOT seeded here — they come from environment variables:
--   crypto_key, reveal_password, settings_admin_password → env vars (not in DB)
--   s3_key_id, s3_secret_key → set at runtime by garage-init.php (reads from shared volume)
--   s3_encryption_key → env var S3_SSE_C_KEY (not in DB)
INSERT INTO app_settings (key, value, description, is_secret) VALUES
('default_masking', 'true', 'เปิด masking เป็นค่าเริ่มต้น (true/false)', false);
