<?php

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/mask.php';

function createUser(string $name, string $email, string $phone, ?string $profilePicData = null, ?string $profilePicMime = null): int
{
    $pdo = getDb();
    $key = getCryptoKey();

    if ($profilePicData !== null) {
        $picHex = bin2hex($profilePicData);
        $sql = "INSERT INTO users (name_encrypted, email_encrypted, phone_encrypted, email_hmac, phone_hmac, profile_picture_encrypted, profile_picture_mime)
                VALUES (pgp_sym_encrypt(:name, :key, 'cipher-algo=aes256'), pgp_sym_encrypt(:email, :key, 'cipher-algo=aes256'), pgp_sym_encrypt(:phone, :key, 'cipher-algo=aes256'),
                        hmac(:email, :key, 'sha256'), hmac(:phone, :key, 'sha256'),
                        pgp_sym_encrypt_bytea(decode(:pic, 'hex'), :key, 'cipher-algo=aes256'), :mime)
                RETURNING id";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':name'  => $name,
            ':email' => $email,
            ':phone' => $phone,
            ':key'   => $key,
            ':pic'   => $picHex,
            ':mime'  => $profilePicMime,
        ]);
    } else {
        $sql = "INSERT INTO users (name_encrypted, email_encrypted, phone_encrypted, email_hmac, phone_hmac)
                VALUES (pgp_sym_encrypt(:name, :key, 'cipher-algo=aes256'), pgp_sym_encrypt(:email, :key, 'cipher-algo=aes256'), pgp_sym_encrypt(:phone, :key, 'cipher-algo=aes256'),
                        hmac(:email, :key, 'sha256'), hmac(:phone, :key, 'sha256'))
                RETURNING id";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':name'  => $name,
            ':email' => $email,
            ':phone' => $phone,
            ':key'   => $key,
        ]);
    }

    return (int) $stmt->fetchColumn();
}

function auditLog(string $action, ?int $recordId, string $detail): void
{
    $pdo = getDb();
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $pdo->prepare("INSERT INTO audit_log (action, record_id, detail, ip_address) VALUES (:action, :rid, :detail, :ip)");
    $stmt->execute([':action' => $action, ':rid' => $recordId, ':detail' => $detail, ':ip' => $ip]);
}

function getAllUsers(): array
{
    $pdo = getDb();
    $key = getCryptoKey();

    $sql = "SELECT id,
                   pgp_sym_decrypt(name_encrypted, :key)  AS name,
                   pgp_sym_decrypt(email_encrypted, :key) AS email,
                   pgp_sym_decrypt(phone_encrypted, :key) AS phone,
                   profile_picture_mime AS has_profile_pic,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
            FROM users
            ORDER BY id DESC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':key' => $key]);

    return $stmt->fetchAll();
}

function getUser(int $id): ?array
{
    $pdo = getDb();
    $key = getCryptoKey();

    $sql = "SELECT id,
                   pgp_sym_decrypt(name_encrypted, :key)  AS name,
                   pgp_sym_decrypt(email_encrypted, :key) AS email,
                   pgp_sym_decrypt(phone_encrypted, :key) AS phone,
                   profile_picture_mime AS has_profile_pic
            FROM users WHERE id = :id";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':id' => $id, ':key' => $key]);

    $row = $stmt->fetch();
    return $row ?: null;
}

function updateUser(int $id, string $name, string $email, string $phone, ?string $profilePicData = null, ?string $profilePicMime = null): bool
{
    $pdo = getDb();
    $key = getCryptoKey();

    if ($profilePicData !== null) {
        $picHex = bin2hex($profilePicData);
        $sql = "UPDATE users
                SET name_encrypted  = pgp_sym_encrypt(:name, :key, 'cipher-algo=aes256'),
                    email_encrypted = pgp_sym_encrypt(:email, :key, 'cipher-algo=aes256'),
                    phone_encrypted = pgp_sym_encrypt(:phone, :key, 'cipher-algo=aes256'),
                    email_hmac      = hmac(:email, :key, 'sha256'),
                    phone_hmac      = hmac(:phone, :key, 'sha256'),
                    profile_picture_encrypted = pgp_sym_encrypt_bytea(decode(:pic, 'hex'), :key, 'cipher-algo=aes256'),
                    profile_picture_mime      = :mime
                WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':id'    => $id,
            ':name'  => $name,
            ':email' => $email,
            ':phone' => $phone,
            ':key'   => $key,
            ':pic'   => $picHex,
            ':mime'  => $profilePicMime,
        ]);
    } else {
        $sql = "UPDATE users
                SET name_encrypted  = pgp_sym_encrypt(:name, :key, 'cipher-algo=aes256'),
                    email_encrypted = pgp_sym_encrypt(:email, :key, 'cipher-algo=aes256'),
                    phone_encrypted = pgp_sym_encrypt(:phone, :key, 'cipher-algo=aes256'),
                    email_hmac      = hmac(:email, :key, 'sha256'),
                    phone_hmac      = hmac(:phone, :key, 'sha256')
                WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':id'    => $id,
            ':name'  => $name,
            ':email' => $email,
            ':phone' => $phone,
            ':key'   => $key,
        ]);
    }
    return $stmt->rowCount() > 0;
}

function getUserProfilePicture(int $id): ?array
{
    $pdo = getDb();
    $key = getCryptoKey();
    $sql = "SELECT pgp_sym_decrypt_bytea(profile_picture_encrypted, :key) AS pic, profile_picture_mime AS mime
            FROM users WHERE id = :id AND profile_picture_encrypted IS NOT NULL";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':id' => $id, ':key' => $key]);
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }
    $pic = $row['pic'];
    if (is_resource($pic)) {
        $pic = stream_get_contents($pic);
    }
    return ['pic' => $pic, 'mime' => $row['mime']];
}

function deleteUser(int $id): bool
{
    $pdo = getDb();
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
    $stmt->execute([':id' => $id]);
    return $stmt->rowCount() > 0;
}

function searchByHmac(string $field, string $value): array
{
    $pdo = getDb();
    $key = getCryptoKey();
    $allowed = ['email' => 'email_hmac', 'phone' => 'phone_hmac'];
    if (!isset($allowed[$field])) {
        return [];
    }
    $col = $allowed[$field];
    $sql = "SELECT id,
                   pgp_sym_decrypt(name_encrypted, :key)  AS name,
                   pgp_sym_decrypt(email_encrypted, :key) AS email,
                   pgp_sym_decrypt(phone_encrypted, :key) AS phone,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
            FROM users WHERE {$col} = hmac(:value, :key, 'sha256')
            ORDER BY id DESC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':key' => $key, ':value' => $value]);
    return $stmt->fetchAll();
}

function searchByDecrypt(string $field, string $value): array
{
    $pdo = getDb();
    $key = getCryptoKey();
    $allowed = ['email' => 'email_encrypted', 'phone' => 'phone_encrypted'];
    if (!isset($allowed[$field])) {
        return [];
    }
    $col = $allowed[$field];
    $sql = "SELECT id,
                   pgp_sym_decrypt(name_encrypted, :key)  AS name,
                   pgp_sym_decrypt(email_encrypted, :key) AS email,
                   pgp_sym_decrypt(phone_encrypted, :key) AS phone,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
            FROM users WHERE pgp_sym_decrypt({$col}, :key) = :value
            ORDER BY id DESC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':key' => $key, ':value' => $value]);
    return $stmt->fetchAll();
}

function getAuditLogs(int $limit = 50): array
{
    $pdo = getDb();
    $sql = "SELECT id, action, table_name, record_id, detail, ip_address,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
            FROM audit_log ORDER BY id DESC LIMIT :limit";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':limit' => $limit]);
    return $stmt->fetchAll();
}

function getKeyHistory(): array
{
    $pdo = getDb();
    $sql = "SELECT id, key_label, key_hash,
                   to_char(rotated_at, 'YYYY-MM-DD HH24:MI:SS') AS rotated_at,
                   rotated_by
            FROM key_history ORDER BY id DESC";
    return $pdo->query($sql)->fetchAll();
}

function rotateKey(string $oldKey, string $newKey, string $label): array
{
    $pdo = getDb();

    $pdo->beginTransaction();
    try {
        // Re-encrypt text fields + update HMAC
        $sql = "UPDATE users
                SET name_encrypted  = pgp_sym_encrypt(pgp_sym_decrypt(name_encrypted, :oldkey), :newkey, 'cipher-algo=aes256'),
                    email_encrypted = pgp_sym_encrypt(pgp_sym_decrypt(email_encrypted, :oldkey), :newkey, 'cipher-algo=aes256'),
                    phone_encrypted = pgp_sym_encrypt(pgp_sym_decrypt(phone_encrypted, :oldkey), :newkey, 'cipher-algo=aes256'),
                    email_hmac      = hmac(pgp_sym_decrypt(email_encrypted, :oldkey), :newkey, 'sha256'),
                    phone_hmac      = hmac(pgp_sym_decrypt(phone_encrypted, :oldkey), :newkey, 'sha256')";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':oldkey' => $oldKey, ':newkey' => $newKey]);

        $count = $stmt->rowCount();

        // Re-encrypt profile pictures (bytea) — only for rows that have one
        $sqlPic = "UPDATE users
                   SET profile_picture_encrypted = pgp_sym_encrypt_bytea(
                       pgp_sym_decrypt_bytea(profile_picture_encrypted, :oldkey),
                       :newkey, 'cipher-algo=aes256')
                   WHERE profile_picture_encrypted IS NOT NULL";
        $stmtPic = $pdo->prepare($sqlPic);
        $stmtPic->execute([':oldkey' => $oldKey, ':newkey' => $newKey]);
        $picCount = $stmtPic->rowCount();

        $hash = hash('sha256', $newKey);
        $stmt2 = $pdo->prepare("INSERT INTO key_history (key_label, key_hash, rotated_by) VALUES (:label, :hash, :by)");
        $stmt2->execute([':label' => $label, ':hash' => $hash, ':by' => 'web-admin']);

        // Staging: write new key to .new files WITHOUT touching originals.
        // If commit fails, originals are intact and match the rolled-back DB.
        $tempKeyFile = '/tmp/.crypto_key.new';
        $tempBackupFile = '/run/app-data/.crypto_key_backup.new';

        if (file_put_contents($tempKeyFile, $newKey) === false) {
            throw new RuntimeException('Cannot write temp key file — aborting rotation');
        }
        chmod($tempKeyFile, 0600);
        chown($tempKeyFile, 'www-data');

        if (file_put_contents($tempBackupFile, $newKey) === false) {
            @unlink($tempKeyFile);
            throw new RuntimeException('Cannot write staging backup key file — aborting rotation (DB unchanged)');
        }
        chmod($tempBackupFile, 0600);
        chown($tempBackupFile, 'www-data');

        // Commit DB — staging files are ready, originals still have old key
        $pdo->commit();
        $committed = true;

        // After commit, DB uses new key. We must ensure the app can read it.
        // Always update cache/env so this request uses the new key immediately.
        $GLOBALS['__crypto_key_cache'] = $newKey;
        putenv("PGCRYPTO_KEY={$newKey}");

        // Promote backup first: atomic rename .new → final
        $backupKeyFile = '/run/app-data/.crypto_key_backup';
        $backupPromoted = rename($tempBackupFile, $backupKeyFile);

        // Promote runtime: atomic rename .new → final
        $runtimePromoted = rename($tempKeyFile, '/tmp/.crypto_key');

        if ($backupPromoted && $runtimePromoted) {
            // Both promoted successfully.
            clearSettingCache();
            return ['success' => true, 'reencrypted' => $count, 'pics_reencrypted' => $picCount];
        }

        if ($backupPromoted && !$runtimePromoted) {
            // Backup has new key, runtime rename failed.
            // Remove stale runtime so getCryptoKey() falls through to backup.
            @unlink('/tmp/.crypto_key');
            // Also clean up temp if rename left it behind
            if (file_exists($tempKeyFile)) {
                @unlink($tempKeyFile);
            }
            error_log('CRITICAL: Key rotation committed, backup promoted, but runtime rename failed. Removed stale runtime — getCryptoKey() will use backup. Manual: copy ' . $backupKeyFile . ' to /tmp/.crypto_key');
            clearSettingCache();
            return ['success' => false, 'error' => 'Key rotation committed but runtime file update failed — getCryptoKey() will use backup. Manual intervention: copy ' . $backupKeyFile . ' to /tmp/.crypto_key'];
        }

        if (!$backupPromoted && $runtimePromoted) {
            // Runtime has new key, backup rename failed.
            // Staging backup .new still exists — try writing directly.
            $directBackupOk = false;
            if (file_exists($tempBackupFile)) {
                $writeOk = (file_put_contents($backupKeyFile, $newKey) !== false);
                if ($writeOk) {
                    @chmod($backupKeyFile, 0600);
                    @chown($backupKeyFile, 'www-data');
                    // Verify by reading back and comparing hash
                    $verify = @file_get_contents($backupKeyFile);
                    if ($verify !== false && hash('sha256', trim($verify)) === hash('sha256', $newKey)) {
                        $directBackupOk = true;
                        @unlink($tempBackupFile);
                    }
                }
            }
            if (!$directBackupOk) {
                // Direct write failed or verification failed — keep staging file as recovery source
                error_log('CRITICAL: Key rotation committed, runtime promoted, but backup direct write failed. Staging backup kept at ' . $tempBackupFile . ' for recovery. Manual: copy ' . $tempBackupFile . ' to ' . $backupKeyFile);
                clearSettingCache();
                return ['success' => false, 'error' => 'Key rotation committed, runtime updated, but backup write failed. Staging backup at ' . $tempBackupFile . ' — manual recovery needed: copy to ' . $backupKeyFile];
            }
            error_log('CRITICAL: Key rotation committed, runtime promoted, backup rename failed but direct write succeeded.');
            clearSettingCache();
            return ['success' => false, 'error' => 'Key rotation committed, runtime updated, backup promotion failed — direct write succeeded. Manual: verify ' . $backupKeyFile];
        }

        // Both promotions failed.
        // DB has new key, both originals have old key, staging files may still exist.
        // Last resort: write new key directly to runtime and backup.
        // Verify each write before deleting the corresponding staging file.
        $runtimeDirectOk = false;
        $backupDirectOk = false;

        $writeRt = @file_put_contents('/tmp/.crypto_key', $newKey);
        if ($writeRt !== false) {
            @chmod('/tmp/.crypto_key', 0600);
            @chown('/tmp/.crypto_key', 'www-data');
            $verifyRt = @file_get_contents('/tmp/.crypto_key');
            if ($verifyRt !== false && hash('sha256', trim($verifyRt)) === hash('sha256', $newKey)) {
                $runtimeDirectOk = true;
            }
        }

        $writeBk = @file_put_contents($backupKeyFile, $newKey);
        if ($writeBk !== false) {
            @chmod($backupKeyFile, 0600);
            @chown($backupKeyFile, 'www-data');
            $verifyBk = @file_get_contents($backupKeyFile);
            if ($verifyBk !== false && hash('sha256', trim($verifyBk)) === hash('sha256', $newKey)) {
                $backupDirectOk = true;
            }
        }

        // Only clean up staging files that have a verified direct-write replacement
        if ($runtimeDirectOk && file_exists($tempKeyFile)) {
            @unlink($tempKeyFile);
        }
        if ($backupDirectOk && file_exists($tempBackupFile)) {
            @unlink($tempBackupFile);
        }

        if (!$runtimeDirectOk && !$backupDirectOk) {
            // All filesystem writes failed. DB has new key but no accessible key file.
            // Staging files are the only recovery source — do NOT delete them.
            error_log('CRITICAL: Key rotation committed but all filesystem writes failed. DB uses new key, no key file accessible. Staging files kept: ' . $tempKeyFile . ', ' . $tempBackupFile . '. Manual recovery: copy staging file to /tmp/.crypto_key and ' . $backupKeyFile);
            clearSettingCache();
            return ['success' => false, 'error' => 'Key rotation committed but all filesystem writes failed. Staging files kept for recovery: ' . $tempKeyFile . ', ' . $tempBackupFile . ' — URGENT manual intervention required'];
        }

        $errorMsg = 'Key rotation committed but both atomic renames failed — ';
        $errorMsg .= $runtimeDirectOk ? 'runtime direct write OK' : 'runtime direct write FAILED (staging kept at ' . $tempKeyFile . ')';
        $errorMsg .= ', ';
        $errorMsg .= $backupDirectOk ? 'backup direct write OK' : 'backup direct write FAILED (staging kept at ' . $tempBackupFile . ')';
        error_log('CRITICAL: ' . $errorMsg . '. Manual: verify /tmp/.crypto_key and ' . $backupKeyFile);
        clearSettingCache();
        return ['success' => false, 'error' => $errorMsg];
    } catch (Throwable $e) {
        // Only rollback if transaction is still active (not yet committed)
        if (!isset($committed) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        // Clean up ALL staging files so stale data doesn't linger.
        // Originals are untouched if we failed before commit.
        if (isset($tempKeyFile) && file_exists($tempKeyFile)) {
            @unlink($tempKeyFile);
        }
        if (isset($tempBackupFile) && file_exists($tempBackupFile)) {
            @unlink($tempBackupFile);
        }
        // If we committed but failed after, both originals may or may not be promoted.
        // Backup has new key (matches DB) if promoted, old key if not yet promoted.
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function verifyApiKey(string $token): bool
{
    $pdo = getDb();
    $hash = hash('sha256', $token);
    // Atomic update + check in a single statement to prevent race condition.
    // Two concurrent requests cannot both pass: the first UPDATE sets used_at,
    // the second's WHERE clause (used_at IS NULL) fails.
    // Conditions: active, not expired, not already used (for one-time tokens).
    // For regular tokens (expires_at IS NULL): used_at is never set, reusable.
    $sql = "UPDATE api_tokens
            SET last_used_at = now(),
                used_at = CASE WHEN expires_at IS NOT NULL THEN now() ELSE used_at END
            WHERE token_hash = :hash
              AND is_active = true
              AND (expires_at IS NULL OR expires_at > now())
              AND (expires_at IS NULL OR used_at IS NULL)
            RETURNING id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':hash' => $hash]);
    $row = $stmt->fetch();
    if ($row) {
        return true;
    }
    // No row returned = token invalid, expired, or already used.
    // Check if it exists but is expired — deactivate it for cleanup.
    $check = $pdo->prepare("UPDATE api_tokens SET is_active = false
                            WHERE token_hash = :hash AND is_active = true
                              AND expires_at IS NOT NULL AND expires_at <= now()");
    $check->execute([':hash' => $hash]);
    return false;
}

function getAllUsersMasked(): array
{
    $users = getAllUsers();
    foreach ($users as &$u) {
        $u['name']  = maskName($u['name']);
        $u['email'] = maskEmail($u['email']);
        $u['phone'] = maskPhone($u['phone']);
    }
    unset($u);
    return $users;
}

function getAllUsersUnmasked(): array
{
    return getAllUsers();
}

function getAllSettings(): array
{
    $pdo = getDb();
    $sql = "SELECT key, value, description, is_secret,
                   to_char(updated_at, 'YYYY-MM-DD HH24:MI:SS') AS updated_at
            FROM app_settings ORDER BY key";
    return $pdo->query($sql)->fetchAll();
}

function updateSetting(string $key, string $value): void
{
    $pdo = getDb();
    $stmt = $pdo->prepare("UPDATE app_settings SET value = :value, updated_at = now() WHERE key = :key");
    $stmt->execute([':key' => $key, ':value' => $value]);
}

function getApiTokens(): array
{
    $pdo = getDb();
    $sql = "SELECT id, label, is_active,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at,
                   to_char(last_used_at, 'YYYY-MM-DD HH24:MI:SS') AS last_used_at
            FROM api_tokens ORDER BY id DESC";
    return $pdo->query($sql)->fetchAll();
}

function createApiToken(string $token, string $label): void
{
    $pdo = getDb();
    $hash = hash('sha256', $token);
    $stmt = $pdo->prepare("INSERT INTO api_tokens (token_hash, label) VALUES (:hash, :label)");
    $stmt->execute([':hash' => $hash, ':label' => $label]);
}

function toggleApiToken(int $id, bool $active): void
{
    $pdo = getDb();
    $stmt = $pdo->prepare("UPDATE api_tokens SET is_active = :active WHERE id = :id");
    $stmt->execute([':active' => $active, ':id' => $id]);
}

function addFileRecord(string $originalName, string $s3Key, string $mimeType, int $fileSize, string $sseKeyHash, ?int $userId = null, string $attachmentType = 'general'): int
{
    $pdo = getDb();
    $stmt = $pdo->prepare("INSERT INTO file_storage (user_id, original_name, s3_key, mime_type, file_size, sse_c_key_hash, attachment_type, uploaded_by)
                           VALUES (:uid, :name, :key, :mime, :size, :hash, :atype, :by) RETURNING id");
    $stmt->execute([
        ':uid'   => $userId,
        ':name'  => $originalName,
        ':key'   => $s3Key,
        ':mime'  => $mimeType,
        ':size'  => $fileSize,
        ':hash'  => $sseKeyHash,
        ':atype' => $attachmentType,
        ':by'    => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    ]);
    return (int) $stmt->fetchColumn();
}

function getFileRecords(): array
{
    $pdo = getDb();
    $sql = "SELECT id, user_id, original_name, s3_key, mime_type, file_size, sse_c_key_hash, attachment_type, uploaded_by,
                   to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
            FROM file_storage ORDER BY id DESC";
    return $pdo->query($sql)->fetchAll();
}

function getUserFiles(int $userId): array
{
    $pdo = getDb();
    $stmt = $pdo->prepare("SELECT id, user_id, original_name, s3_key, mime_type, file_size, sse_c_key_hash, attachment_type, uploaded_by,
                                  to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
                           FROM file_storage WHERE user_id = :uid ORDER BY id ASC");
    $stmt->execute([':uid' => $userId]);
    return $stmt->fetchAll();
}

function getFileRecord(int $id): ?array
{
    $pdo = getDb();
    $stmt = $pdo->prepare("SELECT id, user_id, original_name, s3_key, mime_type, file_size, sse_c_key_hash, attachment_type, uploaded_by,
                                  to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
                           FROM file_storage WHERE id = :id");
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function deleteFileRecord(int $id): void
{
    $pdo = getDb();
    $stmt = $pdo->prepare("DELETE FROM file_storage WHERE id = :id");
    $stmt->execute([':id' => $id]);
}

function deleteUserFiles(int $userId): array
{
    // Only SELECT file records — do NOT delete metadata here.
    // Caller must delete S3 objects first, then delete metadata per file.
    // This prevents orphaned S3 objects with no metadata for retry.
    $pdo = getDb();
    $stmt = $pdo->prepare("SELECT id, s3_key, original_name FROM file_storage WHERE user_id = :uid");
    $stmt->execute([':uid' => $userId]);
    return $stmt->fetchAll();
}
