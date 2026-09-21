<?php

function getDb(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $host = getenv('DB_HOST') ?: 'db';
    $port = getenv('DB_PORT') ?: '5432';
    $dbname = getenv('DB_NAME') ?: 'appdb';
    $user   = getenv('DB_USER') ?: 'appuser';

    // Cert directory is configurable so the API service can keep its own
    // client identity (CN=apiapp) separate from the web portal's (CN=webapp).
    $certDir     = rtrim(getenv('PG_CERT_DIR') ?: '/tmp/pg-certs', '/');
    $sslRootCert = $certDir . '/ca.crt';
    $sslCert     = $certDir . '/client.crt';
    $sslKey      = $certDir . '/client.key';

    $dsn = "pgsql:host={$host};port={$port};dbname={$dbname};"
         . "sslmode=verify-full;"
         . "sslrootcert={$sslRootCert};"
         . "sslcert={$sslCert};"
         . "sslkey={$sslKey}";

    try {
        $pdo = new PDO($dsn, $user, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (PDOException $e) {
        error_log('DB connection failed: ' . $e->getMessage());
        http_response_code(500);
        die('Database connection failed. Please try again later.');
    }

    return $pdo;
}

function getSetting(string $key, string $fallback = ''): string
{
    if (!isset($GLOBALS['__setting_cache'])) {
        $GLOBALS['__setting_cache'] = [];
    }
    $cache = &$GLOBALS['__setting_cache'];
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    try {
        $pdo = getDb();
        $stmt = $pdo->prepare("SELECT value FROM app_settings WHERE key = :key");
        $stmt->execute([':key' => $key]);
        $row = $stmt->fetch();
        if ($row) {
            $cache[$key] = $row['value'];
            return $row['value'];
        }
    } catch (Throwable $e) {
        // DB not ready yet — fall through to env/default
    }
    $cache[$key] = $fallback;
    return $fallback;
}

function clearSettingCache(): void
{
    $GLOBALS['__setting_cache'] = [];
    // Also clear crypto key cache so next getCryptoKey() re-reads from file
    $GLOBALS['__crypto_key_cache'] = null;
}

function getCryptoKey(): string
{
    // Global cache (clearable by clearSettingCache) — set directly by rotateKey()
    // so the same request uses the new key immediately after rotation.
    $cachedKey = $GLOBALS['__crypto_key_cache'] ?? null;
    if ($cachedKey !== null) {
        return $cachedKey;
    }

    // Check runtime file first (updated by key rotation via atomic rename)
    $runtimeKeyFile = '/tmp/.crypto_key';
    if (is_file($runtimeKeyFile) && is_readable($runtimeKeyFile)) {
        $key = trim(file_get_contents($runtimeKeyFile));
        if ($key !== '') {
            $GLOBALS['__crypto_key_cache'] = $key;
            return $key;
        }
    }
    // Check persistent backup on webrun volume — survives webtmp volume loss.
    // Also serves as fallback when runtime file is stale or missing after
    // a failed rename in key rotation (backup is promoted before runtime).
    $backupKeyFile = '/run/app-data/.crypto_key_backup';
    if (is_file($backupKeyFile) && is_readable($backupKeyFile)) {
        $key = trim(file_get_contents($backupKeyFile));
        if ($key !== '') {
            // Restore runtime file from backup
            @file_put_contents($runtimeKeyFile, $key);
            @chmod($runtimeKeyFile, 0600);
            @chown($runtimeKeyFile, 'www-data');
            $GLOBALS['__crypto_key_cache'] = $key;
            return $key;
        }
    }
    // Fall back to env var (original key from .env — only works if no rotation happened)
    $envKey = getenv('PGCRYPTO_KEY');
    if ($envKey && $envKey !== '') {
        $GLOBALS['__crypto_key_cache'] = $envKey;
        return $envKey;
    }
    // No fallback — fail closed if no key is configured
    error_log('FATAL: No crypto key found in runtime file, backup file, or PGCRYPTO_KEY env var');
    return '';
}

function getRevealPassword(): string
{
    return getenv('REVEAL_PASSWORD') ?: '';
}

function getSettingsAdminPassword(): string
{
    return getenv('SETTINGS_ADMIN_PASSWORD') ?: '';
}
