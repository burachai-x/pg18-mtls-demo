<?php
/**
 * Garage S3 initialization script — run once on container startup.
 * Reads S3 credentials from shared volume (written by garage-init container)
 * and writes them to a runtime file for the web app.
 *
 * CLI-only — blocked from web access via nginx config and this guard.
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('Forbidden — CLI only');
}

$credFile = '/var/lib/garage/s3-credentials.env';

echo "[garage-init] Starting initialization...\n";

// Wait for credentials file to appear (garage-init container writes it)
$creds = null;
for ($i = 1; $i <= 30; $i++) {
    if (file_exists($credFile)) {
        $content = file_get_contents($credFile);
        $creds = [];
        foreach (explode("\n", trim($content)) as $line) {
            if (strpos($line, '=') !== false) {
                [$k, $v] = explode('=', $line, 2);
                $creds[trim($k)] = trim($v);
            }
        }
        if (!empty($creds['s3_key_id']) && !empty($creds['s3_secret_key'])) {
            break;
        }
    }
    echo "[garage-init] Waiting for credentials file... ($i/30)\n";
    sleep(2);
    $creds = null;
}

if (!$creds || empty($creds['s3_key_id']) || empty($creds['s3_secret_key'])) {
    echo "[garage-init] WARNING: Could not read S3 credentials from shared volume.\n";
    echo "[garage-init] S3 features will not work until credentials are set manually.\n";
    exit(0);
}

$keyId = $creds['s3_key_id'];
$secretKey = $creds['s3_secret_key'];

echo "[garage-init] Key ID: {$keyId}\n";
echo "[garage-init] Secret: [REDACTED]\n";

// Write S3 credentials to runtime file (not DB — avoids plaintext secrets in app_settings)
echo "[garage-init] Writing S3 credentials to runtime file...\n";
$credContent = "s3_key_id={$keyId}\ns3_secret_key={$secretKey}\n";
file_put_contents('/tmp/.s3_credentials', $credContent);
chmod('/tmp/.s3_credentials', 0600);
chown('/tmp/.s3_credentials', 'www-data');
echo "[garage-init] S3 credentials written successfully!\n";

echo "[garage-init] Done!\n";
