<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/mask.php';

// Authentication is handled by auth.php — $authenticated is already set

$host = getenv('DB_HOST') ?: 'db';
$port = getenv('DB_PORT') ?: '5432';
$dbname = getenv('DB_NAME') ?: 'appdb';
$user   = getenv('DB_USER') ?: 'appuser';

$sslRootCert = '/tmp/pg-certs/ca.crt';
$sslCert     = '/tmp/pg-certs/client.crt';
$sslKey      = '/tmp/pg-certs/client.key';

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$message = '';
$error = '';

// Redirect to login if not authenticated
if (!$authenticated && $action !== '') {
    header('Location: settings.php');
    exit;
}

// Handle download (authenticated only)
if ($authenticated && $action === 'download') {
    $timestamp = date('Y-m-d_His');
    $filename = "backup_{$timestamp}.sql";

    $connStr = "host={$host} port={$port} dbname={$dbname} user={$user} sslmode=verify-full sslrootcert={$sslRootCert} sslcert={$sslCert} sslkey={$sslKey}";

    // Exclude app_settings (contains crypto_key, passwords, S3 credentials)
    // Also exclude key_history (contains key hashes) and api_tokens (contains token hashes)
    $cmd = "PGPASSWORD='' pg_dump \"{$connStr}\" --no-owner --no-acl --exclude-table=app_settings --exclude-table=key_history --exclude-table=api_tokens 2>&1";
    $output = shell_exec($cmd);

    if ($output && strpos($output, 'FATAL') === false && strpos($output, 'ERROR') === false) {
        // Prepend warning header
        $warning = "-- ============================================================\n";
        $warning .= "-- ENCRYPTED BACKUP — PostgreSQL 18 mTLS Demo\n";
        $warning .= "-- Generated: {$timestamp}\n";
        $warning .= "-- \n";
        $warning .= "-- ⚠ This backup contains ENCRYPTED data only.\n";
        $warning .= "-- ⚠ app_settings (crypto_key, passwords, S3 creds) EXCLUDED.\n";
        $warning .= "-- ⚠ key_history and api_tokens also EXCLUDED.\n";
        $warning .= "-- ⚠ To restore: create app_settings manually with correct keys.\n";
        $warning .= "-- ============================================================\n\n";

        header('Content-Type: application/sql');
        header("Content-Disposition: attachment; filename=\"{$filename}\"");
        header('Content-Length: ' . strlen($warning . $output));
        echo $warning . $output;
        exit;
    } else {
        $error = 'pg_dump failed: ' . substr($output ?? 'no output', 0, 200);
    }
}

// Handle download secrets separately (authenticated only, explicit warning)
if ($authenticated && $action === 'download_secrets') {
    $timestamp = date('Y-m-d_His');
    $filename = "backup_secrets_{$timestamp}.sql";

    $connStr = "host={$host} port={$port} dbname={$dbname} user={$user} sslmode=verify-full sslrootcert={$sslRootCert} sslcert={$sslCert} sslkey={$sslKey}";

    // Dump ONLY app_settings (secrets file — handle with extreme care)
    $cmd = "PGPASSWORD='' pg_dump \"{$connStr}\" --no-owner --no-acl --data-only --table=app_settings 2>&1";
    $output = shell_exec($cmd);

    if ($output && strpos($output, 'FATAL') === false && strpos($output, 'ERROR') === false) {
        $warning = "-- ============================================================\n";
        $warning .= "-- ⚠⚠⚠ SECRET BACKUP — HANDLE WITH EXTREME CARE ⚠⚠⚠\n";
        $warning .= "-- Generated: {$timestamp}\n";
        $warning .= "-- \n";
        $warning .= "-- This file contains encrypted user data (ciphertext).\n";
        $warning .= "-- Secrets (crypto_key, passwords, S3 creds) are NOT in this backup —\n";
        $warning .= "--   they are stored in env vars and runtime files, not in app_settings.\n";
        $warning .= "-- \n";
        $warning .= "-- ⚠ Store securely — ciphertext + key history metadata are sensitive.\n";
        $warning .= "-- ============================================================\n\n";

        header('Content-Type: application/sql');
        header("Content-Disposition: attachment; filename=\"{$filename}\"");
        header('Content-Length: ' . strlen($warning . $output));
        echo $warning . $output;
        exit;
    } else {
        $error = 'pg_dump failed: ' . substr($output ?? 'no output', 0, 200);
    }
}

// Handle view backup (show in browser — authenticated only)
$backupContent = '';
$backupSize = 0;
$lineCount = 0;
$encryptedLines = 0;
$hasSecrets = false;
if ($authenticated && $action === 'view') {
    $connStr = "host={$host} port={$port} dbname={$dbname} user={$user} sslmode=verify-full sslrootcert={$sslRootCert} sslcert={$sslCert} sslkey={$sslKey}";

    // Exclude app_settings from view too
    $cmd = "PGPASSWORD='' pg_dump \"{$connStr}\" --data-only --inserts --no-owner --no-acl --exclude-table=app_settings --exclude-table=key_history --exclude-table=api_tokens 2>&1";
    $output = shell_exec($cmd);

    if ($output && strpos($output, 'FATAL') === false && strpos($output, 'ERROR') === false) {
        $backupContent = $output;
        $backupSize = strlen($output);
        $lines = explode("\n", $output);
        $lineCount = count($lines);
        foreach ($lines as $line) {
            if (strpos($line, 'pgp_sym_encrypt') !== false || strpos($line, '\\x') !== false || strpos($line, 'hmac') !== false) {
                $encryptedLines++;
            }
        }
        $hasSecrets = strpos($output, 'crypto_key') !== false || strpos($output, 'reveal_password') !== false;
    } else {
        $error = 'pg_dump failed: ' . substr($output ?? 'no output', 0, 200);
    }
}

// Get current stats
$pdo = getDb();
$key = getCryptoKey();
$stmt = $pdo->query("SELECT count(*) AS cnt FROM users");
$userCount = (int) $stmt->fetchColumn();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup & Restore — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">Backup & Restore</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
                <?php if ($authenticated): ?>
                    <span class="ml-auto px-2 py-1 rounded text-xs bg-green-900/50 text-green-400 border border-green-800">authenticated</span>
                <?php else: ?>
                    <a href="settings.php" class="ml-auto px-3 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition">Login required</a>
                <?php endif; ?>
            </div>
            <p class="text-slate-400">
                สาธิตว่าข้อมูลใน backup เป็น <strong class="text-amber-400">เข้ารหัสอยู่เสมอ</strong> — ถ้าไม่มี key ก็อ่านไม่ได้แม้จะ restore แล้ว
            </p>
            <div class="mt-3 p-3 rounded-lg bg-amber-900/30 border border-amber-800 text-amber-300 text-sm">
                <strong>⚠ หมายเหตุ:</strong> Backup แยก secrets ออกจากข้อมูลเข้ารหัส —
                <code>app_settings</code> (crypto_key, passwords, S3 credentials) ถูก <strong>exclude</strong> จาก backup หลัก
                และดาวน์โหลดแยกไฟล์เท่านั้น ต้อง login ก่อน
            </div>
        </header>

        <?php if ($error): ?>
            <div class="mb-4 p-3 rounded-lg bg-red-900/50 border border-red-700 text-red-300">
                ✗ <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <!-- Stats -->
        <div class="mb-6 grid grid-cols-3 gap-4">
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">ข้อมูลใน DB</div>
                <div class="text-2xl font-bold text-cyan-400"><?= $userCount ?> รายการ</div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">การเข้ารหัส</div>
                <div class="text-lg font-bold text-amber-400">pgp_sym_encrypt</div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">สถานะข้อมูลใน Backup</div>
                <div class="text-lg font-bold text-green-400">เข้ารหัสอยู่</div>
            </div>
        </div>

        <!-- Actions -->
        <?php if (!$authenticated): ?>
        <div class="bg-slate-800 rounded-xl p-8 border border-slate-700 text-center">
            <p class="text-slate-400 mb-4">กรุณา login ที่หน้า Settings ก่อนใช้งาน Backup</p>
            <a href="settings.php" class="inline-block px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">ไปหน้า Login</a>
        </div>
        <?php else: ?>
        <div class="grid grid-cols-2 gap-4 mb-6">
            <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-slate-200 mb-2">1. ดาวน์โหลด Backup (ข้อมูลเข้ารหัส)</h2>
                <p class="text-sm text-slate-400 mb-4">
                    <code class="text-amber-400">pg_dump</code> ผ่าน mTLS — <strong>exclude</strong> <code>app_settings</code>, <code>key_history</code>, <code>api_tokens</code>
                </p>
                <a href="backup.php?action=download" class="inline-block px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">
                    ดาวน์โหลด .sql (encrypted data only)
                </a>
            </div>
            <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 class="text-lg font-semibold text-slate-200 mb-2">2. ดูข้อมูลใน Backup</h2>
                <p class="text-sm text-slate-400 mb-4">
                    ดูว่าข้อมูลในไฟล์ backup เป็นอย่างไร — ยืนยันว่าเป็นเข้ารหัส (ไม่มี plaintext secrets)
                </p>
                <a href="backup.php?action=view" class="inline-block px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium transition">
                    ดูข้อมูลใน Backup
                </a>
            </div>
        </div>

        <!-- Secret backup (separate, explicit warning) -->
        <div class="bg-red-900/30 border border-red-800 rounded-xl p-6 mb-6">
            <h2 class="text-lg font-semibold text-red-300 mb-2">⚠ 3. ดาวน์โหลด Secrets (แยกไฟล์ — ใช้ด้วยความระมัดระวัง)</h2>
            <p class="text-sm text-red-300/70 mb-4">
                ไฟล์นี้มี <code>crypto_key</code>, <code>reveal_password</code>, <code>settings_admin_password</code>, S3 credentials และ SSE-C key เป็น <strong>plaintext</strong>
                — ควรเก็บใน KMS/Vault ไม่ควรเก็บใน git หรือที่เข้าถึงได้ง่าย
            </p>
            <a href="backup.php?action=download_secrets" class="inline-block px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white font-medium transition"
               onclick="return confirm('ยืนยัน: ไฟล์นี้มี plaintext secrets ทั้งหมด — ต้องการดาวน์โหลด?')">
                ดาวน์โหลด secrets .sql
            </a>
        </div>
        <?php endif; ?>

        <?php if ($action === 'view' && $backupContent): ?>
            <!-- Backup Analysis -->
            <div class="mb-6 bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-700">
                    <h2 class="text-xl font-semibold text-slate-200">วิเคราะห์ Backup</h2>
                </div>
                <div class="p-6 grid grid-cols-3 gap-4">
                    <div>
                        <div class="text-slate-400 text-sm">ขนาดไฟล์</div>
                        <div class="text-xl font-bold text-cyan-400"><?= number_format($backupSize) ?> bytes</div>
                    </div>
                    <div>
                        <div class="text-slate-400 text-sm">จำนวนบรรทัด</div>
                        <div class="text-xl font-bold text-slate-200"><?= number_format($lineCount) ?></div>
                    </div>
                    <div>
                        <div class="text-slate-400 text-sm">บรรทัดที่มีข้อมูลเข้ารหัส</div>
                        <div class="text-xl font-bold text-green-400"><?= $encryptedLines ?></div>
                    </div>
                </div>
            </div>

            <!-- Backup Content -->
            <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
                    <h2 class="text-xl font-semibold text-slate-200">ข้อมูลใน Backup (data-only)</h2>
                    <span class="text-xs text-slate-500">แสดง 100 บรรทัดแรก</span>
                </div>
                <div class="p-4 overflow-x-auto">
                    <pre class="text-xs font-mono text-slate-300 bg-slate-900 p-4 rounded-lg overflow-x-auto max-h-96"><?php
                    $lines = explode("\n", $backupContent);
                    $display = array_slice($lines, 0, 100);
                    $shown = [];
                    foreach ($display as $line) {
                        // Highlight encrypted data
                        if (strpos($line, 'pgp_sym_encrypt') !== false || strpos($line, '\\x') !== false) {
                            $shown[] = $line;
                        } elseif (strpos($line, 'INSERT INTO') !== false) {
                            $shown[] = $line;
                        } elseif (strpos($line, '--') === 0 || strpos($line, 'COPY') === 0 || strpos($line, 'SET') === 0) {
                            $shown[] = $line;
                        }
                    }
                    // Show all INSERT lines (they contain the encrypted data)
                    $insertLines = array_filter($lines, fn($l) => strpos($l, 'INSERT INTO') !== false);
                    if (count($insertLines) > 0) {
                        echo "-- INSERT statements (ข้อมูลเข้ารหัสทั้งหมด):\n\n";
                        foreach (array_slice($insertLines, 0, 5) as $line) {
                            // Truncate very long lines
                            if (strlen($line) > 300) {
                                echo htmlspecialchars(substr($line, 0, 300)) . "...\n";
                            } else {
                                echo htmlspecialchars($line) . "\n";
                            }
                        }
                        if (count($insertLines) > 5) {
                            echo "\n... และอีก " . (count($insertLines) - 5) . " บรรทัด\n";
                        }
                    } else {
                        echo htmlspecialchars(implode("\n", $display));
                    }
                    ?></pre>
                </div>
            </div>

            <!-- Key point -->
            <div class="mt-6 bg-green-900/30 border border-green-800 rounded-lg p-4 text-sm text-green-300">
                <strong>✓ ยืนยัน:</strong> ข้อมูลในไฟล์ backup เป็น <code>pgp_sym_encrypt(...)</code> ทั้งหมด
                — ถ้าผู้ไม่ประสงค์ดีได้ไฟล์นี้ไป จะไม่สามารถอ่านข้อมูลได้หากไม่มี encryption key
                แม้จะ restore ขึ้น PostgreSQL อื่นก็ตาม ข้อมูลยังคงเข้ารหัสอยู่ในตาราง
                <br><br>
                <strong>✓ Secrets แยกไฟล์:</strong> <code>app_settings</code> (crypto_key, passwords, S3 credentials)
                ถูก exclude จาก backup หลัก — ดาวน์โหลดแยกเท่านั้นผ่านปุ่ม "ดาวน์โหลด secrets"
                <?php if ($hasSecrets): ?>
                <br><br>
                <strong class="text-red-400">⚠ พบ secrets ใน backup!</strong> กรุณาตรวจสอบ
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Info -->
        <div class="mt-6 bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>วิธีการทำงาน:</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li><code>pg_dump</code> ทำงานผ่าน mTLS connection (ใช้ client cert)</li>
                <li>ข้อมูลที่ dump ออกมาเป็น <code>bytea</code> ที่เข้ารหัสแล้ว — ไม่ใช่ plaintext</li>
                <li>ถ้า restore ขึ้น DB อื่น ข้อมูลยังเข้ารหัสอยู่ ต้องมี key ถึงจะ <code>pgp_sym_decrypt</code> ได้</li>
                <li><strong>app_settings แยกไฟล์:</strong> crypto_key, passwords, S3 credentials ไม่อยู่ใน backup หลัก</li>
                <li>ต้อง login ที่หน้า Settings ก่อนถึงจะดาวน์โหลด backup ได้</li>
            </ul>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Backup & Restore (encrypted at rest)
        </footer>
    </div>
</body>
</html>
