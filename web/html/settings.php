<?php

// Secure session settings before session_start
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
// Secure cookie only when on HTTPS; HTTP on :8180 just redirects so cookie won't be useful
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 8443)
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
if ($isHttps) {
    ini_set('session.cookie_secure', '1');
}

session_start();
require_once __DIR__ . '/crud.php';

$authenticated = isset($_SESSION['settings_auth']) && $_SESSION['settings_auth'] === true;
$message = '';
$error = '';

// Session timeout: 15 min idle, 8 hour absolute
$IDLE_TIMEOUT = 900;    // 15 minutes
$ABSOLUTE_TIMEOUT = 28800; // 8 hours
if ($authenticated) {
    $now = time();
    $loginTime = $_SESSION['login_time'] ?? 0;
    $lastActivity = $_SESSION['last_activity'] ?? 0;

    if ($loginTime > 0 && ($now - $loginTime) > $ABSOLUTE_TIMEOUT) {
        session_destroy();
        $authenticated = false;
        $error = 'เซสชันหมดอายุ (เกิน 8 ชั่วโมง) — กรุณาเข้าสู่ระบบใหม่';
    } elseif ($lastActivity > 0 && ($now - $lastActivity) > $IDLE_TIMEOUT) {
        session_destroy();
        $authenticated = false;
        $error = 'เซสชันหมดอายุ (ไม่มีการใช้งาน 15 นาที) — กรุณาเข้าสู่ระบบใหม่';
    } else {
        $_SESSION['last_activity'] = $now;
    }
}

// --- CSRF token helper (also defined in auth.php for authenticated pages) ---
if (!function_exists('getCsrfToken')) {
    function getCsrfToken(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('verifyCsrfToken')) {
    function verifyCsrfToken(string $token): bool
    {
        return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

// --- Rate limiter for login attempts (DB-based, not session-based) ---
// Session-based rate limiting can be bypassed by dropping the session cookie.
function getClientIp(): string
{
    // Use REMOTE_ADDR only — do NOT trust X-Forwarded-For from localhost
    // as attackers can spoof it to bypass rate limiting.
    // nginx fastcgi_params sets REMOTE_ADDR to the actual client IP.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function checkLoginRateLimit(): bool
{
    $maxAttempts = 5;
    $lockoutSeconds = 60;
    $ip = getClientIp();
    try {
        $pdo = getDb();
        // Count attempts in the last lockout window
        $stmt = $pdo->prepare("SELECT count(*) FROM login_attempts WHERE ip_address = :ip AND attempted_at > now() - make_interval(secs => :s)");
        $stmt->bindValue(':ip', $ip);
        $stmt->bindValue(':s', $lockoutSeconds, PDO::PARAM_INT);
        $stmt->execute();
        $count = (int) $stmt->fetchColumn();
        return $count < $maxAttempts;
    } catch (Throwable $e) {
        // DB not ready — allow login (fail open for availability)
        return true;
    }
}

function recordFailedLogin(): void
{
    $ip = getClientIp();
    try {
        $pdo = getDb();
        $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address) VALUES (:ip)");
        $stmt->execute([':ip' => $ip]);
    } catch (Throwable $e) {
        // DB not ready — silently ignore
    }
}

function resetLoginAttempts(): void
{
    $ip = getClientIp();
    try {
        $pdo = getDb();
        $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = :ip");
        $stmt->execute([':ip' => $ip]);
    } catch (Throwable $e) {
        // DB not ready — silently ignore
    }
}

function getRemainingAttempts(): int
{
    $maxAttempts = 5;
    $lockoutSeconds = 60;
    $ip = getClientIp();
    try {
        $pdo = getDb();
        $stmt = $pdo->prepare("SELECT count(*) FROM login_attempts WHERE ip_address = :ip AND attempted_at > now() - make_interval(secs => :s)");
        $stmt->bindValue(':ip', $ip);
        $stmt->bindValue(':s', $lockoutSeconds, PDO::PARAM_INT);
        $stmt->execute();
        $count = (int) $stmt->fetchColumn();
        return max(0, $maxAttempts - $count);
    } catch (Throwable $e) {
        return $maxAttempts;
    }
}

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // Login doesn't need CSRF (no session yet to protect), but all other POST actions do
    if ($action !== 'login') {
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!verifyCsrfToken($csrfToken)) {
            $error = 'CSRF token ไม่ถูกต้อง — กรุณารีเฟรชหน้าแล้วลองใหม่';
            $action = ''; // prevent further processing
        }
    }

    if ($action === 'login') {
        if (!checkLoginRateLimit()) {
            $error = 'พยายามเข้าสู่ระบบมากเกินไป — กรุณารอ 60 วินาทีแล้วลองใหม่';
        } else {
            $password = $_POST['admin_password'] ?? '';
            $expected = getSettingsAdminPassword();
            if (hash_equals($expected, $password)) {
                session_regenerate_id(true);
                $_SESSION['settings_auth'] = true;
                $_SESSION['login_time'] = time();
                $authenticated = true;
                resetLoginAttempts();
            } else {
                recordFailedLogin();
                $remaining = getRemainingAttempts();
                $error = "รหัสผ่านไม่ถูกต้อง (เหลือ {$remaining} ครั้งก่อนล็อค 60 วินาที)";
            }
        }
    } elseif ($action === 'logout') {
        session_destroy();
        $authenticated = false;
    } elseif ($authenticated && $action === 'update_setting') {
        $key   = $_POST['setting_key'] ?? '';
        $value = $_POST['setting_value'] ?? '';
        // crypto_key is managed via key-rotation workflow only — never editable here
        // reveal_password and settings_admin_password are managed via env vars
        $allowedKeys = ['default_masking'];
        if (!in_array($key, $allowedKeys, true)) {
            $error = 'ไม่อนุญาตให้แก้ไข key นี้ — crypto_key ใช้หน้า Key Rotation เท่านั้น';
        } else {
            updateSetting($key, $value);
            auditLog('SETTING_UPDATE', null, "อัปเดต setting: {$key}");
            $message = "อัปเดต '{$key}' สำเร็จ";
        }
    } elseif ($authenticated && $action === 'create_token') {
        $label = trim($_POST['token_label'] ?? '');
        if ($label === '') {
            $error = 'ต้องระบุ label';
        } else {
            // Auto-generate token with high entropy — user does not supply the token
            $token = 'tok_' . bin2hex(random_bytes(32));
            createApiToken($token, $label);
            auditLog('TOKEN_CREATE', null, "สร้าง API token: {$label}");
            $message = "สร้าง API token '{$label}' สำเร็จ — token: {$token} (เก็บไว้ใช้ทันที — แสดงครั้งเดียว)";
        }
    } elseif ($authenticated && $action === 'toggle_token') {
        $tokenId = (int) ($_POST['token_id'] ?? 0);
        $active   = ($_POST['active'] ?? '') === '1';
        toggleApiToken($tokenId, $active);
        auditLog('TOKEN_TOGGLE', $tokenId, $active ? 'เปิดใช้งาน token' : 'ปิดใช้งาน token');
        $message = $active ? "เปิดใช้งาน token แล้ว" : "ปิดใช้งาน token แล้ว";
    }
}

// Show login form if not authenticated
if (!$authenticated) {
    ?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-md mx-auto px-4 py-16">
        <div class="bg-slate-800 rounded-xl border border-slate-700 p-8">
            <h1 class="text-2xl font-bold text-cyan-400 mb-2">Settings</h1>
            <p class="text-slate-400 text-sm mb-6">กรอกรหัสผ่าน admin เพื่อจัดการค่าต่างๆ</p>
            <?php if ($error): ?>
                <div class="mb-4 p-3 rounded-lg bg-red-900/50 border border-red-700 text-red-300 text-sm">
                    ✗ <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>
            <form method="POST" action="settings.php" class="space-y-4">
                <input type="hidden" name="action" value="login">
                <div>
                    <label class="block text-sm text-slate-400 mb-1">Admin Password</label>
                    <input type="password" name="admin_password" required autofocus
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100"
                           placeholder="Admin password">
                </div>
                <button type="submit" class="w-full px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">
                    เข้าสู่ระบบ
                </button>
            </form>
            <div class="mt-6 text-center">
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
        </div>
    </div>
</body>
</html>
    <?php
    exit;
}

// Authenticated — show settings
$settings = getAllSettings();
$tokens = getApiTokens();

// Secrets managed via env vars or runtime files (not editable in DB)
$envManagedSecrets = ['crypto_key', 'reveal_password', 'settings_admin_password', 's3_key_id', 's3_secret_key', 's3_encryption_key'];
// Filter out env-managed secrets from the editable settings list
$editableSettings = array_filter($settings, fn($s) => !in_array($s['key'], $envManagedSecrets, true));
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-4xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">Settings</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
                <form method="POST" action="settings.php" class="ml-auto">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                    <button type="submit" class="px-3 py-1 rounded-lg bg-red-900/50 text-red-400 border border-red-800 hover:bg-red-900/70 transition text-sm">
                        Logout
                    </button>
                </form>
            </div>
            <p class="text-slate-400">
                จัดการค่าต่างๆ ที่เก็บในตาราง <code class="text-amber-400">app_settings</code> — ไม่ต้องแก้ .env
            </p>
        </header>

        <?php if ($message): ?>
            <div class="mb-4 p-3 rounded-lg bg-green-900/50 border border-green-700 text-green-300 text-sm">
                ✓ <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="mb-4 p-3 rounded-lg bg-red-900/50 border border-red-700 text-red-300 text-sm">
                ✗ <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <!-- App Settings -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">Application Settings</h2>
                <p class="text-xs text-slate-500 mt-1">ค่าที่ไม่ใช่ secret เก็บใน DB — secret เก็บใน env vars</p>
            </div>
            <div class="divide-y divide-slate-700">
                <?php foreach ($editableSettings as $s): ?>
                    <div class="px-6 py-4">
                        <form method="POST" action="settings.php" class="flex items-center gap-4">
                            <input type="hidden" name="action" value="update_setting">
                            <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                            <input type="hidden" name="setting_key" value="<?= htmlspecialchars($s['key']) ?>">
                            <div class="flex-1">
                                <div class="flex items-center gap-2 mb-1">
                                    <span class="font-mono text-cyan-400 text-sm"><?= htmlspecialchars($s['key']) ?></span>
                                    <?php if ($s['is_secret']): ?>
                                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800">secret</span>
                                    <?php else: ?>
                                        <span class="px-1.5 py-0.5 rounded text-xs bg-slate-700 text-slate-400 border border-slate-600">public</span>
                                    <?php endif; ?>
                                </div>
                                <p class="text-xs text-slate-500"><?= htmlspecialchars($s['description'] ?? '') ?></p>
                                <p class="text-xs text-slate-600 mt-1">อัปเดตล่าสุด: <?= htmlspecialchars($s['updated_at']) ?></p>
                            </div>
                            <div class="flex-1">
                                <input type="text" name="setting_value"
                                       value="<?= htmlspecialchars($s['value']) ?>"
                                       class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100 font-mono text-sm">
                            </div>
                            <button type="submit" class="px-3 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium transition whitespace-nowrap">
                                บันทึก
                            </button>
                        </form>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Env-managed secrets (read-only display) -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">Secrets (Environment Variables)</h2>
                <p class="text-xs text-slate-500 mt-1">ค่าเหล่านี้เก็บใน env vars ไม่ใช่ DB — แก้ไขที่ .env / docker-compose.yml</p>
            </div>
            <div class="divide-y divide-slate-700">
                <div class="px-6 py-4 flex items-center gap-4">
                    <div class="flex-1">
                        <span class="font-mono text-cyan-400 text-sm">crypto_key</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800 ml-2">secret</span>
                        <p class="text-xs text-slate-500 mt-1">เปลี่ยนผ่านหน้า Key Rotation เท่านั้น (re-encrypt ข้อมูลอัตโนมัติ)</p>
                    </div>
                    <div class="flex-1">
                        <input type="text" value="(managed by env: PGCRYPTO_KEY)" disabled
                               class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-500 font-mono text-sm cursor-not-allowed">
                    </div>
                </div>
                <div class="px-6 py-4 flex items-center gap-4">
                    <div class="flex-1">
                        <span class="font-mono text-cyan-400 text-sm">reveal_password</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800 ml-2">secret</span>
                        <p class="text-xs text-slate-500 mt-1">เปลี่ยนที่ env: REVEAL_PASSWORD</p>
                    </div>
                    <div class="flex-1">
                        <input type="text" value="(managed by env: REVEAL_PASSWORD)" disabled
                               class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-500 font-mono text-sm cursor-not-allowed">
                    </div>
                </div>
                <div class="px-6 py-4 flex items-center gap-4">
                    <div class="flex-1">
                        <span class="font-mono text-cyan-400 text-sm">settings_admin_password</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800 ml-2">secret</span>
                        <p class="text-xs text-slate-500 mt-1">เปลี่ยนที่ env: SETTINGS_ADMIN_PASSWORD</p>
                    </div>
                    <div class="flex-1">
                        <input type="text" value="(managed by env: SETTINGS_ADMIN_PASSWORD)" disabled
                               class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-500 font-mono text-sm cursor-not-allowed">
                    </div>
                </div>
                <div class="px-6 py-4 flex items-center gap-4">
                    <div class="flex-1">
                        <span class="font-mono text-cyan-400 text-sm">s3_encryption_key</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800 ml-2">secret</span>
                        <p class="text-xs text-slate-500 mt-1">SSE-C key — เปลี่ยนที่ env: S3_SSE_C_KEY</p>
                    </div>
                    <div class="flex-1">
                        <input type="text" value="(managed by env: S3_SSE_C_KEY)" disabled
                               class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-500 font-mono text-sm cursor-not-allowed">
                    </div>
                </div>
                <div class="px-6 py-4 flex items-center gap-4">
                    <div class="flex-1">
                        <span class="font-mono text-cyan-400 text-sm">s3_key_id / s3_secret_key</span>
                        <span class="px-1.5 py-0.5 rounded text-xs bg-red-900/50 text-red-400 border border-red-800 ml-2">secret</span>
                        <p class="text-xs text-slate-500 mt-1">เขียนลง runtime file โดย garage-init.php (อ่านจาก shared volume)</p>
                    </div>
                    <div class="flex-1">
                        <input type="text" value="(managed by runtime: /tmp/.s3_credentials)" disabled
                               class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-500 font-mono text-sm cursor-not-allowed">
                    </div>
                </div>
            </div>
        </div>

        <!-- API Tokens -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">API Tokens</h2>
            </div>
            <table class="w-full text-sm">
                <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                    <tr>
                        <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                        <th class="px-4 py-3 text-left">Label</th>
                        <th class="px-4 py-3 text-left whitespace-nowrap">สถานะ</th>
                        <th class="px-4 py-3 text-left whitespace-nowrap">สร้างเมื่อ</th>
                        <th class="px-4 py-3 text-left whitespace-nowrap">ใช้ล่าสุด</th>
                        <th class="px-4 py-3 text-left whitespace-nowrap">การจัดการ</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    <?php foreach ($tokens as $t): ?>
                        <tr class="hover:bg-slate-750 transition">
                            <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $t['id'] ?></td>
                            <td class="px-4 py-3 text-slate-300"><?= htmlspecialchars($t['label']) ?></td>
                            <td class="px-4 py-3 whitespace-nowrap">
                                <?php if ($t['is_active']): ?>
                                    <span class="px-2 py-1 rounded text-xs bg-green-900/50 text-green-400 border border-green-800">active</span>
                                <?php else: ?>
                                    <span class="px-2 py-1 rounded text-xs bg-red-900/50 text-red-400 border border-red-800">disabled</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($t['created_at']) ?></td>
                            <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($t['last_used_at'] ?? '-') ?></td>
                            <td class="px-4 py-3 whitespace-nowrap">
                                <form method="POST" action="settings.php" class="inline">
                                    <input type="hidden" name="action" value="toggle_token">
                                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                    <input type="hidden" name="token_id" value="<?= (int) $t['id'] ?>">
                                    <input type="hidden" name="active" value="<?= $t['is_active'] ? '0' : '1' ?>">
                                    <button type="submit" class="text-xs <?= $t['is_active'] ? 'text-red-400 hover:text-red-300' : 'text-green-400 hover:text-green-300' ?>">
                                        <?= $t['is_active'] ? 'ปิด' : 'เปิด' ?>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <!-- Create new token -->
            <div class="px-6 py-4 border-t border-slate-700">
                <form method="POST" action="settings.php" class="flex items-end gap-3">
                    <input type="hidden" name="action" value="create_token">
                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                    <div class="flex-1">
                        <label class="block text-sm text-slate-400 mb-1">Label (ระบุชื่อสำหรับ token นี้)</label>
                        <input type="text" name="token_label"
                               class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100"
                               placeholder="เช่น CI/CD Pipeline" required>
                    </div>
                    <button type="submit" class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition whitespace-nowrap">
                        สร้าง Token
                    </button>
                </form>
            </div>
        </div>

        <!-- Security Info -->
        <div class="bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>ความปลอดภัย:</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li>Secrets (crypto_key, reveal_password, admin_password) เก็บใน env vars — ไม่ใช่ DB เพื่อกันการรั่วของกุญแจพร้อมข้อมูล</li>
                <li>crypto_key เปลี่ยนผ่านหน้า Key Rotation เท่านั้น (re-encrypt ข้อมูลอัตโนมัติ)</li>
                <li>API token แรกถูกสุ่มตอน seed — ดูจาก log ของ container db ครั้งแรกที่รัน</li>
                <li>API token ใหม่จะถูก hash (SHA-256) ก่อนเก็บ — แสดง plaintext เฉพาะตอนสร้าง</li>
                <li><strong>Session:</strong> HttpOnly + SameSite=Strict + Secure (HTTPS only) + session_regenerate_id หลัง login</li>
                <li><strong>CSRF:</strong> ทุก POST action ต้องมี CSRF token (ยกเวั้น login) — ครอบคลุม index.php, upload.php, key-rotation.php แล้ว</li>
                <li><strong>Rate limit:</strong> ล็อค 60 วินาทีหลังพยายาม login ผิด 5 ครั้ง — เก็บใน DB (login_attempts table) ไม่ใช่ session ป้องกันการทิ้ง cookie เพื่อรีเซ็ตการนับ</li>
            </ul>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Settings (DB-stored config)
        </footer>
    </div>
</body>
</html>
