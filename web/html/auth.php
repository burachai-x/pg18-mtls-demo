<?php

// Shared authentication guard — include at top of any page requiring login.
// Uses the same session as settings.php (settings_auth key).

// Secure session settings before session_start
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
if ($isHttps) {
    ini_set('session.cookie_secure', '1');
}

session_start();

$authenticated = isset($_SESSION['settings_auth']) && $_SESSION['settings_auth'] === true;

// Session timeout: 15 min idle, 8 hour absolute
$IDLE_TIMEOUT = 900;    // 15 minutes
$ABSOLUTE_TIMEOUT = 28800; // 8 hours
if ($authenticated) {
    $now = time();
    $loginTime = $_SESSION['login_time'] ?? 0;
    $lastActivity = $_SESSION['last_activity'] ?? 0;

    if (($loginTime > 0 && ($now - $loginTime) > $ABSOLUTE_TIMEOUT)
        || ($lastActivity > 0 && ($now - $lastActivity) > $IDLE_TIMEOUT)) {
        session_destroy();
        $authenticated = false;
    } else {
        $_SESSION['last_activity'] = $now;
    }
}

if (!$authenticated) {
    $isApi = strpos($_SERVER['REQUEST_URI'] ?? '', '/api.php') !== false
        || (function_exists('getallheaders') && stripos(getallheaders()['Accept'] ?? '', 'application/json') !== false);

    if ($isApi) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Authentication required']);
        exit;
    }

    header('Location: settings.php');
    exit;
}

// --- CSRF token helpers (shared across all authenticated pages) ---
function getCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(string $token): bool
{
    return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Convenience: verify CSRF on POST requests, die with error if invalid
function enforceCsrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!verifyCsrfToken($token)) {
            http_response_code(403);
            echo 'CSRF token ไม่ถูกต้อง — กรุณารีเฟรชหน้าแล้วลองใหม่';
            exit;
        }
    }
}
