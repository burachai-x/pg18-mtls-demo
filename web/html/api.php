<?php

// API uses Bearer token auth, not session login.
// Start session with secure settings for consistency.
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

require_once __DIR__ . '/crud.php';

header('Content-Type: application/json; charset=utf-8');

function json_response(int $code, array $data): void
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$parts  = array_values(array_filter(explode('/', trim($path, '/'))));

// Expect: /api.php/users  or  /api.php/users/{id}
if (count($parts) < 2 || $parts[0] !== 'api.php') {
    json_response(404, ['error' => 'Not found', 'path' => $path]);
}

$resource = $parts[1] ?? '';
$id       = isset($parts[2]) ? (int) $parts[2] : null;

if ($resource !== 'users') {
    json_response(404, ['error' => "Unknown resource: {$resource}"]);
}

// API token authentication
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$token = '';
if (preg_match('/Bearer\s+(.+)/i', $authHeader, $m)) {
    $token = trim($m[1]);
}

if ($token === '') {
    json_response(401, ['error' => 'Missing Authorization header', 'hint' => 'Use: Authorization: Bearer <token>']);
}

if (!verifyApiKey($token)) {
    json_response(401, ['error' => 'Invalid or inactive API token']);
}

// Route by method
switch ($method) {
    case 'GET':
        if ($id) {
            $user = getUser($id);
            if (!$user) {
                json_response(404, ['error' => "User not found: {$id}"]);
            }
            // Mask sensitive data in API by default
            $user['name']  = maskName($user['name']);
            $user['email'] = maskEmail($user['email']);
            $user['phone'] = maskPhone($user['phone']);
            json_response(200, ['data' => $user, 'masked' => true]);
        } else {
            $users = getAllUsersMasked();
            json_response(200, ['data' => $users, 'count' => count($users), 'masked' => true]);
        }
        break;

    case 'POST':
        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input) {
            $input = $_POST;
        }
        $name  = trim($input['name'] ?? '');
        $email = trim($input['email'] ?? '');
        $phone = trim($input['phone'] ?? '');
        if ($name === '' || $email === '' || $phone === '') {
            json_response(400, ['error' => 'Fields required: name, email, phone']);
        }
        try {
            $newId = createUser($name, $email, $phone);
            auditLog('API_CREATE', $newId, "API: สร้างผู้ใช้ '{$name}'");
            json_response(201, ['success' => true, 'id' => $newId, 'message' => 'User created (encrypted)']);
        } catch (Throwable $e) {
            error_log('API POST error: ' . $e->getMessage());
            json_response(500, ['error' => 'Internal server error']);
        }
        break;

    case 'PUT':
        if (!$id) {
            json_response(400, ['error' => 'User ID required for PUT']);
        }
        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input) {
            parse_str(file_get_contents('php://input'), $input);
        }
        $name  = trim($input['name'] ?? '');
        $email = trim($input['email'] ?? '');
        $phone = trim($input['phone'] ?? '');
        if ($name === '' || $email === '' || $phone === '') {
            json_response(400, ['error' => 'Fields required: name, email, phone']);
        }
        try {
            $updated = updateUser($id, $name, $email, $phone);
            if (!$updated) {
                json_response(404, ['error' => "User not found: {$id}"]);
            }
            auditLog('API_UPDATE', $id, "API: อัปเดตผู้ใช้ ID {$id}");
            json_response(200, ['success' => true, 'id' => $id, 'message' => 'User updated (re-encrypted)']);
        } catch (Throwable $e) {
            error_log('API PUT error: ' . $e->getMessage());
            json_response(500, ['error' => 'Internal server error']);
        }
        break;

    case 'DELETE':
        if (!$id) {
            json_response(400, ['error' => 'User ID required for DELETE']);
        }
        try {
            $deleted = deleteUser($id);
            if (!$deleted) {
                json_response(404, ['error' => "User not found: {$id}"]);
            }
            auditLog('API_DELETE', $id, "API: ลบผู้ใช้ ID {$id}");
            json_response(200, ['success' => true, 'id' => $id, 'message' => 'User deleted']);
        } catch (Throwable $e) {
            error_log('API DELETE error: ' . $e->getMessage());
            json_response(500, ['error' => 'Internal server error']);
        }
        break;

    default:
        json_response(405, ['error' => "Method not allowed: {$method}"]);
}
