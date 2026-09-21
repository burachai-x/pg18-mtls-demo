<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/mask.php';
require_once __DIR__ . '/s3.php';

$action = $_POST['action'] ?? $_GET['action'] ?? '';
$message = '';
$error = '';
$revealData = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    enforceCsrf();
    try {
        if ($action === 'create') {
            $name  = trim($_POST['name']  ?? '');
            $email = trim($_POST['email'] ?? '');
            $phone = trim($_POST['phone'] ?? '');

            if ($name === '' || $email === '' || $phone === '') {
                throw new InvalidArgumentException('กรุณากรอกข้อมูลให้ครบทุกช่อง');
            }

            // Handle profile picture upload (stored encrypted in DB)
            $picData = null;
            $picMime = null;
            if (!empty($_FILES['profile_pic']['name']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
                $picFile = $_FILES['profile_pic'];
                $picMime = mime_content_type($picFile['tmp_name']);
                $allowedPicMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                if (!in_array($picMime, $allowedPicMimes, true)) {
                    throw new InvalidArgumentException("รูปโปรไฟล์: ประเภทไฟล์ '{$picMime}' ไม่ได้รับอนุญาต (JPEG, PNG, GIF, WebP เท่านั้น)");
                }
                if ($picFile['size'] > 5 * 1024 * 1024) {
                    throw new InvalidArgumentException('รูปโปรไฟล์: ไฟล์ใหญ่เกิน 5 MB');
                }
                $picData = file_get_contents($picFile['tmp_name']);
            }

            $newUserId = createUser($name, $email, $phone, $picData, $picMime);
            auditLog('CREATE', $newUserId, "เพิ่มผู้ใช้ '{$name}'" . ($picData ? ' (พร้อมรูปโปรไฟล์)' : ''));
            $message = "เพิ่มผู้ใช้ '{$name}' สำเร็จ (ข้อมูลถูกเข้ารหัส AES-256)" . ($picData ? ' · รูปโปรไฟล์เข้ารหัสใน DB' : '');

            // Handle file attachment
            if (!empty($_FILES['attachment']['name']) && $_FILES['attachment']['error'] === UPLOAD_ERR_OK) {
                $attResult = handleUserAttachment($newUserId, 'id_card');
                if ($attResult['success']) {
                    $message .= " \u00b7 แนบไฟล์ '{$attResult['name']}' ไว้ใน S3 (SSE-C) สำเร็จ";
                } else {
                    $error = $attResult['error'];
                }
            }
        } elseif ($action === 'update') {
            $id    = (int) ($_POST['id']    ?? 0);
            $name  = trim($_POST['name']  ?? '');
            $email = trim($_POST['email'] ?? '');
            $phone = trim($_POST['phone'] ?? '');

            if ($id <= 0 || $name === '' || $email === '' || $phone === '') {
                throw new InvalidArgumentException('ข้อมูลไม่ถูกต้อง');
            }

            // Handle profile picture upload (stored encrypted in DB)
            $picData = null;
            $picMime = null;
            if (!empty($_FILES['profile_pic']['name']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
                $picFile = $_FILES['profile_pic'];
                $picMime = mime_content_type($picFile['tmp_name']);
                $allowedPicMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                if (!in_array($picMime, $allowedPicMimes, true)) {
                    throw new InvalidArgumentException("รูปโปรไฟล์: ประเภทไฟล์ '{$picMime}' ไม่ได้รับอนุญาต (JPEG, PNG, GIF, WebP เท่านั้น)");
                }
                if ($picFile['size'] > 5 * 1024 * 1024) {
                    throw new InvalidArgumentException('รูปโปรไฟล์: ไฟล์ใหญ่เกิน 5 MB');
                }
                $picData = file_get_contents($picFile['tmp_name']);
            }

            updateUser($id, $name, $email, $phone, $picData, $picMime);
            auditLog('UPDATE', $id, "อัปเดตผู้ใช้ ID {$id}: {$name}" . ($picData ? ' (พร้อมรูปโปรไฟล์ใหม่)' : ''));
            $message = "อัปเดตผู้ใช้ ID {$id} สำเร็จ" . ($picData ? ' · รูปโปรไฟล์เข้ารหัสใน DB' : '');

            // Handle file attachment on edit
            if (!empty($_FILES['attachment']['name']) && $_FILES['attachment']['error'] === UPLOAD_ERR_OK) {
                $attResult = handleUserAttachment($id, 'id_card');
                if ($attResult['success']) {
                    $message .= " \u00b7 แนบไฟล์ '{$attResult['name']}' ไว้ใน S3 (SSE-C) สำเร็จ";
                } else {
                    $error = $attResult['error'];
                }
            }
        } elseif ($action === 'delete') {
            $id = (int) ($_POST['id'] ?? 0);
            if ($id <= 0) {
                throw new InvalidArgumentException('ID ไม่ถูกต้อง');
            }
            // Get user files (metadata only — don't delete yet)
            $userFiles = deleteUserFiles($id);
            $s3Failures = 0;
            foreach ($userFiles as $uf) {
                if (deleteFileFromS3($uf['s3_key'])) {
                    // S3 delete succeeded — safe to delete metadata
                    deleteFileRecord((int) $uf['id']);
                } else {
                    $s3Failures++;
                    auditLog('FILE_DELETE_FAILED', (int) $uf['id'], "ลบไฟล์ '{$uf['original_name']}' จาก S3 ล้มเหลว (user {$id}) — metadata retained for retry: {$uf['s3_key']}");
                }
            }
            if ($s3Failures > 0) {
                // Do NOT delete user — ON DELETE CASCADE on file_storage would wipe
                // metadata we just retained for retry. User must fix S3 issues first.
                $error = "ไม่สามารถลบผู้ใช้ ID {$id} ได้ — มี {$s3Failures} ไฟล์ใน S3 ที่ลบไม่สำเร็จ (metadata เก็บไว้สำหรับ retry) กรุณาลบไฟล์จาก S3 ให้สำเร็จก่อน";
                auditLog('DELETE_ABORTED', $id, "ยกเลิกการลบผู้ใช้ ID {$id} เนื่องจาก S3 ล้มเหลว {$s3Failures} ไฟล์");
            } else {
                deleteUser($id);
                auditLog('DELETE', $id, "ลบผู้ใช้ ID {$id} (และไฟล์แนบ " . count($userFiles) . " ไฟล์)");
                $message = "ลบผู้ใช้ ID {$id} สำเร็จ" . (count($userFiles) > 0 ? " (ลบไฟล์แนบ " . count($userFiles) . " ไฟล์จาก S3)" : "");
            }
        } elseif ($action === 'download_file') {
            $fileId = (int) ($_POST['file_id'] ?? 0);
            $record = getFileRecord($fileId);
            if (!$record) {
                throw new InvalidArgumentException('ไม่พบไฟล์ ID ' . $fileId);
            }
            $data = downloadFileFromS3($record['s3_key']);
            if ($data === null) {
                throw new RuntimeException('ดาวน์โหลดจาก S3 ล้มเหลว (SSE-C decrypt)');
            }
            auditLog('FILE_DOWNLOAD', $fileId, "ดาวน์โหลดไฟล์ '{$record['original_name']}' จาก S3 (SSE-C decrypt)");
            // Sanitize filename: strip CR/LF to prevent header injection
            $safeName = str_replace(["\r", "\n", "\0"], '', $record['original_name']);
            $encodedName = rawurlencode($safeName);
            header('Content-Type: ' . $record['mime_type']);
            header("Content-Disposition: attachment; filename=\"{$safeName}\"; filename*=UTF-8''{$encodedName}");
            header('Content-Length: ' . strlen($data));
            echo $data;
            exit;
        } elseif ($action === 'reveal') {
            $revealPassword = $_POST['reveal_password'] ?? '';
            $expectedPassword = getRevealPassword();
            if (hash_equals($expectedPassword, $revealPassword)) {
                $revealData = true;
                auditLog('REVEAL', null, 'ดูข้อมูลเต็ม (unmasked)');
                $message = "ดูข้อมูลเต็มสำเร็จ — ข้อมูลจะแสดงครั้งเดียวในหน้านี้";
            } else {
                throw new InvalidArgumentException('รหัสผ่านดูข้อมูลเต็มไม่ถูกต้อง');
            }
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

// Serve profile picture (GET request)
if (($_GET['action'] ?? '') === 'profile_pic' && isset($_GET['id'])) {
    $pic = getUserProfilePicture((int) $_GET['id']);
    if ($pic && $pic['pic'] !== null) {
        header('Content-Type: ' . $pic['mime']);
        header('Content-Length: ' . strlen($pic['pic']));
        header('Cache-Control: private, no-store');
        echo $pic['pic'];
        exit;
    }
    http_response_code(404);
    exit;
}

$editUser = null;
if (($_GET['action'] ?? '') === 'edit' && isset($_GET['id'])) {
    $editUser = getUser((int) $_GET['id']);
}

$users = getAllUsers();

// Check default_masking setting from DB
$defaultMasking = getSetting('default_masking', 'true') === 'true';
// If default masking is off, show unmasked data unless explicitly toggled
if (!$defaultMasking && !$revealData) {
    $revealData = true;
}

// Get attachments for edit user
$editUserFiles = [];
if ($editUser) {
    $editUserFiles = getUserFiles((int) $editUser['id']);
}

// Get attachments for all users (for download links in table)
$userAttachments = [];
foreach ($users as $u) {
    $userAttachments[$u['id']] = getUserFiles((int) $u['id']);
}

function handleUserAttachment(int $userId, string $attachmentType): array
{
    $file = $_FILES['attachment'];
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
    $maxSize = 10 * 1024 * 1024;

    $mimeType = mime_content_type($file['tmp_name']);
    if (!in_array($mimeType, $allowedTypes, true)) {
        return ['success' => false, 'error' => "ประเภทไฟล์ '{$mimeType}' ไม่ได้รับอนุญาต (JPEG, PNG, GIF, WebP, PDF เท่านั้น)"];
    }
    if ($file['size'] > $maxSize) {
        return ['success' => false, 'error' => 'ไฟล์ใหญ่เกิน 10 MB'];
    }

    $data = file_get_contents($file['tmp_name']);
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    $s3Key = 'attachments/users/' . $userId . '/' . $attachmentType . '/' . uniqid('file_') . '.' . $ext;

    $result = uploadDataToS3($data, $s3Key, $mimeType);
    if (!$result['success']) {
        return ['success' => false, 'error' => 'S3 upload ล้มเหลว: ' . $result['error']];
    }

    addFileRecord($file['name'], $s3Key, $mimeType, strlen($data), $result['key_hash'], $userId, $attachmentType);
    auditLog('FILE_UPLOAD', $userId, "แนบไฟล์ '{$file['name']}' ({$mimeType}, " . strlen($data) . " bytes) สำหรับผู้ใช้ ID {$userId}");

    return ['success' => true, 'name' => $file['name']];
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PostgreSQL 18 mTLS + pgcrypto Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8">
            <h1 class="text-3xl font-bold text-cyan-400">PostgreSQL 18 mTLS + pgcrypto Demo</h1>
            <p class="text-slate-400 mt-2">
                User CRUD — เข้ารหัสฟิลด์ข้อมูล + รูปโปรไฟล์ด้วย <code class="text-amber-400">pgp_sym_encrypt</code> (AES-256) · ไฟล์แนบเข้ารหัสใน S3 ด้วย <code class="text-teal-400">SSE-C</code>
            </p>
            <div class="mt-3 flex flex-wrap gap-3 text-sm">
                <span class="px-2 py-1 rounded bg-green-900/50 text-green-400 border border-green-800">mTLS: PHP ↔ PostgreSQL</span>
                <span class="px-2 py-1 rounded bg-blue-900/50 text-blue-400 border border-blue-800">pgcrypto: AES-256</span>
                <span class="px-2 py-1 rounded bg-teal-900/50 text-teal-400 border border-teal-800">S3: SSE-C</span>
                <span class="px-2 py-1 rounded bg-purple-900/50 text-purple-400 border border-purple-800">HTTPS: TLS 1.2/1.3 + PQC</span>
            </div>

            <div class="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                <!-- กลุ่ม: ข้อมูล -->
                <div class="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">📊 จัดการข้อมูล</div>
                    <div class="flex flex-col gap-1.5">
                        <a href="inspect.php" class="text-amber-400 hover:text-amber-300 transition">Inspect DB → <span class="text-slate-500 text-xs">ดูโครงสร้างตาราง & ข้อมูล</span></a>
                        <a href="search.php" class="text-cyan-400 hover:text-cyan-300 transition">Search → <span class="text-slate-500 text-xs">ค้นหาผู้ใช้ (ถอดรหัสได้)</span></a>
                    </div>
                </div>

                <!-- กลุ่ม: ความปลอดภัย -->
                <div class="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">🔐 ความปลอดภัย</div>
                    <div class="flex flex-col gap-1.5">
                        <a href="key-rotation.php" class="text-pink-400 hover:text-pink-300 transition">Key Rotation → <span class="text-slate-500 text-xs">หมุนเวียน pgcrypto key</span></a>
                        <a href="settings.php" class="text-slate-300 hover:text-white transition">Settings → <span class="text-slate-500 text-xs">ตั้งค่าระบบ (password)</span></a>
                        <a href="mtls-test.php" class="text-green-400 hover:text-green-300 transition">mTLS Test → <span class="text-slate-500 text-xs">ทดสอบ TLS connection</span></a>
                    </div>
                </div>

                <!-- กลุ่ม: S3 Storage -->
                <div class="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">☁️ S3 Object Storage</div>
                    <div class="flex flex-col gap-1.5">
                        <a href="upload.php" class="text-teal-400 hover:text-teal-300 transition">File Upload → <span class="text-slate-500 text-xs">อัพโหลดรูป/PDF (SSE-C)</span></a>
                        <a href="sse-c-test.php" class="text-amber-400 hover:text-amber-300 transition">SSE-C Test → <span class="text-slate-500 text-xs">ทดสอบการเข้ารหัสไฟล์</span></a>
                    </div>
                </div>

                <!-- กลุ่ม: ระบบ -->
                <div class="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">🛠️ ระบบ & API</div>
                    <div class="flex flex-col gap-1.5">
                        <a href="audit.php" class="text-purple-400 hover:text-purple-300 transition">Audit Log → <span class="text-slate-500 text-xs">บันทึกการเปลี่ยนแปลง</span></a>
                        <a href="backup.php" class="text-orange-400 hover:text-orange-300 transition">Backup → <span class="text-slate-500 text-xs">สำรองข้อมูล</span></a>
                        <a href="api-test.php" class="text-indigo-400 hover:text-indigo-300 transition">API Test → <span class="text-slate-500 text-xs">ทดสอบ REST API</span></a>
                    </div>
                </div>
            </div>
        </header>

        <!-- Messages -->
        <?php if ($message): ?>
            <div class="mb-4 p-3 rounded-lg bg-green-900/50 border border-green-700 text-green-300">
                ✓ <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="mb-4 p-3 rounded-lg bg-red-900/50 border border-red-700 text-red-300">
                ✗ <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <!-- Form -->
        <div class="mb-8 bg-slate-800 rounded-xl p-6 border border-slate-700">
            <h2 class="text-xl font-semibold mb-4 text-slate-200">
                <?= $editUser ? 'แก้ไขผู้ใช้' : 'เพิ่มผู้ใช้ใหม่' ?>
            </h2>
            <form method="POST" action="index.php" enctype="multipart/form-data" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                <input type="hidden" name="action" value="<?= $editUser ? 'update' : 'create' ?>">
                <?php if ($editUser): ?>
                    <input type="hidden" name="id" value="<?= (int) $editUser['id'] ?>">
                <?php endif; ?>

                <div>
                    <label class="block text-sm text-slate-400 mb-1">ชื่อ <span class="text-amber-400">(เข้ารหัส)</span></label>
                    <input type="text" name="name" required
                        value="<?= htmlspecialchars($editUser['name'] ?? '') ?>"
                        class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">Email <span class="text-amber-400">(เข้ารหัส)</span></label>
                    <input type="email" name="email" required
                        value="<?= htmlspecialchars($editUser['email'] ?? '') ?>"
                        class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">เบอร์โทร <span class="text-amber-400">(เข้ารหัส)</span></label>
                    <input type="tel" name="phone" required
                        value="<?= htmlspecialchars($editUser['phone'] ?? '') ?>"
                        class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                </div>

                <div>
                    <label class="block text-sm text-slate-400 mb-1">
                        รูปโปรไฟล์
                        <span class="text-purple-400">→ เก็บใน DB (pgcrypto AES-256)</span>
                    </label>
                    <?php if ($editUser && !empty($editUser['has_profile_pic'])): ?>
                        <div class="mb-2 flex items-center gap-3">
                            <img src="index.php?action=profile_pic&id=<?= (int) $editUser['id'] ?>"
                                 alt="รูปโปรไฟล์" class="w-16 h-16 rounded-full object-cover border-2 border-purple-500">
                            <span class="text-xs text-slate-500">รูปปัจจุบัน (ถอดรหัสจาก DB) — อัพโหลดใหม่เพื่อเปลี่ยน</span>
                        </div>
                    <?php endif; ?>
                    <input type="file" name="profile_pic" accept="image/jpeg,image/png,image/gif,image/webp"
                        class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-slate-100 text-sm file:mr-3 file:px-3 file:py-1 file:rounded file:bg-purple-600 file:text-white file:border-0 hover:file:bg-purple-500">
                    <p class="text-xs text-slate-500 mt-1">JPEG, PNG, GIF, WebP — สูงสุด 5 MB · เข้ารหัสด้วย pgp_sym_encrypt (AES-256) เก็บใน PostgreSQL</p>
                </div>

                <div>
                    <label class="block text-sm text-slate-400 mb-1">
                        แนบไฟล์ (สำเนาบัตรประชาชน / เอกสาร)
                        <span class="text-teal-400">→ เก็บใน S3 (SSE-C)</span>
                    </label>
                    <input type="file" name="attachment" accept="image/jpeg,image/png,image/gif,image/webp,application/pdf"
                        class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-slate-100 text-sm file:mr-3 file:px-3 file:py-1 file:rounded file:bg-teal-600 file:text-white file:border-0 hover:file:bg-teal-500">
                    <p class="text-xs text-slate-500 mt-1">JPEG, PNG, GIF, WebP, PDF — สูงสุด 10 MB · ไฟล์จะถูกเข้ารหัสด้วย SSE-C ที่ S3 server</p>
                </div>

                <?php if ($editUser && !empty($editUserFiles)): ?>
                    <div class="p-3 rounded-lg bg-slate-700/50 border border-slate-600">
                        <div class="text-xs font-bold text-slate-400 uppercase mb-2">📎 ไฟล์แนบปัจจุบัน (<?= count($editUserFiles) ?> ไฟล์)</div>
                        <div class="space-y-1">
                            <?php foreach ($editUserFiles as $ef): ?>
                                <div class="flex items-center justify-between text-sm">
                                    <span class="text-slate-300">
                                        <?= htmlspecialchars($ef['original_name']) ?>
                                        <span class="text-slate-500 text-xs">(<?= htmlspecialchars($ef['mime_type']) ?>, <?= number_format($ef['file_size']) ?> B)</span>
                                    </span>
                                    <div class="flex gap-2">
                                        <form method="POST" action="index.php" class="inline">
                                            <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                            <input type="hidden" name="action" value="download_file">
                                            <input type="hidden" name="file_id" value="<?= (int) $ef['id'] ?>">
                                            <button type="submit" class="text-teal-400 hover:text-teal-300 text-xs">ดาวน์โหลด</button>
                                        </form>
                                        <form method="POST" action="upload.php" class="inline" onsubmit="return confirm('ยืนยันการลบไฟล์?')">
                                            <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="file_id" value="<?= (int) $ef['id'] ?>">
                                            <button type="submit" class="text-red-400 hover:text-red-300 text-xs">ลบ</button>
                                        </form>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <div class="flex gap-3">
                    <button type="submit"
                        class="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">
                        <?= $editUser ? 'บันทึกการแก้ไข' : 'เพิ่มผู้ใช้' ?>
                    </button>
                    <?php if ($editUser): ?>
                        <a href="index.php" class="px-4 py-2 rounded-lg bg-slate-600 hover:bg-slate-500 text-white font-medium transition">
                            ยกเลิก
                        </a>
                    <?php endif; ?>
                </div>
            </form>
        </div>

        <!-- User List -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">รายการผู้ใช้ (<?= count($users) ?> คน)</h2>
                <p class="text-xs text-slate-500 mt-1">ข้อมูลถอดรหัสด้วย pgp_sym_decrypt แล้วทำ Data Masking ก่อนส่งให้ browser (server-side)</p>
                <div class="mt-3 flex items-center gap-3 text-xs">
                    <?php if ($revealData): ?>
                        <span class="px-2 py-1 rounded bg-green-900/50 text-green-400 border border-green-800">กำลังแสดงข้อมูลเต็ม</span>
                        <a href="index.php" class="px-3 py-1 rounded bg-slate-600 hover:bg-slate-500 text-white text-xs transition">← กลับไปแบบ Masking</a>
                    <?php else: ?>
                        <button onclick="openRevealModal()" class="px-3 py-1 rounded bg-amber-700 hover:bg-amber-600 text-white text-xs transition">ดูข้อมูลเต็ม</button>
                        <span class="text-slate-600">| ค่าเริ่มต้นแสดงแบบ masking เท่านั้น (server-side)</span>
                    <?php endif; ?>
                </div>
            </div>
            <?php if (empty($users)): ?>
                <div class="px-6 py-12 text-center text-slate-500">ยังไม่มีผู้ใช้ในระบบ</div>
            <?php else: ?>
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                            <th class="px-4 py-3 text-center whitespace-nowrap">รูปโปรไฟล์ <span class="text-purple-400">(DB)</span></th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ชื่อ <span class="text-amber-400">(masked)</span></th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">Email <span class="text-amber-400">(masked)</span></th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">เบอร์โทร <span class="text-amber-400">(masked)</span></th>
                            <th class="px-4 py-3 text-center whitespace-nowrap">ไฟล์แนบ <span class="text-teal-400">(S3)</span></th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">สร้างเมื่อ</th>
                            <th class="px-4 py-3 text-center whitespace-nowrap">จัดการ</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($users as $u): ?>
                            <tr class="hover:bg-slate-750 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $u['id'] ?></td>
                                <td class="px-4 py-3 text-center whitespace-nowrap">
                                    <?php if (!empty($u['has_profile_pic'])): ?>
                                        <img src="index.php?action=profile_pic&id=<?= (int) $u['id'] ?>"
                                             alt="รูปโปรไฟล์" class="w-10 h-10 rounded-full object-cover border border-purple-500 inline-block">
                                    <?php else: ?>
                                        <div class="w-10 h-10 rounded-full bg-slate-600 flex items-center justify-center text-slate-400 text-xs inline-flex">N/A</div>
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 font-medium <?= $revealData ? 'text-slate-200' : 'text-amber-400' ?> whitespace-nowrap">
                                    <?= htmlspecialchars($revealData ? $u['name'] : maskName($u['name'])) ?>
                                </td>
                                <td class="px-4 py-3 <?= $revealData ? 'text-green-400' : 'text-amber-400' ?> whitespace-nowrap">
                                    <?= htmlspecialchars($revealData ? $u['email'] : maskEmail($u['email'])) ?>
                                </td>
                                <td class="px-4 py-3 <?= $revealData ? 'text-green-400' : 'text-amber-400' ?> whitespace-nowrap">
                                    <?= htmlspecialchars($revealData ? $u['phone'] : maskPhone($u['phone'])) ?>
                                </td>
                                <td class="px-4 py-3 text-center whitespace-nowrap">
                                    <?php $atts = $userAttachments[$u['id']] ?? []; ?>
                                    <?php if (count($atts) > 0): ?>
                                        <?php if (count($atts) === 1): ?>
                                            <form method="POST" action="index.php" class="inline">
                                                <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                                <input type="hidden" name="action" value="download_file">
                                                <input type="hidden" name="file_id" value="<?= (int) $atts[0]['id'] ?>">
                                                <button type="submit" class="text-teal-400 hover:text-teal-300 text-xs" title="ดาวน์โหลด <?= htmlspecialchars($atts[0]['original_name']) ?>">
                                                    📎 ดาวน์โหลด
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <span class="text-teal-400">📎 <?= count($atts) ?> ไฟล์</span><br>
                                            <?php foreach ($atts as $af): ?>
                                                <form method="POST" action="index.php" class="inline">
                                                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                                    <input type="hidden" name="action" value="download_file">
                                                    <input type="hidden" name="file_id" value="<?= (int) $af['id'] ?>">
                                                    <button type="submit" class="text-teal-400 hover:text-teal-300 text-xs underline" title="<?= htmlspecialchars($af['original_name']) ?>">
                                                        <?= htmlspecialchars(mb_substr($af['original_name'], 0, 15)) ?>
                                                    </button>
                                                </form>
                                                <?php if ($af !== end($atts)): ?><span class="text-slate-600">·</span><?php endif; ?>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <span class="text-slate-600">—</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($u['created_at']) ?></td>
                                <td class="px-4 py-3 text-center whitespace-nowrap">
                                    <a href="index.php?action=edit&id=<?= (int) $u['id'] ?>"
                                       class="text-cyan-400 hover:text-cyan-300 mr-3">แก้ไข</a>
                                    <form method="POST" action="index.php" class="inline"
                                          onsubmit="return confirm('ยืนยันการลบ?')">
                                        <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="id" value="<?= (int) $u['id'] ?>">
                                        <button type="submit" class="text-red-400 hover:text-red-300">ลบ</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Footer -->
        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS (client cert) · pgcrypto pgp_sym_encrypt (AES-256) · Data Masking · nginx + php-fpm
        </footer>
    </div>

    <!-- Reveal Modal -->
    <div id="revealModal" class="fixed inset-0 z-50 hidden">
        <div class="absolute inset-0 bg-black/60" onclick="closeRevealModal()"></div>
        <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md">
            <div class="bg-slate-800 rounded-xl border border-slate-600 shadow-2xl p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-amber-400">ดูข้อมูลเต็ม</h3>
                    <button onclick="closeRevealModal()" class="text-slate-400 hover:text-slate-200 text-xl">&times;</button>
                </div>
                <p class="text-sm text-slate-400 mb-4">
                    กรอกรหัสผ่านเพื่อดูข้อมูลแบบเต็ม (ไม่ masked)<br>
                    ข้อมูลจะแสดงเฉพาะครั้งนี้ กด "กลับไปแบบ Masking" เพื่อกลับสู่ค่าเริ่มต้น
                </p>
                <form method="POST" action="index.php" class="space-y-4">
                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                    <input type="hidden" name="action" value="reveal">
                    <div>
                        <label class="block text-sm text-slate-400 mb-1">รหัสผ่าน</label>
                        <input type="password" name="reveal_password" required autofocus
                               class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-amber-500 focus:outline-none text-slate-100"
                               placeholder="ใส่รหัสผ่านดูข้อมูลเต็ม">
                    </div>
                    <div class="flex gap-3">
                        <button type="submit" class="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium transition">
                            ยืนยัน
                        </button>
                        <button type="button" onclick="closeRevealModal()" class="px-4 py-2 rounded-lg bg-slate-600 hover:bg-slate-500 text-white font-medium transition">
                            ยกเลิก
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
    function openRevealModal() {
        document.getElementById('revealModal').classList.remove('hidden');
    }
    function closeRevealModal() {
        document.getElementById('revealModal').classList.add('hidden');
    }
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeRevealModal();
    });
    </script>
</body>
</html>
