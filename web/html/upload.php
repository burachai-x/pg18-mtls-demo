<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/s3.php';

$message = '';
$error = '';
$files = getFileRecords();

$allowedMimes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
];

$maxFileSize = 10 * 1024 * 1024; // 10 MB

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    enforceCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'upload') {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            $error = 'กรุณาเลือกไฟล์ที่จะอัพโหลด';
        } else {
            $file = $_FILES['file'];
            $mimeType = mime_content_type($file['tmp_name']);
            $fileSize = $file['size'];
            $originalName = $file['name'];

            if (!in_array($mimeType, $allowedMimes, true)) {
                $error = "ประเภทไฟล์ไม่ได้รับอนุญาต: {$mimeType} (อนุญาตเฉพาะ: JPEG, PNG, GIF, WebP, PDF)";
            } elseif ($fileSize > $maxFileSize) {
                $error = 'ขนาดไฟล์เกิน 10 MB';
            } else {
                $ext = pathinfo($originalName, PATHINFO_EXTENSION);
                $s3Key = 'uploads/' . date('Y/m/') . uniqid('file_', true) . '.' . $ext;

                $result = uploadFileToS3($file['tmp_name'], $s3Key, $mimeType);

                if ($result['success']) {
                    $fileId = addFileRecord($originalName, $s3Key, $mimeType, $fileSize, $result['key_hash']);
                    auditLog('FILE_UPLOAD', $fileId, "อัพโหลดไฟล์ '{$originalName}' ไป S3 (SSE-C), {$fileSize} bytes");
                    $message = "อัพโหลด '{$originalName}' สำเร็จ — เก็บใน S3 พร้อม SSE-C encryption (ID: {$fileId})";
                    $files = getFileRecords();
                } else {
                    $error = 'S3 upload ล้มเหลว: ' . $result['error'];
                }
            }
        }
    } elseif ($action === 'delete') {
        $fileId = (int) ($_POST['file_id'] ?? 0);
        $record = getFileRecord($fileId);
        if (!$record) {
            $error = 'ไม่พบไฟล์ ID ' . $fileId;
        } else {
            $s3Deleted = deleteFileFromS3($record['s3_key']);
            if (!$s3Deleted) {
                $error = "ลบไฟล์จาก S3 ล้มเหลว — ไฟล์ยังอยู่ใน S3 แต่ metadata ไม่ถูกลบ (s3_key: {$record['s3_key']})";
                auditLog('FILE_DELETE_FAILED', $fileId, "ลบไฟล์ '{$record['original_name']}' จาก S3 ล้มเหลว — orphaned object");
            } else {
                deleteFileRecord($fileId);
                auditLog('FILE_DELETE', $fileId, "ลบไฟล์ '{$record['original_name']}' จาก S3 สำเร็จ");
                $message = "ลบไฟล์ '{$record['original_name']}' สำเร็จ";
                $files = getFileRecords();
            }
        }
    } elseif ($action === 'download') {
        $fileId = (int) ($_POST['file_id'] ?? 0);
        $record = getFileRecord($fileId);
        if (!$record) {
            $error = 'ไม่พบไฟล์ ID ' . $fileId;
        } else {
            $data = downloadFileFromS3($record['s3_key']);
            if ($data === null) {
                $error = 'ดาวน์โหลดจาก S3 ล้มเหลว';
            } else {
                auditLog('FILE_DOWNLOAD', $fileId, "ดาวน์โหลดไฟล์ '{$record['original_name']}' จาก S3 (SSE-C decrypt)");
                // Sanitize filename: strip CR/LF to prevent header injection
                $safeName = str_replace(["\r", "\n", "\0"], '', $record['original_name']);
                // RFC 5987 encoding for non-ASCII filenames
                $encodedName = rawurlencode($safeName);
                header('Content-Type: ' . $record['mime_type']);
                header("Content-Disposition: attachment; filename=\"{$safeName}\"; filename*=UTF-8''{$encodedName}");
                header('Content-Length: ' . strlen($data));
                echo $data;
                exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload (S3 + SSE-C) — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">File Upload</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">
                อัพโหลดรูปภาพหรือ PDF — เก็บใน <strong>Garage S3</strong> พร้อม <strong>SSE-C encryption</strong>
                (Server-Side Encryption with Customer-provided Key)
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

        <!-- Upload Form -->
        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-4">อัพโหลดไฟล์ใหม่</h2>
            <form method="POST" action="upload.php" enctype="multipart/form-data" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                <input type="hidden" name="action" value="upload">
                <div>
                    <label class="block text-sm text-slate-400 mb-2">เลือกไฟล์ (JPEG, PNG, GIF, WebP, PDF — สูงสุด 10 MB)</label>
                    <input type="file" name="file" accept="image/jpeg,image/png,image/gif,image/webp,application/pdf" required
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100
                                  file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-cyan-600 file:text-white file:cursor-pointer file:hover:bg-cyan-500">
                </div>
                <button type="submit" class="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">
                    อัพโหลดไป S3 (SSE-C)
                </button>
            </form>
        </div>

        <!-- SSE-C Info -->
        <div class="bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300 mb-6">
            <strong>SSE-C (Server-Side Encryption with Customer-provided Keys):</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li>ไฟล์ถูกเข้ารหัสที่ S3 server ด้วย key ที่เราส่งไป (AES-256)</li>
                <li>S3 ไม่เก็บ key ของเรา — ถ้าไม่มี key จะดาวน์โหลดไฟล์ไม่ได้</li>
                <li>Key เก็บในตาราง <code>app_settings</code> (เข้าถึงผ่าน mTLS DB connection)</li>
                <li>ในตาราง <code>file_storage</code> เก็บเฉพาะ hash ของ key — ไม่เก็บ key จริง</li>
            </ul>
        </div>

        <!-- File List -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">ไฟล์ที่อัพโหลด (<?= count($files) ?> ไฟล์)</h2>
            </div>
            <?php if (empty($files)): ?>
                <div class="px-6 py-8 text-center text-slate-500">ยังไม่มีไฟล์ — อัพโหลดไฟล์แรกได้เลย</div>
            <?php else: ?>
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                            <th class="px-4 py-3 text-left">ชื่อไฟล์</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ประเภท</th>
                            <th class="px-4 py-3 text-right whitespace-nowrap">ขนาด</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">SSE-C Key Hash</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">อัพโหลดโดย</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">เวลา</th>
                            <th class="px-4 py-3 text-center whitespace-nowrap">การจัดการ</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($files as $f): ?>
                            <tr class="hover:bg-slate-750 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $f['id'] ?></td>
                                <td class="px-4 py-3 text-slate-300">
                                    <?php
                                    $isImage = str_starts_with($f['mime_type'], 'image/');
                                    $icon = $isImage ? '🖼️' : '📄';
                                    ?>
                                    <span class="mr-1"><?= $icon ?></span>
                                    <?= htmlspecialchars($f['original_name']) ?>
                                </td>
                                <td class="px-4 py-3 text-slate-400 whitespace-nowrap text-xs"><?= htmlspecialchars($f['mime_type']) ?></td>
                                <td class="px-4 py-3 text-slate-400 text-right whitespace-nowrap">
                                    <?= number_format($f['file_size']) ?> B
                                    <?php if ($f['file_size'] >= 1024): ?>
                                        (<?= number_format($f['file_size'] / 1024, 1) ?> KB)
                                    <?php endif; ?>
                                </td>
                                <td class="px-4 py-3 text-xs font-mono text-amber-400 whitespace-nowrap">
                                    <?= substr($f['sse_c_key_hash'], 0, 16) ?>...
                                </td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($f['uploaded_by']) ?></td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($f['created_at']) ?></td>
                                <td class="px-4 py-3 text-center whitespace-nowrap">
                                    <form method="POST" action="upload.php" class="inline">
                                        <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                        <input type="hidden" name="action" value="download">
                                        <input type="hidden" name="file_id" value="<?= (int) $f['id'] ?>">
                                        <button type="submit" class="text-cyan-400 hover:text-cyan-300 text-xs mr-3">ดาวน์โหลด</button>
                                    </form>
                                    <form method="POST" action="upload.php" class="inline" onsubmit="return confirm('ยืนยันการลบไฟล์?')">
                                        <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="file_id" value="<?= (int) $f['id'] ?>">
                                        <button type="submit" class="text-red-400 hover:text-red-300 text-xs">ลบ</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Garage S3 · SSE-C Encryption
        </footer>
    </div>
</body>
</html>
