<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';

$message = '';
$error = '';
$rotationResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    enforceCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'rotate') {
        $rotationPassword = $_POST['rotation_password'] ?? '';
        $expectedPassword = getRevealPassword();

        if (!hash_equals($expectedPassword, $rotationPassword)) {
            $error = 'รหัสผ่านไม่ถูกต้อง';
        } else {
            $oldKey = getCryptoKey();
            $newKey = trim($_POST['new_key'] ?? '');
            $label  = trim($_POST['key_label'] ?? '');

            if (strlen($newKey) < 16) {
                $error = 'Key ใหม่ต้องมีความยาวอย่างน้อย 16 ตัวอักษร';
            } elseif ($newKey === $oldKey) {
                $error = 'Key ใหม่ต้องไม่ซ้ำกับ key เดิม';
            } else {
                $start = microtime(true);
                $result = rotateKey($oldKey, $newKey, $label ?: 'key-' . date('Y-m-d_His'));
                $elapsed = (microtime(true) - $start) * 1000;

                if ($result['success']) {
                    $rotationResult = $result;
                    $rotationResult['elapsed_ms'] = $elapsed;
                    $rotationResult['new_key'] = $newKey;
                    auditLog('KEY_ROTATION', null, "เปลี่ยน encryption key สำเร็จ: re-encrypt {$result['reencrypted']} แถว, รูป {$result['pics_reencrypted']} รูป, label={$label}");
                    $message = "เปลี่ยน key สำเร็จ — re-encrypt ข้อมูล {$result['reencrypted']} แถว, รูปโปรไฟล์ {$result['pics_reencrypted']} รูป ใน " . number_format($elapsed, 1) . " ms";
                } else {
                    $error = 'Key rotation ล้มเหลว: ' . $result['error'];
                }
            }
        }
    }
}

$history = getKeyHistory();
$pdo = getDb();
$stmt = $pdo->query("SELECT count(*) FROM users");
$userCount = (int) $stmt->fetchColumn();
$currentKey = getCryptoKey();
$currentKeyHash = hash('sha256', $currentKey);
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Key Rotation — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-4xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">Key Rotation</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">
                สาธิตการเปลี่ยน encryption key — re-encrypt ข้อมูลทั้งตารางด้วย key ใหม่ (decrypt ด้วย key เก่า → encrypt ด้วย key ใหม่)
            </p>
        </header>

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

        <?php if ($rotationResult): ?>
            <div class="mb-6 bg-green-900/30 border border-green-800 rounded-lg p-4 text-sm text-green-300">
                <strong>ผลการ Key Rotation:</strong>
                <ul class="mt-2 space-y-1 list-disc list-inside">
                    <li>Re-encrypt สำเร็จ: <strong><?= $rotationResult['reencrypted'] ?></strong> แถว</li>
                    <li>รูปโปรไฟล์ re-encrypt: <strong><?= $rotationResult['pics_reencrypted'] ?></strong> รูป</li>
                    <li>เวลาที่ใช้: <strong><?= number_format($rotationResult['elapsed_ms'], 2) ?></strong> ms</li>
                    <li>Key ใหม่: <code class="text-amber-400"><?= htmlspecialchars($rotationResult['new_key']) ?></code></li>
                    <li>Key ใหม่เขียนลง runtime file อัตโนมัติ — ไม่ต้องแก้ .env หรือ restart</li>
                </ul>
                <div class="mt-3 p-3 bg-amber-900/30 border border-amber-800 rounded text-amber-300">
                    <strong>⚠ หมายเหตุ:</strong> ในระบบจริง key ใหม่ควรเก็บใน KMS/Vault ไม่ใช่ใน .env
                    และควรมี key versioning เพื่อรองรับข้อมูลที่เข้ารหัสด้วย key เก่า
                </div>
            </div>
        <?php endif; ?>

        <!-- Current Key Info -->
        <div class="mb-6 grid grid-cols-3 gap-4">
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">ข้อมูลใน DB</div>
                <div class="text-2xl font-bold text-cyan-400"><?= $userCount ?> แถว</div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">Key Hash (SHA-256)</div>
                <div class="text-xs font-mono text-amber-400 break-all"><?= substr($currentKeyHash, 0, 32) ?>...</div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">จำนวนครั้งที่เปลี่ยน key</div>
                <div class="text-2xl font-bold text-purple-400"><?= count($history) ?></div>
            </div>
        </div>

        <!-- Rotation Form -->
        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-4">เปลี่ยน Encryption Key</h2>
            <form method="POST" action="key-rotation.php" class="space-y-4" onsubmit="return confirm('ยืนยันการเปลี่ยน key? ข้อมูลทั้งหมดจะถูก re-encrypt')">
                <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                <input type="hidden" name="action" value="rotate">
                <div>
                    <label class="block text-sm text-slate-400 mb-1">รหัสผ่านยืนยัน</label>
                    <input type="password" name="rotation_password" required
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100"
                           placeholder="ใส่รหัสผ่านเดียวกับ reveal password">
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">Key ใหม่ (อย่างน้อย 16 ตัวอักษร)</label>
                    <input type="text" name="new_key" required minlength="16"
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100 font-mono"
                           placeholder="เช่น NewSecretKey_2025_Rotated!@#">
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">Label (ชื่อ key สำหรับบันทึกประวัติ)</label>
                    <input type="text" name="key_label"
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100"
                           placeholder="เช่น key-v2-2025">
                </div>
                <button type="submit" class="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium transition">
                    เปลี่ยน Key (Re-encrypt ทั้งตาราง)
                </button>
            </form>
        </div>

        <!-- Key History -->
        <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">ประวัติการเปลี่ยน Key</h2>
            </div>
            <?php if (empty($history)): ?>
                <div class="px-6 py-8 text-center text-slate-500">ยังไม่มีประวัติ</div>
            <?php else: ?>
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">Label</th>
                            <th class="px-4 py-3 text-left">Key Hash (SHA-256)</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">เปลี่ยนโดย</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">เวลา</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($history as $h): ?>
                            <tr class="hover:bg-slate-750 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $h['id'] ?></td>
                                <td class="px-4 py-3 text-cyan-400 font-medium whitespace-nowrap"><?= htmlspecialchars($h['key_label']) ?></td>
                                <td class="px-4 py-3 text-xs font-mono text-amber-400 break-all"><?= htmlspecialchars(substr($h['key_hash'], 0, 32)) ?>...</td>
                                <td class="px-4 py-3 text-slate-400 whitespace-nowrap"><?= htmlspecialchars($h['rotated_by']) ?></td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($h['rotated_at']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <!-- Info -->
        <div class="bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>วิธีการทำงาน:</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li>ใช้ key เก่า <code>pgp_sym_decrypt</code> ข้อมูลทั้งหมด → แล้ว <code>pgp_sym_encrypt</code> ใหม่ด้วย key ใหม่</li>
                <li>ทำใน <strong>transaction เดียว</strong> — ถ้ามี error จะ rollback ข้อมูลกลับเป็น key เดิม</li>
                <li>Re-encrypt ทั้ง text fields (name, email, phone) และ <strong>รูปโปรไฟล์ (bytea)</strong></li>
                <li>HMAC index ก็ถูกคำนวณใหม่ด้วย key ใหม่เช่นกัน</li>
                <li>บันทึกประวัติในตาราง <code>key_history</code> (เก็บเฉพาะ hash ของ key ไม่เก็บ key จริง)</li>
                <li><strong>Key ใหม่เขียนลง runtime file หลัง commit</strong> — ถ้า transaction ล้มเหลว key เดิมยังใช้ได้</li>
            </ul>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Key Rotation (re-encrypt)
        </footer>
    </div>
</body>
</html>
