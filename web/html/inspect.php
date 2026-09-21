<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/mask.php';

$pdo = getDb();
$key = getCryptoKey();

// Fetch raw encrypted data alongside decrypted data
$sql = "SELECT id,
               name_encrypted,
               email_encrypted,
               phone_encrypted,
               pgp_sym_decrypt(name_encrypted, :key)  AS name_decrypted,
               pgp_sym_decrypt(email_encrypted, :key) AS email_decrypted,
               pgp_sym_decrypt(phone_encrypted, :key) AS phone_decrypted,
               to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
        FROM users
        ORDER BY id DESC";

$stmt = $pdo->prepare($sql);
$stmt->execute([':key' => $key]);
$rows = $stmt->fetchAll();

// Also fetch using postgres superuser to show raw hex (via a separate query)
$rawSql = "SELECT id, encode(name_encrypted, 'hex') AS name_hex, encode(email_encrypted, 'hex') AS email_hex, encode(phone_encrypted, 'hex') AS phone_hex FROM users ORDER BY id DESC";
$rawStmt = $pdo->query($rawSql);
$rawRows = $rawStmt ? $rawStmt->fetchAll() : [];
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inspect DB — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-6xl mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-amber-400">Inspect Database</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">
                เปรียบเทียบข้อมูลดิบใน DB (เข้ารหัส) กับข้อมูลถอดรหัสแล้ว — ยืนยันว่า pgcrypto เข้ารหัสจริง
            </p>
        </header>

        <!-- Summary -->
        <div class="mb-6 grid grid-cols-3 gap-4">
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">จำนวน Records</div>
                <div class="text-2xl font-bold text-cyan-400"><?= count($rows) ?></div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">Encryption</div>
                <div class="text-lg font-bold text-amber-400">pgp_sym_encrypt</div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div class="text-slate-400 text-sm">Algorithm</div>
                <div class="text-lg font-bold text-green-400">AES-256 (OpenPGP)</div>
            </div>
        </div>

        <?php if (empty($rows)): ?>
            <div class="bg-slate-800 rounded-xl p-12 text-center text-slate-500 border border-slate-700">
                ยังไม่มีข้อมูลในตาราง users
            </div>
        <?php else: ?>
            <!-- Comparison Table -->
            <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden mb-8">
                <div class="px-6 py-4 border-b border-slate-700">
                    <h2 class="text-xl font-semibold text-slate-200">เปรียบเทียบ: ข้อมูลใน DB (เข้ารหัส) vs ถอดรหัส vs Masked</h2>
                </div>
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-3 py-3 text-left">ID</th>
                            <th class="px-3 py-3 text-left">ชื่อ ใน DB (เข้ารหัส)</th>
                            <th class="px-3 py-3 text-left">ชื่อ ถอดรหัส</th>
                            <th class="px-3 py-3 text-left">ชื่อ Masked</th>
                            <th class="px-3 py-3 text-left">Email ใน DB (เข้ารหัส)</th>
                            <th class="px-3 py-3 text-left">Email ถอดรหัส</th>
                            <th class="px-3 py-3 text-left">Email Masked</th>
                            <th class="px-3 py-3 text-left">Phone ใน DB (เข้ารหัส)</th>
                            <th class="px-3 py-3 text-left">Phone ถอดรหัส</th>
                            <th class="px-3 py-3 text-left">Phone Masked</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($rows as $i => $row): ?>
                            <tr class="hover:bg-slate-750 transition">
                                <td class="px-3 py-3 text-slate-500"><?= (int) $row['id'] ?></td>
                                <td class="px-3 py-3">
                                    <div class="font-mono text-xs text-red-400 break-all max-w-xs">
                                        \x<?= bin2hex(stream_get_contents($row['name_encrypted'])) ?>
                                    </div>
                                </td>
                                <td class="px-3 py-3 text-green-400 font-medium">
                                    <?= htmlspecialchars($row['name_decrypted']) ?>
                                </td>
                                <td class="px-3 py-3 text-amber-400 font-medium">
                                    <?= htmlspecialchars(maskName($row['name_decrypted'])) ?>
                                </td>
                                <td class="px-3 py-3">
                                    <div class="font-mono text-xs text-red-400 break-all max-w-xs">
                                        \x<?= bin2hex(stream_get_contents($row['email_encrypted'])) ?>
                                    </div>
                                </td>
                                <td class="px-3 py-3 text-green-400 font-medium">
                                    <?= htmlspecialchars($row['email_decrypted']) ?>
                                </td>
                                <td class="px-3 py-3 text-amber-400 font-medium">
                                    <?= htmlspecialchars(maskEmail($row['email_decrypted'])) ?>
                                </td>
                                <td class="px-3 py-3">
                                    <div class="font-mono text-xs text-red-400 break-all max-w-xs">
                                        \x<?= bin2hex(stream_get_contents($row['phone_encrypted'])) ?>
                                    </div>
                                </td>
                                <td class="px-3 py-3 text-green-400 font-medium">
                                    <?= htmlspecialchars($row['phone_decrypted']) ?>
                                </td>
                                <td class="px-3 py-3 text-amber-400 font-medium">
                                    <?= htmlspecialchars(maskPhone($row['phone_decrypted'])) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Raw hex view -->
            <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-700">
                    <h2 class="text-xl font-semibold text-slate-200">Raw Hex (encode ฐาน 16)</h2>
                    <p class="text-xs text-slate-500 mt-1">ข้อมูลที่เก็บในคอลัมน์ <code class="text-amber-400">name_encrypted</code>, <code class="text-amber-400">email_encrypted</code> และ <code class="text-amber-400">phone_encrypted</code></p>
                </div>
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-4 py-3 text-left">ID</th>
                            <th class="px-4 py-3 text-left">name_encrypted (hex)</th>
                            <th class="px-4 py-3 text-left">email_encrypted (hex)</th>
                            <th class="px-4 py-3 text-left">phone_encrypted (hex)</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($rawRows as $raw): ?>
                            <tr>
                                <td class="px-4 py-3 text-slate-500"><?= (int) $raw['id'] ?></td>
                                <td class="px-4 py-3 font-mono text-xs text-red-400 break-all"><?= htmlspecialchars($raw['name_hex']) ?></td>
                                <td class="px-4 py-3 font-mono text-xs text-red-400 break-all"><?= htmlspecialchars($raw['email_hex']) ?></td>
                                <td class="px-4 py-3 font-mono text-xs text-red-400 break-all"><?= htmlspecialchars($raw['phone_hex']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Info -->
        <div class="mt-6 bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>วิธีอ่าน:</strong> คอลัมน์สีแดงคือข้อมูลดิบที่เก็บใน PostgreSQL (เข้ารหัสแล้ว — เป็น bytea binary)
            ส่วนคอลัมน์สีเขียวคือข้อมูลหลังถอดรหัสด้วย <code>pgp_sym_decrypt</code> ด้วย key เดียวกัน
            ถ้าไม่มี key จะไม่สามารถอ่านข้อมูลได้
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto pgp_sym_encrypt (AES-256) · inspect page
        </footer>
    </div>
</body>
</html>
