<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/mask.php';

$searchField = $_GET['field'] ?? 'email';
$searchValue = trim($_GET['value'] ?? '');
$method      = $_GET['method'] ?? 'hmac';

$results = [];
$hmacTime = 0;
$decryptTime = 0;
$searched = false;

if ($searchValue !== '' && in_array($searchField, ['email', 'phone'], true)) {
    $searched = true;

    if ($method === 'hmac') {
        $start = microtime(true);
        $results = searchByHmac($searchField, $searchValue);
        $hmacTime = (microtime(true) - $start) * 1000;
    } else {
        $start = microtime(true);
        $results = searchByDecrypt($searchField, $searchValue);
        $decryptTime = (microtime(true) - $start) * 1000;
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Encrypted Data — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">Search Encrypted Data</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">
                เปรียบเทียบการค้นหาข้อมูลที่เข้ารหัส: <strong class="text-green-400">HMAC Index</strong> (ไม่ต้อง decrypt) vs <strong class="text-amber-400">Decrypt All</strong> (คลายรหัสทุกแถว)
            </p>
        </header>

        <!-- Search Form -->
        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6">
            <form method="GET" action="search.php" class="space-y-4">
                <div class="grid grid-cols-3 gap-4">
                    <div>
                        <label class="block text-sm text-slate-400 mb-1">ฟิลด์ที่ค้นหา</label>
                        <select name="field" class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                            <option value="email" <?= $searchField === 'email' ? 'selected' : '' ?>>Email</option>
                            <option value="phone" <?= $searchField === 'phone' ? 'selected' : '' ?>>เบอร์โทร</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm text-slate-400 mb-1">วิธีค้นหา</label>
                        <select name="method" class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                            <option value="hmac" <?= $method === 'hmac' ? 'selected' : '' ?>>HMAC Index (fast)</option>
                            <option value="decrypt" <?= $method === 'decrypt' ? 'selected' : '' ?>>Decrypt All (slow)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm text-slate-400 mb-1">คำค้นหา (exact match)</label>
                        <input type="text" name="value" value="<?= htmlspecialchars($searchValue) ?>" required
                               class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100"
                               placeholder="เช่น somchai.jaidee@gmail.com">
                    </div>
                </div>
                <div class="flex gap-3">
                    <button type="submit" class="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition">
                        ค้นหา
                    </button>
                    <span class="text-xs text-slate-500 self-center">
                        ลองค้นหา: <a href="search.php?field=email&method=hmac&value=somchai.jaidee@gmail.com" class="text-cyan-400 hover:underline">somchai.jaidee@gmail.com</a>
                        หรือ <a href="search.php?field=phone&method=hmac&value=0812345678" class="text-cyan-400 hover:underline">0812345678</a>
                    </span>
                </div>
            </form>
        </div>

        <?php if ($searched): ?>
            <!-- Performance -->
            <div class="mb-6 grid grid-cols-3 gap-4">
                <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <div class="text-slate-400 text-sm">วิธีที่ใช้</div>
                    <div class="text-lg font-bold <?= $method === 'hmac' ? 'text-green-400' : 'text-amber-400' ?>">
                        <?= $method === 'hmac' ? 'HMAC Index' : 'Decrypt All' ?>
                    </div>
                </div>
                <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <div class="text-slate-400 text-sm">เวลาที่ใช้</div>
                    <div class="text-lg font-bold text-cyan-400">
                        <?= number_format($method === 'hmac' ? $hmacTime : $decryptTime, 2) ?> ms
                    </div>
                </div>
                <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <div class="text-slate-400 text-sm">ผลลัพธ์</div>
                    <div class="text-lg font-bold text-slate-200"><?= count($results) ?> รายการ</div>
                </div>
            </div>

            <!-- Comparison info -->
            <div class="mb-6 bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
                <strong>เปรียบเทียบ:</strong>
                <ul class="mt-2 space-y-1 list-disc list-inside">
                    <li><strong class="text-green-400">HMAC Index:</strong> คำนวณ HMAC ของคำค้นหาแล้วเทียบกับคอลัมน์ <code>email_hmac</code> ที่มี index — <strong>ไม่ต้อง decrypt</strong> ข้อมูลเลย ใช้ index lookup</li>
                    <li><strong class="text-amber-400">Decrypt All:</strong> คลายรหัส <code>pgp_sym_decrypt</code> ทุกแถวในตารางแล้วเทียบค่า — <strong>ช้ากว่า</strong> และเปิดเผยข้อมูลใน memory</li>
                    <li>HMAC รองรับเฉพาะ <strong>exact match</strong> เท่านั้น (ไม่สามารถ LIKE หรือ partial search ได้)</li>
                </ul>
            </div>

            <!-- Results -->
            <?php if (empty($results)): ?>
                <div class="bg-slate-800 rounded-xl p-12 text-center text-slate-500 border border-slate-700">
                    ไม่พบข้อมูลที่ตรงกับ "<?= htmlspecialchars($searchValue) ?>"
                </div>
            <?php else: ?>
                <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                    <div class="px-6 py-4 border-b border-slate-700">
                        <h2 class="text-xl font-semibold text-slate-200">ผลการค้นหา (<?= count($results) ?> รายการ)</h2>
                    </div>
                    <table class="w-full text-sm">
                        <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                            <tr>
                                <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                                <th class="px-4 py-3 text-left whitespace-nowrap">ชื่อ</th>
                                <th class="px-4 py-3 text-left whitespace-nowrap">Email</th>
                                <th class="px-4 py-3 text-left whitespace-nowrap">เบอร์โทร</th>
                                <th class="px-4 py-3 text-left whitespace-nowrap">สร้างเมื่อ</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700">
                            <?php foreach ($results as $u): ?>
                                <tr class="hover:bg-slate-750 transition">
                                    <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $u['id'] ?></td>
                                    <td class="px-4 py-3 font-medium text-amber-400 whitespace-nowrap"><?= htmlspecialchars(maskName($u['name'])) ?></td>
                                    <td class="px-4 py-3 text-amber-400 whitespace-nowrap"><?= htmlspecialchars(maskEmail($u['email'])) ?></td>
                                    <td class="px-4 py-3 text-amber-400 whitespace-nowrap"><?= htmlspecialchars(maskPhone($u['phone'])) ?></td>
                                    <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($u['created_at']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <div class="bg-slate-800 rounded-xl p-8 text-center text-slate-500 border border-slate-700">
                กรอกคำค้นหาแล้วกด "ค้นหา" เพื่อเริ่ม
            </div>
        <?php endif; ?>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Searchable Encryption (HMAC + pgp_sym_encrypt)
        </footer>
    </div>
</body>
</html>
