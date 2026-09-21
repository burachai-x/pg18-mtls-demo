<?php

require_once __DIR__ . '/auth.php';

$host = getenv('DB_HOST') ?: 'db';
$port = getenv('DB_PORT') ?: '5432';
$dbname = getenv('DB_NAME') ?: 'appdb';
$user   = getenv('DB_USER') ?: 'webapp';
$password = getenv('DB_PASSWORD') ?: null;

$certDir     = rtrim(getenv('PG_CERT_DIR') ?: '/tmp/pg-certs', '/');
$sslRootCert = $certDir . '/ca.crt';
$sslCert     = $certDir . '/client.crt';
$sslKey      = $certDir . '/client.key';

$results = [];

// ── Test 1: No client cert ──
$dsn1 = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=verify-full;sslrootcert={$sslRootCert}";
try {
    $pdo = new PDO($dsn1, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->query("SELECT 1");
    $results[] = [
        'name'    => '1. ไม่มี client cert',
        'desc'    => 'เชื่อมต่อโดยไม่ส่ง client certificate',
        'expect'  => 'FAIL',
        'actual'  => 'SUCCESS',
        'passed'  => false,
        'detail'  => 'ไม่ควรเชื่อมต่อได้ แต่กลับเชื่อมต่อสำเร็จ (มีปัญหา!)',
    ];
} catch (PDOException $e) {
    $results[] = [
        'name'    => '1. ไม่มี client cert',
        'desc'    => 'เชื่อมต่อโดยไม่ส่ง client certificate',
        'expect'  => 'FAIL',
        'actual'  => 'FAIL',
        'passed'  => true,
        'detail'  => $e->getMessage(),
    ];
}

// ── Test 2: Valid client cert ──
$dsn2 = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=verify-full;sslrootcert={$sslRootCert};sslcert={$sslCert};sslkey={$sslKey}";
try {
    $pdo = new PDO($dsn2, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $stmt = $pdo->query("SELECT 1 AS test");
    $row = $stmt->fetch();
    $results[] = [
        'name'    => '2. มี client cert ที่ถูกต้อง',
        'desc'    => 'เชื่อมต่อด้วย client cert ที่ลงนามโดย CA ของเรา',
        'expect'  => 'SUCCESS',
        'actual'  => 'SUCCESS',
        'passed'  => true,
        'detail'  => 'เชื่อมต่อสำเร็จ — query SELECT 1 ได้ผล: ' . $row['test'],
    ];
} catch (PDOException $e) {
    $results[] = [
        'name'    => '2. มี client cert ที่ถูกต้อง',
        'desc'    => 'เชื่อมต่อด้วย client cert ที่ลงนามโดย CA ของเรา',
        'expect'  => 'SUCCESS',
        'actual'  => 'FAIL',
        'passed'  => false,
        'detail'  => $e->getMessage(),
    ];
}

// ── Test 3: Wrong client cert (not signed by our CA) ──
$fakeCert = '/tmp/fake_client.crt';
$fakeKey  = '/tmp/fake_client.key';
@shell_exec("openssl req -new -x509 -nodes -keyout {$fakeKey} -out {$fakeCert} -subj '/CN=attacker' -days 1 2>/dev/null");
@chmod($fakeKey, 0600);

if (file_exists($fakeCert) && file_exists($fakeKey)) {
    $dsn3 = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=verify-full;sslrootcert={$sslRootCert};sslcert={$fakeCert};sslkey={$fakeKey}";
    try {
        $pdo = new PDO($dsn3, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->query("SELECT 1");
        $results[] = [
            'name'    => '3. Client cert ปลอม (ไม่ได้ลงนามโดย CA)',
            'desc'    => 'ใช้ self-signed cert ที่ไม่ใช่ของ CA ของเรา',
            'expect'  => 'FAIL',
            'actual'  => 'SUCCESS',
            'passed'  => false,
            'detail'  => 'ไม่ควรเชื่อมต่อได้ แต่กลับเชื่อมต่อสำเร็จ (มีปัญหา!)',
        ];
    } catch (PDOException $e) {
        $results[] = [
            'name'    => '3. Client cert ปลอม (ไม่ได้ลงนามโดย CA)',
            'desc'    => 'ใช้ self-signed cert ที่ไม่ใช่ของ CA ของเรา',
            'expect'  => 'FAIL',
            'actual'  => 'FAIL',
            'passed'  => true,
            'detail'  => $e->getMessage(),
        ];
    }
} else {
    $results[] = [
        'name'    => '3. Client cert ปลอม (ไม่ได้ลงนามโดย CA)',
        'desc'    => 'ใช้ self-signed cert ที่ไม่ใช่ของ CA ของเรา',
        'expect'  => 'FAIL',
        'actual'  => 'SKIP',
        'passed'  => true,
        'detail'  => 'ไม่สามารถสร้าง fake cert สำหรับทดสอบได้',
    ];
}

// ── Test 3b: Valid client cert but wrong password ──
// pg_hba uses scram-sha-256 + clientcert=verify-full: the certificate alone
// must not be enough to get in.
$dsnPw = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=verify-full;sslrootcert={$sslRootCert};sslcert={$sslCert};sslkey={$sslKey}";
try {
    $pdo = new PDO($dsnPw, $user, 'definitely-not-the-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->query("SELECT 1");
    $results[] = [
        'name'    => '3b. cert ถูกต้อง แต่รหัสผ่านผิด',
        'desc'    => 'ใช้ client cert ที่ถูกต้อง แต่ส่งรหัสผ่านผิด (ทดสอบปัจจัยที่สอง)',
        'expect'  => 'FAIL',
        'actual'  => 'SUCCESS',
        'passed'  => false,
        'detail'  => 'ไม่ควรเชื่อมต่อได้ — แปลว่ารหัสผ่านไม่ได้ถูกตรวจ (มีปัญหา!)',
    ];
} catch (PDOException $e) {
    $results[] = [
        'name'    => '3b. cert ถูกต้อง แต่รหัสผ่านผิด',
        'desc'    => 'ใช้ client cert ที่ถูกต้อง แต่ส่งรหัสผ่านผิด (ทดสอบปัจจัยที่สอง)',
        'expect'  => 'FAIL',
        'actual'  => 'FAIL',
        'passed'  => true,
        'detail'  => $e->getMessage(),
    ];
}

// ── Test 4: Wrong CA (untrusted server) ──
$fakeCA = '/tmp/fake_ca.crt';
@shell_exec("openssl req -new -x509 -nodes -keyout /tmp/fake_ca.key -out {$fakeCA} -subj '/CN=FakeCA' -days 1 2>/dev/null");

if (file_exists($fakeCA)) {
    $dsn4 = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=verify-full;sslrootcert={$fakeCA};sslcert={$sslCert};sslkey={$sslKey}";
    try {
        $pdo = new PDO($dsn4, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->query("SELECT 1");
        $results[] = [
            'name'    => '4. CA ผิด (ไม่ trust server)',
            'desc'    => 'ใช้ CA ตัวอื่นในการ verify server cert',
            'expect'  => 'FAIL',
            'actual'  => 'SUCCESS',
            'passed'  => false,
            'detail'  => 'ไม่ควรเชื่อมต่อได้ แต่กลับเชื่อมต่อสำเร็จ (มีปัญหา!)',
        ];
    } catch (PDOException $e) {
        $results[] = [
            'name'    => '4. CA ผิด (ไม่ trust server)',
            'desc'    => 'ใช้ CA ตัวอื่นในการ verify server cert',
            'expect'  => 'FAIL',
            'actual'  => 'FAIL',
            'passed'  => true,
            'detail'  => $e->getMessage(),
        ];
    }
} else {
    $results[] = [
        'name'    => '4. CA ผิด (ไม่ trust server)',
        'desc'    => 'ใช้ CA ตัวอื่นในการ verify server cert',
        'expect'  => 'FAIL',
        'actual'  => 'SKIP',
        'passed'  => true,
        'detail'  => 'ไม่สามารถสร้าง fake CA สำหรับทดสอบได้',
    ];
}

// ── Test 5: No SSL (plaintext) ──
$dsn5 = "pgsql:host={$host};port={$port};dbname={$dbname};sslmode=disable";
try {
    $pdo = new PDO($dsn5, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->query("SELECT 1");
    $results[] = [
        'name'    => '5. ไม่ใช้ SSL (plaintext)',
        'desc'    => 'พยายามเชื่อมต่อแบบไม่เข้ารหัส',
        'expect'  => 'FAIL',
        'actual'  => 'SUCCESS',
        'passed'  => false,
        'detail'  => 'ไม่ควรเชื่อมต่อได้ แต่กลับเชื่อมต่อสำเร็จ (มีปัญหา!)',
    ];
} catch (PDOException $e) {
    $results[] = [
        'name'    => '5. ไม่ใช้ SSL (plaintext)',
        'desc'    => 'พยายามเชื่อมต่อแบบไม่เข้ารหัส',
        'expect'  => 'FAIL',
        'actual'  => 'FAIL',
        'passed'  => true,
        'detail'  => $e->getMessage(),
    ];
}

$allPassed = true;
foreach ($results as $r) {
    if (!$r['passed']) {
        $allPassed = false;
        break;
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mTLS Test — PostgreSQL 18 Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-green-400">mTLS Test</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
                <a href="inspect.php" class="text-amber-400 hover:text-amber-300 text-sm">Inspect DB →</a>
            </div>
            <p class="text-slate-400">
                ทดสอบว่า mTLS บังคับใช้จริง — client ที่ไม่มี cert หรือ cert ไม่ถูกต้องจะเชื่อมต่อไม่ได้
            </p>
        </header>

        <!-- Summary -->
        <div class="mb-6 flex gap-4">
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 flex-1">
                <div class="text-slate-400 text-sm">ผลรวม</div>
                <div class="text-2xl font-bold <?= $allPassed ? 'text-green-400' : 'text-red-400' ?>">
                    <?= $allPassed ? '✓ ผ่านทั้งหมด' : '✗ มีข้อผิดพลาด' ?>
                </div>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700 flex-1">
                <div class="text-slate-400 text-sm">จำนวน Tests</div>
                <div class="text-2xl font-bold text-cyan-400"><?= count($results) ?></div>
            </div>
        </div>

        <!-- Test Results -->
        <div class="space-y-4">
            <?php foreach ($results as $r): ?>
                <div class="bg-slate-800 rounded-xl border <?= $r['passed'] ? 'border-green-800' : 'border-red-800' ?> overflow-hidden">
                    <div class="px-6 py-4 flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-semibold text-slate-200"><?= htmlspecialchars($r['name']) ?></h3>
                            <p class="text-sm text-slate-400 mt-1"><?= htmlspecialchars($r['desc']) ?></p>
                        </div>
                        <div class="flex items-center gap-3 ml-4 shrink-0">
                            <div class="text-center">
                                <div class="text-xs text-slate-500">คาดหวัง</div>
                                <div class="font-bold <?= $r['expect'] === 'SUCCESS' ? 'text-green-400' : 'text-red-400' ?>">
                                    <?= $r['expect'] ?>
                                </div>
                            </div>
                            <div class="text-2xl text-slate-600">→</div>
                            <div class="text-center">
                                <div class="text-xs text-slate-500">ผลจริง</div>
                                <div class="font-bold <?= $r['actual'] === 'SUCCESS' ? 'text-green-400' : ($r['actual'] === 'SKIP' ? 'text-slate-400' : 'text-red-400') ?>">
                                    <?= $r['actual'] ?>
                                </div>
                            </div>
                            <div class="text-2xl">
                                <?= $r['passed'] ? '✅' : '❌' ?>
                            </div>
                        </div>
                    </div>
                    <div class="px-6 py-3 bg-slate-900/50 border-t border-slate-700">
                        <div class="text-xs text-slate-500 mb-1">รายละเอียด:</div>
                        <div class="font-mono text-xs <?= $r['passed'] ? 'text-slate-400' : 'text-red-400' ?> break-all">
                            <?= htmlspecialchars($r['detail']) ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- Info -->
        <div class="mt-6 bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>คำอธิบาย:</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li>Test 1: ไม่ส่ง client cert → PostgreSQL ต้องปฏิเสธ (ต้องมี cert)</li>
                <li>Test 2: ส่ง cert ที่ถูกต้อง → ต้องเชื่อมต่อได้</li>
                <li>Test 3: ส่ง cert ปลอม → PostgreSQL ต้องปฏิเสธ (CA ไม่รู้จัก)</li>
                <li>Test 4: ใช้ CA ผิด → ต้องปฏิเสธ (verify server ไม่ได้)</li>
                <li>Test 5: ไม่ใช้ SSL → ต้องปฏิเสธ (บังคับ hostssl)</li>
            </ul>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS (client cert required) · pg_hba.conf: hostssl + clientcert=verify-full
        </footer>
    </div>
</body>
</html>
