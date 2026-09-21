<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/s3.php';
require_once __DIR__ . '/crud.php';

$demo = $_GET['demo'] ?? '';
?>
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSE-C Encryption Test</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
.container{max-width:960px;margin:0 auto}
h1{font-size:1.6rem;margin-bottom:1rem;color:#38bdf8}
h2{font-size:1.1rem;margin:1.5rem 0 0.5rem;color:#fbbf24}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid #334155}
.nav a{color:#818cf8;text-decoration:none;margin-left:1rem;font-size:0.9rem}
.nav a:hover{text-decoration:underline}
.card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.5rem;margin-bottom:1rem}
.card h3{font-size:1rem;margin-bottom:0.75rem;color:#fbbf24}
.result{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:1rem;margin-top:0.75rem;font-family:monospace;font-size:0.85rem;white-space:pre-wrap;word-break:break-all;overflow-x:auto}
.success{border-color:#22c55e;color:#4ade80}
.error{border-color:#ef4444;color:#f87171}
.warning{border-color:#f59e0b;color:#fbbf24}
.info{border-color:#3b82f6;color:#60a5fa}
.btn{display:inline-block;padding:0.5rem 1rem;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer;text-decoration:none;font-size:0.9rem;margin:0.25rem}
.btn:hover{background:#2563eb}
.btn-green{background:#22c55e}
.btn-green:hover{background:#16a34a}
.btn-red{background:#ef4444}
.btn-red:hover{background:#dc2626}
.btn-yellow{background:#f59e0b}
.btn-yellow:hover{background:#d97706}
table{width:100%;border-collapse:collapse;margin:0.5rem 0}
th,td{text-align:left;padding:0.5rem;border-bottom:1px solid #334155}
th{color:#94a3b8;font-size:0.8rem;text-transform:uppercase}
td{font-size:0.85rem}
.hex{font-family:monospace;font-size:0.75rem;color:#94a3b8}
.explain{background:#1e293b;border-left:4px solid #38bdf8;padding:1rem 1.5rem;margin:1rem 0;border-radius:0 8px 8px 0}
.explain p{margin:0.5rem 0;font-size:0.9rem;line-height:1.5}
.explain strong{color:#fbbf24}
ul{margin:0.5rem 0 0.5rem 1.5rem}
li{margin:0.25rem 0;font-size:0.9rem}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>SSE-C Encryption Test</h1>
<div class="nav">
<a href="upload.php">← กลับหน้า Upload</a>
<a href="index.php">หน้าหลัก</a>
</div>
</div>

<div class="explain">
<p><strong>SSE-C (Server-Side Encryption with Customer-provided Keys)</strong> คือการเข้ารหัสไฟล์ที่ S3 server
โดยใช้ key ที่ <em>เราส่งไป</em> — S3 ไม่ได้เก็บ key ของเรา ดังนั้น:</p>
<ul>
<li>✅ ดาวน์โหลดด้วย key ที่ถูกต้อง → ได้ไฟล์ต้นฉบับ</li>
<li>❌ ดาวน์โหลดโดยไม่ส่ง key → ได้ข้อมูลที่เข้ารหัส (อ่านไม่ได้)</li>
<li>❌ ดาวน์โหลดด้วย key ผิด → S3 ปฏิเสธ (AccessDenied)</li>
<li>❌ ดูไฟล์ตรงจาก disk ของ S3 → ข้อมูลเข้ารหัส</li>
</ul>
</div>

<?php
// Get the first uploaded file for testing
$pdo = getDb();
$stmt = $pdo->query("SELECT * FROM file_storage ORDER BY id ASC LIMIT 1");
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) {
    echo '<div class="card warning"><h3>⚠ ยังไม่มีไฟล์ในระบบ</h3><p>กรุณาอัพโหลดไฟล์ก่อนที่หน้า <a href="upload.php" style="color:#818cf8">upload.php</a> แล้วกลับมาทดสอบใหม่</p></div>';
    echo '</div></body></html>';
    exit;
}

$s3Key = $file['s3_key'];
$fileName = $file['original_name'];
$mimeType = $file['mime_type'];
$fileSize = $file['file_size'];
$config = getS3Config();
$sseKey = getSseCKey();
$sseKeyB64 = base64_encode($sseKey);
$sseKeyMd5 = base64_encode(md5($sseKey, true));
?>

<div class="card">
<h3>📄 ไฟล์ทดสอบ: <?= htmlspecialchars($fileName) ?></h3>
<table>
<tr><th>S3 Key</th><td><?= htmlspecialchars($s3Key) ?></td></tr>
<tr><th>MIME Type</th><td><?= htmlspecialchars($mimeType) ?></td></tr>
<tr><th>Size</th><td><?= number_format($fileSize) ?> bytes</td></tr>
<tr><th>SSE-C Key Hash</th><td class="hex"><?= htmlspecialchars($file['sse_c_key_hash']) ?></td></tr>
</table>
</div>

<?php if ($demo === 'correct'): ?>
<div class="card success">
<h3>✅ ทดสอบ 1: ดาวน์โหลดด้วย SSE-C key ที่ถูกต้อง</h3>
<p>ส่ง <code>x-amz-server-side-encryption-customer-key</code> ที่ถูกต้อง → ควรได้ไฟล์ต้นฉบับ</p>
<?php
$resp = s3Request('GET', '/' . $config['bucket'] . '/' . $s3Key, null, [
    'x-amz-server-side-encryption-customer-algorithm' => 'AES256',
    'x-amz-server-side-encryption-customer-key' => $sseKeyB64,
    'x-amz-server-side-encryption-customer-key-md5' => $sseKeyMd5,
]);
?>
<div class="result success">HTTP Status: <?= $resp['status'] ?>

Body (first 200 bytes):
<?= htmlspecialchars(substr($resp['body'], 0, 200)) ?>

✅ ได้ไฟล์ต้นฉบับกลับมา — SSE-C key ที่ถูกต้องสามารถถอดรหัสได้</div>
</div>

<?php elseif ($demo === 'nokey'): ?>
<div class="card error">
<h3>❌ ทดสอบ 2: ดาวน์โหลดโดยไม่ส่ง SSE-C key</h3>
<p>ไม่ส่ง <code>x-amz-server-side-encryption-customer-*</code> headers เลย → ควรได้ข้อมูลที่เข้ารหัส</p>
<?php
$resp = s3Request('GET', '/' . $config['bucket'] . '/' . $s3Key);
$rawHex = bin2hex(substr($resp['body'], 0, 64));
?>
<div class="result error">HTTP Status: <?= $resp['status'] ?>

Raw bytes (hex, first 64 bytes):
<?= chunk_split($rawHex, 2, ' ') ?>

Raw bytes (as text, first 200 chars):
<?= htmlspecialchars(substr($resp['body'], 0, 200)) ?>

❌ ได้ข้อมูลที่เข้ารหัส — อ่านไม่ได้เพราะไม่มี SSE-C key
ถ้าเป็น PDF จริง จะเห็นว่าไม่มี %PDF header ขึ้นต้น (ข้อมูลถูกเข้ารหัสทั้งไฟล์)</div>
</div>

<?php elseif ($demo === 'wrongkey'): ?>
<div class="card error">
<h3>❌ ทดสอบ 3: ดาวน์โหลดด้วย SSE-C key ผิด</h3>
<p>ส่ง key ที่ไม่ถูกต้อง → S3 ควรปฏิเสธด้วย AccessDenied</p>
<?php
$wrongKey = str_repeat('X', 32);
$wrongKeyB64 = base64_encode($wrongKey);
$wrongKeyMd5 = base64_encode(md5($wrongKey, true));
$resp = s3Request('GET', '/' . $config['bucket'] . '/' . $s3Key, null, [
    'x-amz-server-side-encryption-customer-algorithm' => 'AES256',
    'x-amz-server-side-encryption-customer-key' => $wrongKeyB64,
    'x-amz-server-side-encryption-customer-key-md5' => $wrongKeyMd5,
]);
?>
<div class="result error">HTTP Status: <?= $resp['status'] ?>

Response:
<?= htmlspecialchars($resp['body']) ?>

❌ S3 ปฏิเสธการเข้าถึง — key ผิด ไม่สามารถถอดรหัสไฟล์ได้</div>
</div>

<?php elseif ($demo === 'disk'): ?>
<div class="card warning">
<h3>🔍 ทดสอบ 4: ดูไฟล์ตรงจาก disk ของ Garage</h3>
<p>อ่านไฟล์ตรงจาก block storage ใน Garage volume → ควรเห็นข้อมูลที่เข้ารหัส</p>
<?php
// Read raw block data from Garage data directory
$dataDir = '/var/lib/garage/data';
$foundFiles = [];
if (is_dir($dataDir)) {
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dataDir, FilesystemIterator::SKIP_DOTS));
    foreach ($rii as $f) {
        if ($f->isFile() && $f->getSize() > 0) {
            $foundFiles[] = ['path' => $f->getPathname(), 'size' => $f->getSize()];
        }
    }
}
?>
<div class="result warning">พบ <?= count($foundFiles) ?> ไฟล์ใน Garage data directory (<?= $dataDir ?>)

<?php foreach (array_slice($foundFiles, 0, 5) as $i => $bf): ?>
ไฟล์ #<?= $i + 1 ?>: <?= htmlspecialchars($bf['path']) ?> (<?= $bf['size'] ?> bytes)
  Hex (first 64 bytes): <?= chunk_split(bin2hex(substr(file_get_contents($bf['path']), 0, 64)), 2, ' ') ?>

<?php endforeach; ?>
❌ ข้อมูลใน disk เป็น encrypted blocks — ไม่สามารถอ่านเป็นไฟล์ต้นฉบับได้
Garage เก็บข้อมูลเป็น content-addressed blocks ที่ถูกเข้ารหัสด้วย SSE-C key</div>
</div>

<?php elseif ($demo === 's3cli'): ?>
<div class="card warning">
<h3>🔍 ทดสอบ 5: ใช้ garage CLI ดู object โดยไม่มี SSE-C</h3>
<p>ใช้ garage CLI (หรือ aws CLI) เพื่อดาวน์โหลด object โดยไม่ส่ง SSE-C key</p>
<?php
// Try listing the object via S3 API without SSE-C
$resp = s3Request('GET', '/' . $config['bucket'] . '/' . $s3Key);
$rawHex = bin2hex(substr($resp['body'], 0, 128));
$isPdf = substr($resp['body'], 0, 5) === '%PDF-';
?>
<div class="result warning">HTTP Status: <?= $resp['status'] ?>

Object size: <?= strlen($resp['body']) ?> bytes

Hex (first 128 bytes):
<?= chunk_split($rawHex, 2, ' ') ?>

เป็น PDF หรือไม่? <?= $isPdf ? 'ใช่ — ข้อมูลอ่านได้ (ไม่ดี!)' : 'ไม่ — ข้อมูลเข้ารหัสอยู่ ✅' ?>

<?= $isPdf
    ? '⚠ ไฟล์ไม่ได้เข้ารหัส — SSE-C อาจไม่ทำงาน'
    : '✅ ไฟล์ถูกเข้ารหัส — ถึงดาวน์โหลดจาก S3 ได้ ก็อ่านไม่ได้' ?>
</div>
</div>

<?php endif; ?>

<div class="card">
<h3>🧪 เลือกการทดสอบ</h3>
<p style="margin-bottom:0.75rem">คลิกปุ่มเพื่อทดสอบแต่ละสถานการณ์:</p>
<a class="btn btn-green" href="?demo=correct">✅ ดาวน์โหลดด้วย key ที่ถูกต้อง</a>
<a class="btn btn-red" href="?demo=nokey">❌ ดาวน์โหลดไม่ส่ง key</a>
<a class="btn btn-red" href="?demo=wrongkey">❌ ดาวน์โหลดด้วย key ผิด</a>
<a class="btn btn-yellow" href="?demo=disk">🔍 ดูไฟล์ตรงจาก disk</a>
<a class="btn btn-yellow" href="?demo=s3cli">🔍 ใช้ S3 API โดยไม่มี SSE-C</a>
</div>

<?php if ($demo): ?>
<div style="text-align:center;margin-top:1rem">
<a class="btn" href="sse-c-test.php">↻ รีเซ็ต</a>
</div>
<?php endif; ?>

</div>
</body>
</html>
