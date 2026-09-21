<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
require_once __DIR__ . '/mask.php';

$logs = getAuditLogs(100);

$actionColors = [
    'CREATE' => 'text-green-400 bg-green-900/50 border-green-800',
    'UPDATE' => 'text-blue-400 bg-blue-900/50 border-blue-800',
    'DELETE' => 'text-red-400 bg-red-900/50 border-red-800',
    'REVEAL' => 'text-amber-400 bg-amber-900/50 border-amber-800',
];
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Log — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">Audit Log</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">บันทึกการเข้าถึงและเปลี่ยนแปลงข้อมูล — ใคร, ตอนไหน, ทำอะไร</p>
        </header>

        <div class="mb-6 grid grid-cols-4 gap-4">
            <?php
            $counts = ['CREATE' => 0, 'UPDATE' => 0, 'DELETE' => 0, 'REVEAL' => 0];
            foreach ($logs as $l) {
                if (isset($counts[$l['action']])) $counts[$l['action']]++;
            }
            foreach ($counts as $act => $cnt):
                $color = $actionColors[$act] ?? 'text-slate-400 bg-slate-800 border-slate-700';
            ?>
                <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <div class="text-xs <?= explode(' ', $color)[0] ?>"><?= $act ?></div>
                    <div class="text-2xl font-bold text-slate-200"><?= $cnt ?></div>
                </div>
            <?php endforeach; ?>
        </div>

        <?php if (empty($logs)): ?>
            <div class="bg-slate-800 rounded-xl p-12 text-center text-slate-500 border border-slate-700">
                ยังไม่มีบันทึก
            </div>
        <?php else: ?>
            <div class="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                <table class="w-full text-sm">
                    <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                        <tr>
                            <th class="px-4 py-3 text-left whitespace-nowrap">ID</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">Action</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">Record ID</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">รายละเอียด</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">IP</th>
                            <th class="px-4 py-3 text-left whitespace-nowrap">เวลา</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        <?php foreach ($logs as $log): ?>
                            <tr class="hover:bg-slate-750 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?= (int) $log['id'] ?></td>
                                <td class="px-4 py-3 whitespace-nowrap">
                                    <span class="px-2 py-1 rounded text-xs border <?= $actionColors[$log['action']] ?? 'text-slate-400 bg-slate-800 border-slate-700' ?>">
                                        <?= htmlspecialchars($log['action']) ?>
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-slate-400 whitespace-nowrap"><?= $log['record_id'] ? (int) $log['record_id'] : '-' ?></td>
                                <td class="px-4 py-3 text-slate-300"><?= htmlspecialchars($log['detail']) ?></td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($log['ip_address']) ?></td>
                                <td class="px-4 py-3 text-slate-500 text-xs whitespace-nowrap"><?= htmlspecialchars($log['created_at']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · Audit Log
        </footer>
    </div>
</body>
</html>
