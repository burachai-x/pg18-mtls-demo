<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/crud.php';
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Test — PostgreSQL 18 mTLS Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .json-view { white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <div class="max-w-5xl mx-auto px-4 py-8">
        <header class="mb-8">
            <div class="flex items-center gap-4 mb-2">
                <h1 class="text-3xl font-bold text-cyan-400">REST API Test</h1>
                <a href="index.php" class="text-cyan-400 hover:text-cyan-300 text-sm">← กลับหน้าหลัก</a>
            </div>
            <p class="text-slate-400">
                ทดสอบ REST API สำหรับ CRUD — ต้องมี API token ใน header <code class="text-amber-400">Authorization: Bearer &lt;token&gt;</code>
            </p>
        </header>

        <!-- Token Info -->
        <div class="mb-6 bg-slate-800 rounded-xl p-4 border border-slate-700">
            <div class="flex items-center gap-4">
                <div>
                    <div class="text-slate-400 text-sm">Default API Token</div>
                    <div class="text-amber-400 font-mono text-sm">demo-api-token-2024</div>
                </div>
                <div class="text-xs text-slate-500">
                    Token ถูก hash (SHA-256) แล้วเก็บในตาราง <code>api_tokens</code> — ไม่เก็บ plaintext
                </div>
            </div>
        </div>

        <!-- API Endpoints -->
        <div class="mb-6 bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-700">
                <h2 class="text-xl font-semibold text-slate-200">Endpoints</h2>
            </div>
            <table class="w-full text-sm">
                <thead class="bg-slate-750 text-slate-400 border-b border-slate-700">
                    <tr>
                        <th class="px-4 py-3 text-left whitespace-nowrap">Method</th>
                        <th class="px-4 py-3 text-left">Path</th>
                        <th class="px-4 py-3 text-left">Description</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-700">
                    <tr class="hover:bg-slate-750"><td class="px-4 py-3"><span class="px-2 py-1 rounded bg-green-900/50 text-green-400 text-xs">GET</span></td><td class="px-4 py-3 font-mono text-cyan-400">/api.php/users</td><td class="px-4 py-3 text-slate-400">List all users (masked)</td></tr>
                    <tr class="hover:bg-slate-750"><td class="px-4 py-3"><span class="px-2 py-1 rounded bg-green-900/50 text-green-400 text-xs">GET</span></td><td class="px-4 py-3 font-mono text-cyan-400">/api.php/users/{id}</td><td class="px-4 py-3 text-slate-400">Get user by ID (masked)</td></tr>
                    <tr class="hover:bg-slate-750"><td class="px-4 py-3"><span class="px-2 py-1 rounded bg-blue-900/50 text-blue-400 text-xs">POST</span></td><td class="px-4 py-3 font-mono text-cyan-400">/api.php/users</td><td class="px-4 py-3 text-slate-400">Create user (encrypted)</td></tr>
                    <tr class="hover:bg-slate-750"><td class="px-4 py-3"><span class="px-2 py-1 rounded bg-amber-900/50 text-amber-400 text-xs">PUT</span></td><td class="px-4 py-3 font-mono text-cyan-400">/api.php/users/{id}</td><td class="px-4 py-3 text-slate-400">Update user (re-encrypted)</td></tr>
                    <tr class="hover:bg-slate-750"><td class="px-4 py-3"><span class="px-2 py-1 rounded bg-red-900/50 text-red-400 text-xs">DELETE</span></td><td class="px-4 py-3 font-mono text-cyan-400">/api.php/users/{id}</td><td class="px-4 py-3 text-slate-400">Delete user</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Interactive Test -->
        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-4">ทดสอบ API (Live)</h2>

            <div class="grid grid-cols-3 gap-4 mb-4">
                <div>
                    <label class="block text-sm text-slate-400 mb-1">Method</label>
                    <select id="method" class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">User ID (optional)</label>
                    <input type="number" id="userId" placeholder="เช่น 1"
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100">
                </div>
                <div>
                    <label class="block text-sm text-slate-400 mb-1">API Token</label>
                    <input type="text" id="token" value="demo-api-token-2024"
                           class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100 font-mono text-sm">
                </div>
            </div>

            <div id="bodySection" class="mb-4 hidden">
                <label class="block text-sm text-slate-400 mb-1">Request Body (JSON)</label>
                <textarea id="body" rows="4"
                          class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-cyan-500 focus:outline-none text-slate-100 font-mono text-sm"
                          placeholder='{"name":"ทดสอบ API","email":"api@test.com","phone":"0800000000"}'>{"name":"ทดสอบ API","email":"api@test.com","phone":"0800000000"}</textarea>
            </div>

            <button onclick="callApi()" class="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition mb-4">
                ส่ง Request
            </button>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <div class="text-sm text-slate-400 mb-1">cURL Command</div>
                    <pre id="curlCmd" class="text-xs font-mono text-green-400 bg-slate-900 p-3 rounded-lg overflow-x-auto json-view"></pre>
                </div>
                <div>
                    <div class="text-sm text-slate-400 mb-1">Response</div>
                    <pre id="response" class="text-xs font-mono text-slate-300 bg-slate-900 p-3 rounded-lg overflow-x-auto json-view min-h-24">กด "ส่ง Request" เพื่อดูผล</pre>
                </div>
            </div>
        </div>

        <!-- No Token Test -->
        <div class="bg-slate-800 rounded-xl p-6 border border-slate-700 mb-6">
            <h2 class="text-lg font-semibold text-slate-200 mb-4">ทดสอบ: ไม่มี Token (ควรได้ 401)</h2>
            <button onclick="callApiNoToken()" class="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium transition">
                ส่ง GET โดยไม่มี Authorization header
            </button>
            <pre id="noTokenResponse" class="mt-3 text-xs font-mono text-slate-300 bg-slate-900 p-3 rounded-lg overflow-x-auto json-view min-h-24">กดปุ่มเพื่อทดสอบ</pre>
        </div>

        <!-- Info -->
        <div class="bg-blue-900/30 border border-blue-800 rounded-lg p-4 text-sm text-blue-300">
            <strong>ความปลอดภัย:</strong>
            <ul class="mt-2 space-y-1 list-disc list-inside">
                <li>API token ถูก hash (SHA-256) แล้วเก็บใน <code>api_tokens</code> — ไม่เก็บ plaintext</li>
                <li>ทุก request ต้องมี <code>Authorization: Bearer &lt;token&gt;</code> header</li>
                <li>API ส่งข้อมูลแบบ <strong>masked</strong> เสมอ (ไม่ส่งข้อมูลเต็มผ่าน API)</li>
                <li>การสร้าง/แก้ไขผ่าน API ก็เข้ารหัสด้วย <code>pgp_sym_encrypt</code> เหมือนหน้าเว็บ</li>
                <li>มี audit log แยกสำหรับ action ผ่าน API (<code>API_CREATE</code>, <code>API_UPDATE</code>, <code>API_DELETE</code>)</li>
            </ul>
        </div>

        <footer class="mt-8 text-center text-slate-600 text-xs">
            PostgreSQL 18 · mTLS · pgcrypto · REST API + Token Auth
        </footer>
    </div>

    <script>
    function updateBodyVisibility() {
        const method = document.getElementById('method').value;
        const bodySection = document.getElementById('bodySection');
        bodySection.classList.toggle('hidden', method === 'GET' || method === 'DELETE');
    }
    document.getElementById('method').addEventListener('change', updateBodyVisibility);
    updateBodyVisibility();

    function callApi() {
        const method = document.getElementById('method').value;
        const userId = document.getElementById('userId').value;
        const token  = document.getElementById('token').value;
        const body   = document.getElementById('body').value;

        let url = '/api.php/users';
        if (userId) url += '/' + userId;

        const curl = `curl -X ${method} http://localhost:8180${url} \\\n  -H "Authorization: Bearer ${token}"` +
            ((method === 'POST' || method === 'PUT') ? ` \\\n  -H "Content-Type: application/json" \\\n  -d '${body}'` : '');
        document.getElementById('curlCmd').textContent = curl;

        const opts = { method, headers: { 'Authorization': 'Bearer ' + token } };
        if (method === 'POST' || method === 'PUT') {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = body;
        }

        fetch(url, opts)
            .then(r => r.text().then(t => ({ status: r.status, body: t })))
            .then(({ status, body }) => {
                try {
                    const json = JSON.parse(body);
                    document.getElementById('response').textContent = `HTTP ${status}\n\n` + JSON.stringify(json, null, 2);
                } catch {
                    document.getElementById('response').textContent = `HTTP ${status}\n\n` + body;
                }
            })
            .catch(e => {
                document.getElementById('response').textContent = 'Error: ' + e.message;
            });
    }

    function callApiNoToken() {
        fetch('/api.php/users')
            .then(r => r.text().then(t => ({ status: r.status, body: t })))
            .then(({ status, body }) => {
                try {
                    const json = JSON.parse(body);
                    document.getElementById('noTokenResponse').textContent = `HTTP ${status}\n\n` + JSON.stringify(json, null, 2);
                } catch {
                    document.getElementById('noTokenResponse').textContent = `HTTP ${status}\n\n` + body;
                }
            });
    }
    </script>
</body>
</html>
