<?php

require_once __DIR__ . '/db.php';

function getS3Config(): array
{
    // S3 credentials are stored in runtime files (written by garage-init.php from shared volume)
    // Not in DB — avoids plaintext secrets in app_settings
    $keyId = '';
    $secretKey = '';
    $credFile = '/tmp/.s3_credentials';
    if (is_file($credFile) && is_readable($credFile)) {
        $content = file_get_contents($credFile);
        foreach (explode("\n", trim($content)) as $line) {
            if (strpos($line, '=') !== false) {
                [$k, $v] = explode('=', $line, 2);
                $k = trim($k);
                $v = trim($v);
                if ($k === 's3_key_id') $keyId = $v;
                elseif ($k === 's3_secret_key') $secretKey = $v;
            }
        }
    }
    return [
        'endpoint'   => getenv('S3_ENDPOINT') ?: 'http://127.0.0.1:3901',
        'region'     => getenv('S3_REGION') ?: 'garage',
        'bucket'     => getenv('S3_BUCKET') ?: 'app-files',
        'key_id'     => $keyId,
        'secret_key' => $secretKey,
    ];
}

function getSseCKey(): string
{
    // Read from env var — not from DB
    $key = getenv('S3_SSE_C_KEY') ?: 'SSE-C-Encryption-Key-2024!@#';
    return substr(str_pad($key, 32, "\0"), 0, 32);
}

function awsSigV4(string $method, string $url, array $headers, string $payload, string $accessKey, string $secretKey, string $region, string $service = 's3'): array
{
    $parsed = parse_url($url);
    $host = $parsed['host'];
    $port = $parsed['port'] ?? '';
    $path = $parsed['path'] ?? '/';
    $query = $parsed['query'] ?? '';

    $hostHeader = $port ? "{$host}:{$port}" : $host;
    $now = new DateTime('UTC');
    $amzDate = $now->format('Ymd\THis\Z');
    $dateStamp = $now->format('Ymd');

    $canonicalUri = '/' . ltrim($path, '/');
    $canonicalQuery = $query;

    // Build canonical headers — must include ALL x-amz-* headers for signing
    $canonicalHeaders = "host:{$hostHeader}\nx-amz-date:{$amzDate}\n";
    $signedHeaderKeys = ['host', 'x-amz-date'];

    // Add all x-amz-* headers to canonical headers
    foreach ($headers as $k => $v) {
        $lowerK = strtolower($k);
        if (str_starts_with($lowerK, 'x-amz-') && !in_array($lowerK, $signedHeaderKeys, true)) {
            $canonicalHeaders .= "{$lowerK}:{$v}\n";
            $signedHeaderKeys[] = $lowerK;
        }
    }
    sort($signedHeaderKeys);
    $signedHeaders = implode(';', $signedHeaderKeys);

    // Rebuild canonical headers in sorted order
    $headerMap = ['host' => $hostHeader, 'x-amz-date' => $amzDate];
    foreach ($headers as $k => $v) {
        $lowerK = strtolower($k);
        if (str_starts_with($lowerK, 'x-amz-')) {
            $headerMap[$lowerK] = $v;
        }
    }
    $canonicalHeaders = '';
    foreach ($signedHeaderKeys as $hk) {
        $canonicalHeaders .= "{$hk}:{$headerMap[$hk]}\n";
    }

    $payloadHash = hash('sha256', $payload);

    $canonicalRequest = "{$method}\n{$canonicalUri}\n{$canonicalQuery}\n{$canonicalHeaders}\n{$signedHeaders}\n{$payloadHash}";

    $scope = "{$dateStamp}/{$region}/{$service}/aws4_request";
    $stringToSign = "AWS4-HMAC-SHA256\n{$amzDate}\n{$scope}\n" . hash('sha256', $canonicalRequest);

    $kDate = hash_hmac('sha256', $dateStamp, "AWS4{$secretKey}", true);
    $kRegion = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', $service, $kRegion, true);
    $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
    $signature = hash_hmac('sha256', $stringToSign, $kSigning);

    $authHeader = "AWS4-HMAC-SHA256 Credential={$accessKey}/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}";

    $headers['Authorization'] = $authHeader;
    $headers['x-amz-date'] = $amzDate;
    $headers['x-amz-content-sha256'] = $payloadHash;

    return $headers;
}

function s3Request(string $method, string $path, ?string $data = null, array $extraHeaders = []): array
{
    $config = getS3Config();

    // Sign with the upstream Host (garage:3900) but send request to nginx proxy (127.0.0.1:3901)
    // nginx will set Host: garage:3900 when forwarding to Garage, so signature matches
    $signHost = 'garage:3900';
    $signUrl = "http://{$signHost}{$path}";
    $actualUrl = $config['endpoint'] . $path;

    $payload = $data ?? '';
    $payloadHash = hash('sha256', $payload);

    // Headers for signing — only x-amz-* and Host go into SigV4
    $signHeaders = array_merge([
        'x-amz-content-sha256' => $payloadHash,
    ], array_filter($extraHeaders, fn($k) => str_starts_with(strtolower($k), 'x-amz-'), ARRAY_FILTER_USE_KEY));

    $signedHeaders = awsSigV4($method, $signUrl, $signHeaders, $payload, $config['key_id'], $config['secret_key'], $config['region']);

    // Build curl headers — include Host header explicitly so nginx forwards it correctly
    $curlHeaders = [];
    foreach ($signedHeaders as $k => $v) {
        if (strtolower($k) === 'host') {
            // Override Host header to match signing host
            $curlHeaders[] = "Host: {$v}";
            continue;
        }
        $curlHeaders[] = "{$k}: {$v}";
    }
    // Add non-x-amz extra headers (Content-Type, etc.)
    foreach ($extraHeaders as $k => $v) {
        if (!str_starts_with(strtolower($k), 'x-amz-')) {
            $curlHeaders[] = "{$k}: {$v}";
        }
    }

    $ch = curl_init($actualUrl);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }

    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    return [
        'status' => $code,
        'body'   => $resp,
        'error'  => $error,
    ];
}

function uploadFileToS3(string $localPath, string $s3Key, string $mimeType): array
{
    $config = getS3Config();
    $sseKey = getSseCKey();
    $data = file_get_contents($localPath);

    $sseKeyB64 = base64_encode($sseKey);
    $sseKeyMd5 = base64_encode(md5($sseKey, true));

    $path = '/' . $config['bucket'] . '/' . $s3Key;

    $resp = s3Request('PUT', $path, $data, [
        'Content-Type'           => $mimeType,
        'Content-Length'         => strlen($data),
        'x-amz-server-side-encryption-customer-algorithm' => 'AES256',
        'x-amz-server-side-encryption-customer-key'       => $sseKeyB64,
        'x-amz-server-side-encryption-customer-key-md5'   => $sseKeyMd5,
    ]);

    if ($resp['status'] === 200) {
        return [
            'success'  => true,
            's3_key'   => $s3Key,
            'etag'     => '',
            'key_hash' => hash('sha256', $sseKey),
        ];
    }
    return [
        'success' => false,
        'error'   => "HTTP {$resp['status']}: {$resp['body']}" . ($resp['error'] ? " ({$resp['error']})" : ''),
    ];
}

function uploadDataToS3(string $data, string $s3Key, string $mimeType): array
{
    $config = getS3Config();
    $sseKey = getSseCKey();

    $sseKeyB64 = base64_encode($sseKey);
    $sseKeyMd5 = base64_encode(md5($sseKey, true));

    $path = '/' . $config['bucket'] . '/' . $s3Key;

    $resp = s3Request('PUT', $path, $data, [
        'Content-Type'           => $mimeType,
        'Content-Length'         => strlen($data),
        'x-amz-server-side-encryption-customer-algorithm' => 'AES256',
        'x-amz-server-side-encryption-customer-key'       => $sseKeyB64,
        'x-amz-server-side-encryption-customer-key-md5'   => $sseKeyMd5,
    ]);

    if ($resp['status'] === 200) {
        return [
            'success'  => true,
            's3_key'   => $s3Key,
            'etag'     => '',
            'key_hash' => hash('sha256', $sseKey),
        ];
    }
    return [
        'success' => false,
        'error'   => "HTTP {$resp['status']}: {$resp['body']}",
    ];
}

function downloadFileFromS3(string $s3Key): ?string
{
    $config = getS3Config();
    $sseKey = getSseCKey();

    $sseKeyB64 = base64_encode($sseKey);
    $sseKeyMd5 = base64_encode(md5($sseKey, true));

    $path = '/' . $config['bucket'] . '/' . $s3Key;

    $resp = s3Request('GET', $path, null, [
        'x-amz-server-side-encryption-customer-algorithm' => 'AES256',
        'x-amz-server-side-encryption-customer-key'       => $sseKeyB64,
        'x-amz-server-side-encryption-customer-key-md5'   => $sseKeyMd5,
    ]);

    if ($resp['status'] === 200) {
        return $resp['body'];
    }
    return null;
}

function deleteFileFromS3(string $s3Key): bool
{
    $config = getS3Config();
    $path = '/' . $config['bucket'] . '/' . $s3Key;

    $resp = s3Request('DELETE', $path);
    return $resp['status'] === 204 || $resp['status'] === 200;
}

function listFilesFromS3(int $limit = 100): array
{
    $config = getS3Config();
    $path = '/' . $config['bucket'] . '?max-keys=' . $limit;

    $resp = s3Request('GET', $path);
    if ($resp['status'] === 200) {
        $xml = simplexml_load_string($resp['body']);
        $files = [];
        if ($xml && isset($xml->Contents)) {
            foreach ($xml->Contents as $obj) {
                $files[] = [
                    'key'  => (string) $obj->Key,
                    'size' => (int) $obj->Size,
                    'etag' => (string) $obj->ETag,
                ];
            }
        }
        return $files;
    }
    return [];
}
