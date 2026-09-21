<?php

function maskEmail(string $email): string
{
    $parts = explode('@', $email);
    if (count($parts) !== 2) {
        return str_repeat('*', mb_strlen($email)) . '@' . $email;
    }
    $local  = $parts[0];
    $domain = $parts[1];
    $localLen = mb_strlen($local);

    if ($localLen <= 1) {
        $maskedLocal = '*';
    } elseif ($localLen <= 4) {
        $maskedLocal = mb_substr($local, 0, 1) . str_repeat('*', $localLen - 1);
    } else {
        $keep = (int) ceil($localLen / 3);
        $maskedLocal = mb_substr($local, 0, $keep) . str_repeat('*', $localLen - $keep);
    }

    return $maskedLocal . '@' . $domain;
}

function maskPhone(string $phone): string
{
    $len = strlen($phone);
    if ($len <= 4) {
        return str_repeat('*', $len - 2) . substr($phone, -2);
    }
    $head = substr($phone, 0, 3);
    $tail = substr($phone, -2);
    $middle = str_repeat('*', $len - 5);
    return $head . '-' . $middle . '-' . $tail;
}

function maskName(string $name): string
{
    $name = trim($name);
    $parts = preg_split('/\s+/u', $name);

    if (count($parts) >= 2) {
        $first = $parts[0];
        $last  = implode(' ', array_slice($parts, 1));

        return maskSingleWord($first) . ' ' . maskSingleWord($last);
    }

    return maskSingleWord($name);
}

function maskSingleWord(string $word): string
{
    $len = mb_strlen($word);
    if ($len <= 1) {
        return '*';
    }
    if ($len <= 2) {
        return mb_substr($word, 0, 1) . '*';
    }
    if ($len <= 4) {
        return mb_substr($word, 0, 1) . str_repeat('*', $len - 2) . mb_substr($word, -1);
    }
    return mb_substr($word, 0, 2) . str_repeat('*', $len - 4) . mb_substr($word, -2);
}
