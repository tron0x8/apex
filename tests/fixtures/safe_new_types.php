<?php
/**
 * Test fixture for SAFE usage of potentially dangerous patterns.
 * These should NOT be reported as vulnerabilities.
 *
 * Expected findings: 0 (or minimal with low confidence)
 */

// 1. Safe redirect - validated URL
$url = $_GET['redirect'];
if (in_array($url, $allowed_urls, true)) {
    header("Location: " . $url);  // SAFE: Whitelisted URLs only
}

// 2. Safe mass assignment - with fillable protection
$fillable = ['name', 'email'];  // SAFE: Fillable defined
$user->fill($request->only(['name', 'email']));  // SAFE: Explicit field selection

// 3. Secure randomness
$token = bin2hex(random_bytes(32));  // SAFE: CSPRNG
$session_id = random_int(100000, 999999);  // SAFE: Cryptographic random

// 4. Race condition mitigated with file locking
$fp = fopen($file, 'r+');
flock($fp, LOCK_EX);  // SAFE: File lock prevents TOCTOU
$data = fread($fp, filesize($file));
flock($fp, LOCK_UN);
fclose($fp);

// 5. Safe logging - sanitized input
$username = preg_replace('/[\r\n]/', '', $_POST['username']);
error_log("Login: " . $username);  // SAFE: Newlines stripped

// 6. Safe regex - no nested quantifiers, no user pattern
preg_match('/^[a-zA-Z0-9]+$/', $input);  // SAFE: Simple pattern
ini_set('pcre.backtrack_limit', 10000);  // SAFE: Backtrack limit set
preg_match("/^(a+)+$/", $fixed_input);   // Not user input, lower risk

// 7. Safe header with sanitization
$value = str_replace(["\r", "\n"], '', $_GET['header_val']);
header("X-Custom: " . $value);  // SAFE: Newlines stripped
?>
