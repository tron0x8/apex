<?php
/**
 * Test fixture for new vulnerability types added in APEX v3.0
 * Each section demonstrates a real-world vulnerable pattern.
 *
 * Expected findings:
 * - Header Injection (line 13)
 * - Mass Assignment (line 18)
 * - Insecure Randomness (line 23)
 * - Race Condition (line 28-29)
 * - Log Injection (line 34)
 * - Regex DoS (line 39)
 */

// 1. HTTP Header Injection - CWE-113
$redirect = $_GET['redirect'];
header("Location: " . $redirect);  // VULN: Header injection via unvalidated redirect

// 2. Mass Assignment - CWE-915
extract($_POST);  // VULN: Overwrites all local variables with POST data

// 3. Insecure Randomness - CWE-330
$token = md5(mt_rand());  // VULN: Predictable token using weak PRNG
$session_id = uniqid();   // VULN: Predictable session ID

// 4. Race Condition (TOCTOU) - CWE-362
$file = $_GET['file'];
if (file_exists($file)) { unlink($file); }  // VULN: File can change between check and delete

// 5. Log Injection - CWE-117
$username = $_POST['username'];
error_log("Login attempt: " . $_POST['username']);  // VULN: Newlines can forge log entries

// 6. Regex DoS - CWE-1333
$pattern = $_GET['pattern'];
preg_match($pattern, $input);  // VULN: User-controlled regex pattern
preg_match("/^(a+)+$/", $_GET['input']);  // VULN: Nested quantifiers with user input

// 7. Additional Header Injection variants
header("X-Custom: " . $_POST['value']);  // VULN

// 8. Mass Assignment via ORM
$user->fill($_POST);  // VULN: No fillable/guarded protection
User::create($_REQUEST);  // VULN: Direct mass assignment
?>
