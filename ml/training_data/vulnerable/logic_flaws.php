<?php
// LOGIC FLAWS - VULNERABLE EXAMPLES

// Example 1: Missing authentication check
function deleteUser($id) {
    $sql = "DELETE FROM users WHERE id = ?";
    $db->execute($sql, [$id]);
}

// Example 2: Insecure direct object reference (IDOR)
$userId = $_GET['user_id'];
$profile = getUserProfile($userId);
echo $profile;

// Example 3: Missing authorization
$orderId = $_GET['order_id'];
$order = getOrder($orderId);
cancelOrder($order);

// Example 4: Race condition
$balance = getBalance($userId);
if ($balance >= $amount) {
    withdraw($userId, $amount);
}

// Example 5: Type juggling
if ($_GET['password'] == $storedHash) {
    login();
}

// Example 6: Loose comparison
if ($_POST['admin'] == true) {
    grantAdmin();
}

// Example 7: Mass assignment
$user = new User($_POST);
$user->save();

// Example 8: Unvalidated redirect
$url = $_GET['redirect'];
header("Location: " . $url);

// Example 9: Missing CSRF token
if ($_POST['action'] == 'delete') {
    deleteAccount($_SESSION['user_id']);
}

// Example 10: Insecure password reset
$token = md5($email . time());
$resetLink = "reset.php?token=" . $token;

// Example 11: Predictable token
$token = rand(1000, 9999);
$_SESSION['otp'] = $token;

// Example 12: Information disclosure
catch (Exception $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
}

// Example 13: Debug mode in production
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Example 14: Hardcoded credentials
$dbPassword = "admin123";
$apiKey = "sk_live_abc123";

// Example 15: Weak password hashing
$hash = md5($_POST['password']);
$hash = sha1($_POST['password']);

// Example 16: Missing rate limiting
while (true) {
    $result = tryLogin($_POST['user'], $_POST['pass']);
}

// Example 17: Session fixation
session_id($_GET['session']);
session_start();

// Example 18: Privilege escalation
$role = $_POST['role'];
$user->setRole($role);

// Example 19: Unsafe file upload
move_uploaded_file($_FILES['file']['tmp_name'], 
    'uploads/' . $_FILES['file']['name']);

// Example 20: Business logic bypass
$price = $_POST['price'];
$order->setPrice($price);
$order->process();

// Example 21: Integer overflow
$quantity = $_GET['qty'];
$total = $price * $quantity;

// Example 22: Null byte injection
$file = $_GET['file'];
include($file . ".php");

// Example 23: HTTP response splitting
$lang = $_GET['lang'];
header("Content-Language: " . $lang);

// Example 24: Clickjacking
// Missing X-Frame-Options header

// Example 25: Insecure cookie
setcookie('session', $token);
// Missing Secure, HttpOnly flags
