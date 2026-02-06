<?php
// LOGIC - SAFE EXAMPLES

// Example 1: Authentication check
function deleteUser($id) {
    if (!isAuthenticated()) {
        throw new UnauthorizedException();
    }
    if (!hasPermission('delete_user')) {
        throw new ForbiddenException();
    }
    $db->delete('users', $id);
}

// Example 2: Authorization check (IDOR prevention)
$userId = $_GET['user_id'];
if ($userId != $_SESSION['user_id'] && !isAdmin()) {
    die('Access denied');
}
$profile = getUserProfile($userId);

// Example 3: Ownership verification
$orderId = $_GET['order_id'];
$order = getOrder($orderId);
if ($order->user_id !== $_SESSION['user_id']) {
    throw new ForbiddenException();
}
cancelOrder($order);

// Example 4: Transaction for race condition
$db->beginTransaction();
$balance = getBalance($userId, true); // FOR UPDATE
if ($balance >= $amount) {
    withdraw($userId, $amount);
}
$db->commit();

// Example 5: Strict comparison
if ($_GET['password'] === $storedHash) {
    login();
}

// Example 6: Type casting
if ((bool)$_POST['admin'] === true && isAdmin()) {
    grantAdmin();
}

// Example 7: Mass assignment protection
$user = new User();
$user->fill($request->only(['name', 'email']));
$user->save();

// Example 8: Validated redirect
$allowed = ['/', '/dashboard', '/profile'];
$url = $_GET['redirect'];
if (in_array($url, $allowed)) {
    header("Location: " . $url);
}

// Example 9: CSRF token validation
if (!hash_equals($_SESSION['csrf'], $_POST['csrf_token'])) {
    die('CSRF validation failed');
}
deleteAccount($_SESSION['user_id']);

// Example 10: Secure password reset
$token = bin2hex(random_bytes(32));
$hash = password_hash($token, PASSWORD_DEFAULT);
storeResetToken($email, $hash, time() + 3600);

// Example 11: Cryptographic OTP
$token = random_int(100000, 999999);
$_SESSION['otp'] = password_hash($token, PASSWORD_DEFAULT);

// Example 12: Safe error handling
catch (Exception $e) {
    error_log($e->getMessage());
    echo 'An error occurred. Please try again.';
}

// Example 13: Production config
error_reporting(0);
ini_set('display_errors', 0);

// Example 14: Environment credentials
$dbPassword = getenv('DB_PASSWORD');
$apiKey = getenv('API_KEY');

// Example 15: Strong password hashing
$hash = password_hash($_POST['password'], PASSWORD_ARGON2ID);

// Example 16: Rate limiting
if ($rateLimiter->isLimited($_SERVER['REMOTE_ADDR'])) {
    http_response_code(429);
    die('Too many requests');
}

// Example 17: Regenerate session
session_regenerate_id(true);

// Example 18: Role validation
$allowedRoles = ['user', 'editor'];
$role = $_POST['role'];
if (in_array($role, $allowedRoles) && canAssignRole($role)) {
    $user->setRole($role);
}

// Example 19: Safe file upload
$allowed = ['jpg', 'png', 'gif'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (in_array(strtolower($ext), $allowed)) {
    $name = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $name);
}

// Example 20: Secure cookie
setcookie('session', $token, [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
