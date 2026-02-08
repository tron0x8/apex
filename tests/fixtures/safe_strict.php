<?php
// SAFE: Strict comparison (no type juggling)
$password = $_POST['password'];
if ($storedHash === $password) {
    login();
}

// SAFE: password_verify (proper hash comparison)
$password = $_POST['password'];
if (password_verify($password, $storedHash)) {
    login();
}

// SAFE: Whitelist validation for file inclusion
$page = $_GET['page'];
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed, true)) {
    include($page . '.php');
}

// SAFE: Strict type check before use
$id = $_GET['id'];
if (ctype_digit($id)) {
    $result = mysql_query("SELECT * FROM users WHERE id=" . $id);
}

// SAFE: Escaped backtick SQL (not injection)
$db->query("SELECT `id`, `name` FROM `users` WHERE `status` = 1");
?>
