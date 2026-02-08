<?php
// SAFE: intval sanitization for SQL
$id = intval($_GET['id']);
$result = mysql_query("SELECT * FROM users WHERE id=" . $id);

// SAFE: htmlspecialchars for XSS
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Welcome " . $name;

// SAFE: escapeshellarg for command injection
$dir = escapeshellarg($_GET['dir']);
exec("ls " . $dir);

// SAFE: basename for file inclusion
$page = basename($_GET['page']);
include("pages/" . $page . ".php");

// SAFE: Type cast sanitization
$id = (int)$_POST['id'];
$result = mysql_query("SELECT * FROM users WHERE id=" . $id);

// SAFE: is_numeric check (conditional use - scanner may not track branch safety)
$price = $_GET['price'];
if (is_numeric($price)) {
    $safe_price = intval($price);
    $result = mysql_query("SELECT * FROM products WHERE price < " . $safe_price);
}
?>
