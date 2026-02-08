<?php
// VULNERABLE: Direct concatenation SQL injection
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id=" . $id);

// VULNERABLE: Variable interpolation SQL injection
$name = $_POST['name'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name='$name'");

// VULNERABLE: Multi-line SQL injection
$user = $_REQUEST['user'];
$pass = $_REQUEST['pass'];
$query = "SELECT * FROM accounts WHERE user='" . $user . "' AND pass='" . $pass . "'";
$result = mysql_query($query);

// VULNERABLE: Method call SQL injection
$search = $_GET['search'];
$stmt = $pdo->query("SELECT * FROM products WHERE title LIKE '%" . $search . "%'");

// VULNERABLE: ORDER BY injection
$sort = $_GET['sort'];
$result = $db->query("SELECT * FROM items ORDER BY " . $sort);
?>
