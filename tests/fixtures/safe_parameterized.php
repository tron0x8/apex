<?php
// SAFE: PDO prepared statement with positional params
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// SAFE: PDO prepared statement with named params
$name = $_POST['name'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
$stmt->bindParam(':name', $name);
$stmt->execute();

// SAFE: MySQLi prepared statement
$email = $_POST['email'];
$stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();

// SAFE: Multiple bound params
$user = $_POST['user'];
$pass = $_POST['pass'];
$stmt = $pdo->prepare("SELECT * FROM accounts WHERE user = ? AND pass = ?");
$stmt->execute([$user, $pass]);
?>
