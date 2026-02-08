<?php
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$name = $_POST['name'];
$stmt2 = $db->prepare("INSERT INTO users (name) VALUES (:name)");
$stmt2->bindParam(':name', $name);
$stmt2->execute();
?>
