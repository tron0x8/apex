<?php
$name = $_POST['name'];
$query = "SELECT * FROM users WHERE name = '";
$query .= $name;
$query .= "'";
$result = mysql_query($query);
echo "<h1>Hello " . $name . "</h1>";
?>
