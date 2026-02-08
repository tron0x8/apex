<?php
// VULNERABLE: Source on line 3, sink on line 5
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $id;
$result = mysql_query($query);

// VULNERABLE: Source 3 lines before sink
$cmd = $_POST['command'];
$escaped = $cmd;  // Not actually escaped!
system($escaped);

// VULNERABLE: Source and echo separated
$name = $_GET['name'];
$x = "padding";
echo "Hello " . $name;

// VULNERABLE: File inclusion across lines
$page = $_GET['page'];
$path = "pages/" . $page;
include($path);

// VULNERABLE: Eval across lines
$code = $_REQUEST['code'];
$exec = $code;
eval($exec);
?>
