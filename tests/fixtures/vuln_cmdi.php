<?php
// VULNERABLE: Direct exec
exec($_POST['command']);

// VULNERABLE: system() call
$cmd = $_GET['cmd'];
system($cmd);

// VULNERABLE: passthru
passthru($_GET['run']);

// VULNERABLE: shell_exec
$dir = $_GET['dir'];
$output = shell_exec("ls " . $dir);

// VULNERABLE: Backtick operator
$file = $_GET['file'];
$result = `cat $file`;

// VULNERABLE: popen
$prog = $_POST['prog'];
$handle = popen($prog, "r");

// VULNERABLE: Multi-line command injection
$host = $_GET['host'];
$port = $_GET['port'];
$command = "nmap -sS " . $host . " -p " . $port;
exec($command);
?>
