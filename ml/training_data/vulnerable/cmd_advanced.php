<?php
// COMMAND INJECTION - ADVANCED VULNERABLE EXAMPLES

// Example 1: system direct
system($_GET['cmd']);

// Example 2: exec direct
exec($_POST['command']);

// Example 3: passthru
passthru($_REQUEST['cmd']);

// Example 4: shell_exec
$output = shell_exec($_GET['cmd']);

// Example 5: backticks
$result = `{$_POST['cmd']}`;

// Example 6: popen
$handle = popen($_GET['cmd'], 'r');

// Example 7: proc_open
proc_open($_POST['cmd'], $descriptors, $pipes);

// Example 8: Concatenation
$file = $_GET['file'];
system("cat " . $file);

// Example 9: In argument
$host = $_POST['host'];
exec("ping -c 4 " . $host);

// Example 10: Multiple args
$src = $_GET['src'];
$dst = $_GET['dst'];
system("cp " . $src . " " . $dst);

// Example 11: With path
$name = $_POST['name'];
exec("/usr/bin/process " . $name);

// Example 12: Variable command
$action = $_GET['action'];
$target = $_GET['target'];
system($action . " " . $target);

// Example 13: In pipe
$filter = $_POST['filter'];
system("cat /var/log/app.log | grep " . $filter);

// Example 14: Redirect
$file = $_GET['output'];
exec("ls -la > " . $file);

// Example 15: Background
$cmd = $_POST['cmd'];
exec($cmd . " &");

// Example 16: With options
$opts = $_GET['options'];
system("tar " . $opts . " archive.tar");

// Example 17: From cookie
$cmd = $_COOKIE['cmd'];
exec($cmd);

// Example 18: pcntl_exec
$program = $_GET['program'];
pcntl_exec($program);

// Example 19: Eval with system
eval('system("' . $_GET['cmd'] . '");');

// Example 20: Double variable
$a = $_GET['a'];
$b = $_POST['b'];
exec($a . " " . $b);
