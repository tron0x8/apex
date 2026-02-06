<?php
// COMMAND INJECTION - VULNERABLE EXAMPLES

// Example 1: Direct system call
$cmd = $_GET['cmd'];
system($cmd);

// Example 2: Direct exec
$command = $_POST['command'];
exec($command, $output);

// Example 3: Shell exec
$input = $_REQUEST['input'];
$result = shell_exec($input);

// Example 4: Passthru
$file = $_GET['file'];
passthru("cat " . $file);

// Example 5: Backticks
$host = $_GET['host'];
$result = `ping -c 4 $host`;

// Example 6: Popen
$cmd = $_POST['cmd'];
$handle = popen($cmd, 'r');

// Example 7: Proc open
$command = $_GET['run'];
$process = proc_open($command, $descriptors, $pipes);

// Example 8: Concatenation with command
$filename = $_GET['file'];
system("cat /var/log/" . $filename);

// Example 9: Command with arguments
$ip = $_POST['ip'];
exec("ping -c 4 " . $ip, $output);

// Example 10: Multiple commands possible
$input = $_GET['input'];
system("echo " . $input);

// Example 11: Command in variable
$action = $_POST['action'];
$target = $_POST['target'];
$cmd = "$action $target";
exec($cmd);

// Example 12: Wget/curl injection
$url = $_GET['url'];
exec("wget " . $url);

// Example 13: Tar injection
$file = $_POST['file'];
system("tar -xvf " . $file);

// Example 14: Find injection
$pattern = $_GET['pattern'];
exec("find /var/www -name " . $pattern, $files);

// Example 15: Git injection
$repo = $_POST['repo'];
shell_exec("git clone " . $repo);
