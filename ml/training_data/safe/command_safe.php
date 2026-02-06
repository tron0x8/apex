<?php
// COMMAND - SAFE EXAMPLES

// Example 1: escapeshellarg
$file = escapeshellarg($_GET['file']);
system("cat " . $file);

// Example 2: escapeshellcmd
$cmd = escapeshellcmd($_POST['cmd']);
exec($cmd, $output);

// Example 3: Whitelist approach
$allowed = ['ls', 'pwd', 'whoami'];
$cmd = $_GET['cmd'];
if (in_array($cmd, $allowed)) {
    system($cmd);
}

// Example 4: Basename for files
$file = basename($_GET['file']);
exec("cat /var/log/" . escapeshellarg($file));

// Example 5: preg_match validation
$input = $_POST['input'];
if (preg_match('/^[a-zA-Z0-9]+$/', $input)) {
    system("echo " . $input);
}

// Example 6: ctype_alnum check
$name = $_GET['name'];
if (ctype_alnum($name)) {
    exec("grep " . escapeshellarg($name) . " /etc/passwd");
}

// Example 7: Intval for numeric
$count = intval($_GET['count']);
exec("head -n $count /var/log/syslog", $output);

// Example 8: Predefined options
$actions = ['start' => 'service nginx start', 'stop' => 'service nginx stop'];
$action = $_POST['action'];
if (isset($actions[$action])) {
    exec($actions[$action]);
}

// Example 9: Array whitelist
$hosts = ['google.com', 'github.com', 'example.com'];
$host = $_GET['host'];
if (in_array($host, $hosts)) {
    exec("ping -c 4 " . escapeshellarg($host));
}

// Example 10: filter_var for IP
$ip = $_GET['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    exec("ping -c 4 " . escapeshellarg($ip));
}

// Example 11: Symfony Process
use Symfony\Component\Process\Process;
$process = new Process(['ls', '-la', $_GET['dir']]);
$process->run();

// Example 12: No user input
$logfile = '/var/log/app.log';
system("tail -100 " . $logfile);

// Example 13: Hardcoded command with safe arg
$filename = basename($_POST['file']);
if (file_exists("/uploads/$filename")) {
    exec("file " . escapeshellarg("/uploads/$filename"));
}

// Example 14: Multiple escapes
$arg1 = escapeshellarg($_GET['a']);
$arg2 = escapeshellarg($_GET['b']);
exec("diff $arg1 $arg2", $output);

// Example 15: Symfony process with array
$process = new Process([
    'convert',
    $_FILES['image']['tmp_name'],
    '-resize', '100x100',
    '/tmp/thumb.jpg'
]);
