<?php
// COMMAND INJECTION - ADVANCED SAFE EXAMPLES

// Example 1: escapeshellarg
$file = escapeshellarg($_GET['file']);
system("cat " . $file);

// Example 2: escapeshellcmd
$cmd = escapeshellcmd($_POST['cmd']);
exec($cmd);

// Example 3: Both escapes
$arg = escapeshellarg($_GET['arg']);
$cmd = escapeshellcmd("process " . $arg);
exec($cmd);

// Example 4: Whitelist commands
$allowed = ['ls', 'pwd', 'whoami'];
$cmd = $_GET['cmd'];
if (in_array($cmd, $allowed)) {
    system($cmd);
}

// Example 5: Whitelist with args
$cmds = ['list' => 'ls -la', 'disk' => 'df -h'];
$action = $_POST['action'];
if (isset($cmds[$action])) {
    exec($cmds[$action]);
}

// Example 6: basename for files
$file = basename($_GET['file']);
exec("cat /var/log/" . escapeshellarg($file));

// Example 7: preg_match validation
$host = $_POST['host'];
if (preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
    exec("ping -c 4 " . escapeshellarg($host));
}

// Example 8: ctype_alnum
$name = $_GET['name'];
if (ctype_alnum($name)) {
    system("grep " . escapeshellarg($name) . " /etc/passwd");
}

// Example 9: intval for count
$n = intval($_GET['count']);
exec("head -n " . $n . " /var/log/app.log");

// Example 10: filter_var IP
$ip = $_GET['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    exec("ping -c 4 " . escapeshellarg($ip));
}

// Example 11: Symfony Process array
$process = new Process(['ls', '-la', $_GET['dir']]);
$process->run();

// Example 12: No user input
system("uptime");

// Example 13: Config only
$logfile = $config['log_path'];
exec("tail -100 " . $logfile);

// Example 14: Hardcoded with safe param
$id = intval($_GET['id']);
exec("get_user " . $id);

// Example 15: Multiple escapes
$a = escapeshellarg($_GET['a']);
$b = escapeshellarg($_GET['b']);
exec("diff " . $a . " " . $b);

// Example 16: Array command
$args = array_map('escapeshellarg', $_GET['args']);
exec("process " . implode(' ', $args));

// Example 17: Path validation
$file = $_GET['file'];
$real = realpath("/uploads/" . $file);
if ($real && strpos($real, "/uploads/") === 0) {
    exec("file " . escapeshellarg($real));
}

// Example 18: Enum check
$formats = ['json', 'xml', 'csv'];
$fmt = $_GET['format'];
if (in_array($fmt, $formats)) {
    exec("export --format=" . $fmt);
}

// Example 19: Length limit
$input = $_POST['input'];
if (strlen($input) < 20 && ctype_alnum($input)) {
    exec("lookup " . escapeshellarg($input));
}

// Example 20: Database lookup
$id = intval($_GET['id']);
$row = $db->query("SELECT cmd FROM allowed_commands WHERE id = ?", [$id]);
if ($row) {
    exec($row['cmd']);
}
