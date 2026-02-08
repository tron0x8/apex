<?php
// VULNERABLE: Taint flows through helper function
function executeQuery($query) {
    return mysql_query($query);
}

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=" . $id;
executeQuery($sql);

// VULNERABLE: Taint flows through processing function
function processInput($input) {
    return trim($input);
}

function runCommand($cmd) {
    exec($cmd);
}

$userCmd = $_POST['cmd'];
$cleaned = processInput($userCmd);
runCommand($cleaned);

// VULNERABLE: Return value propagation
function getUserInput() {
    return $_GET['data'];
}

$data = getUserInput();
echo $data;
?>
