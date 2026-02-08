<?php
// VULNERABLE: Direct unserialize from POST
$data = unserialize($_POST['data']);

// VULNERABLE: Base64 decoded unserialize
$input = $_COOKIE['session'];
$obj = unserialize(base64_decode($input));

// VULNERABLE: Multi-line deserialization
$raw = $_REQUEST['payload'];
$decoded = base64_decode($raw);
$object = unserialize($decoded);
?>
