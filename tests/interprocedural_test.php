<?php
// Inter-procedural test - nested function calls

// Vulnerable: Chain of function calls
function fetchUserData() {
    $id = $_GET['user_id'];
    return queryDatabase($id);
}

function queryDatabase($userId) {
    return mysql_query("SELECT * FROM users WHERE id = " . $userId);
}

function processRequest() {
    $data = fetchUserData();
    displayData($data);
}

function displayData($data) {
    echo $data;
}

// Another chain - command execution
function getAction() {
    $action = $_POST['action'];
    return executeAction($action);
}

function executeAction($cmd) {
    return system($cmd);
}

// Safe chain with sanitization
function getCleanId() {
    $id = intval($_GET['id']);
    return fetchRecord($id);
}

function fetchRecord($id) {
    return mysql_query("SELECT * FROM data WHERE id = " . $id);
}
