<?php
// SQL INJECTION - ADVANCED SAFE EXAMPLES

// Example 1: PDO prepare with positional
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// Example 2: PDO prepare with named
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $_POST['email']]);

// Example 3: mysqli prepare
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();

// Example 4: intval casting
$id = intval($_GET['id']);
$sql = "SELECT * FROM users WHERE id = " . $id;

// Example 5: (int) casting
$id = (int)$_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;

// Example 6: is_numeric check
$id = $_GET['id'];
if (is_numeric($id)) {
    $sql = "SELECT * FROM users WHERE id = " . $id;
}

// Example 7: ctype_digit check
$id = $_GET['id'];
if (ctype_digit($id)) {
    $sql = "SELECT * FROM users WHERE id = " . $id;
}

// Example 8: mysqli_real_escape_string
$name = mysqli_real_escape_string($conn, $_POST['name']);
$sql = "SELECT * FROM users WHERE name = '" . $name . "'";

// Example 9: PDO quote
$name = $pdo->quote($_POST['name']);
$sql = "SELECT * FROM users WHERE name = " . $name;

// Example 10: addslashes
$value = addslashes($_GET['value']);
$sql = "SELECT * FROM data WHERE value = '" . $value . "'";

// Example 11: Whitelist columns
$allowed = ['id', 'name', 'email', 'created'];
$col = $_GET['sort'];
if (in_array($col, $allowed)) {
    $sql = "SELECT * FROM users ORDER BY " . $col;
}

// Example 12: Whitelist tables
$tables = ['users', 'products', 'orders'];
$table = $_GET['table'];
if (in_array($table, $tables)) {
    $sql = "SELECT * FROM " . $table;
}

// Example 13: preg_match validation
$id = $_GET['id'];
if (preg_match('/^[0-9]+$/', $id)) {
    $sql = "SELECT * FROM users WHERE id = " . $id;
}

// Example 14: filter_var
$id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($id !== false) {
    $sql = "SELECT * FROM users WHERE id = " . $id;
}

// Example 15: Eloquent ORM
$user = User::where('id', $_GET['id'])->first();

// Example 16: Query Builder
$users = DB::table('users')->where('id', '=', $_GET['id'])->get();

// Example 17: Doctrine
$user = $em->find(User::class, $_GET['id']);

// Example 18: WordPress prepare
$result = $wpdb->get_row($wpdb->prepare("SELECT * FROM users WHERE id = %d", $_GET['id']));

// Example 19: sprintf with intval
$id = intval($_GET['id']);
$sql = sprintf("SELECT * FROM users WHERE id = %d", $id);

// Example 20: Array binding
$stmt = $pdo->prepare("SELECT * FROM users WHERE id IN (?, ?, ?)");
$stmt->execute(array_map('intval', explode(',', $_GET['ids'])));
