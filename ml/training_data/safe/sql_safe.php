<?php
// SQL - SAFE EXAMPLES (Properly sanitized)

// Example 1: intval
$id = intval($_GET['id']);
$sql = "SELECT * FROM users WHERE id = $id";
mysql_query($sql);

// Example 2: (int) cast
$id = (int)$_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");

// Example 3: Prepared statement PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// Example 4: Prepared statement mysqli
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $_POST['username']);
$stmt->execute();

// Example 5: mysqli_real_escape_string
$username = mysqli_real_escape_string($conn, $_POST['username']);
$sql = "SELECT * FROM users WHERE username = '$username'";

// Example 6: PDO quote
$name = $pdo->quote($_POST['name']);
$sql = "SELECT * FROM users WHERE name = $name";

// Example 7: addslashes (weak but present)
$value = addslashes($_GET['value']);
$sql = "SELECT * FROM data WHERE value = '$value'";

// Example 8: Named parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $_POST['email']]);

// Example 9: Multiple binds
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ? AND age > ?");
$stmt->execute([$_POST['name'], intval($_POST['age'])]);

// Example 10: Eloquent ORM
$user = User::where('email', $_POST['email'])->first();

// Example 11: Query builder
$users = DB::table('users')->where('id', $_GET['id'])->get();

// Example 12: Doctrine
$user = $em->getRepository('User')->findOneBy(['email' => $_POST['email']]);

// Example 13: WordPress prepare
$results = $wpdb->get_results($wpdb->prepare(
    "SELECT * FROM users WHERE id = %d", $_GET['id']
));

// Example 14: CodeIgniter escape
$name = $this->db->escape($_POST['name']);
$this->db->query("SELECT * FROM users WHERE name = $name");

// Example 15: is_numeric check
$id = $_GET['id'];
if (is_numeric($id)) {
    $sql = "SELECT * FROM users WHERE id = $id";
    mysql_query($sql);
}
