<?php
// SQL INJECTION - VULNERABLE EXAMPLES
// Real-world patterns collected from CVEs and bug bounties

// Example 1: Direct concatenation
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysql_query($sql);

// Example 2: String interpolation
$username = $_POST['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);

// Example 3: ORDER BY injection
$sort = $_GET['sort'];
$sql = "SELECT * FROM products ORDER BY $sort";

// Example 4: LIMIT injection
$limit = $_REQUEST['limit'];
$sql = "SELECT * FROM items LIMIT $limit";

// Example 5: WHERE IN injection
$ids = $_GET['ids'];
$sql = "SELECT * FROM users WHERE id IN ($ids)";

// Example 6: LIKE injection
$search = $_POST['search'];
$sql = "SELECT * FROM articles WHERE title LIKE '%$search%'";

// Example 7: INSERT injection
$name = $_POST['name'];
$email = $_POST['email'];
$sql = "INSERT INTO users (name, email) VALUES ('$name', '$email')";

// Example 8: UPDATE injection
$value = $_POST['value'];
$id = $_GET['id'];
$sql = "UPDATE settings SET value = '$value' WHERE id = $id";

// Example 9: DELETE injection
$id = $_GET['delete'];
$sql = "DELETE FROM comments WHERE id = $id";

// Example 10: UNION injection
$id = $_GET['id'];
$sql = "SELECT name, email FROM users WHERE id = $id";

// Example 11: Multi-query injection
$data = $_POST['data'];
mysqli_multi_query($conn, "SELECT * FROM x WHERE y='$data'");

// Example 12: PDO without prepare
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id = $id");

// Example 13: Sprintf without proper escaping
$id = $_GET['id'];
$sql = sprintf("SELECT * FROM users WHERE id = %s", $id);

// Example 14: Double query
$name = $_POST['name'];
$check = mysql_query("SELECT id FROM users WHERE name='$name'");
if (mysql_num_rows($check) == 0) {
    mysql_query("INSERT INTO users (name) VALUES ('$name')");
}

// Example 15: Complex concatenation
$table = $_GET['table'];
$column = $_GET['column'];
$value = $_GET['value'];
$sql = "SELECT * FROM " . $table . " WHERE " . $column . " = '" . $value . "'";
