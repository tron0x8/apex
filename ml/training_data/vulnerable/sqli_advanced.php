<?php
// SQL INJECTION - ADVANCED VULNERABLE EXAMPLES

// Example 1: String concatenation
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysql_query($sql);

// Example 2: Double quotes interpolation
$name = $_POST['name'];
$query = "SELECT * FROM users WHERE name = '$name'";
mysqli_query($conn, $query);

// Example 3: sprintf without escape
$email = $_REQUEST['email'];
$sql = sprintf("SELECT * FROM users WHERE email = '%s'", $email);

// Example 4: ORDER BY injection
$order = $_GET['sort'];
$sql = "SELECT * FROM products ORDER BY " . $order;

// Example 5: LIMIT injection
$limit = $_GET['limit'];
$sql = "SELECT * FROM items LIMIT " . $limit;

// Example 6: Table name injection
$table = $_POST['table'];
$sql = "SELECT * FROM " . $table;

// Example 7: Column name injection
$col = $_GET['column'];
$sql = "SELECT " . $col . " FROM users";

// Example 8: LIKE injection
$search = $_POST['q'];
$sql = "SELECT * FROM products WHERE name LIKE '%" . $search . "%'";

// Example 9: IN clause injection
$ids = $_GET['ids'];
$sql = "SELECT * FROM users WHERE id IN (" . $ids . ")";

// Example 10: UPDATE injection
$value = $_POST['value'];
$sql = "UPDATE users SET status = '" . $value . "' WHERE id = 1";

// Example 11: INSERT injection
$data = $_REQUEST['data'];
$sql = "INSERT INTO logs VALUES ('" . $data . "')";

// Example 12: DELETE injection
$id = $_GET['delete'];
$sql = "DELETE FROM items WHERE id = " . $id;

// Example 13: UNION injection
$id = $_GET['id'];
$sql = "SELECT name FROM users WHERE id = " . $id;

// Example 14: Subquery injection
$filter = $_POST['filter'];
$sql = "SELECT * FROM (SELECT * FROM users WHERE " . $filter . ") t";

// Example 15: HAVING injection
$having = $_GET['having'];
$sql = "SELECT COUNT(*) FROM orders GROUP BY status HAVING " . $having;

// Example 16: PDO without prepare
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id = " . $id);

// Example 17: mysqli without escape
$name = $_POST['name'];
$mysqli->query("SELECT * FROM users WHERE name = '" . $name . "'");

// Example 18: pg_query injection
$id = $_GET['id'];
pg_query($conn, "SELECT * FROM users WHERE id = " . $id);

// Example 19: Variable from cookie
$user = $_COOKIE['user'];
$sql = "SELECT * FROM sessions WHERE user = '" . $user . "'";

// Example 20: Multiple variables
$a = $_GET['a'];
$b = $_POST['b'];
$sql = "SELECT * FROM t WHERE a = '$a' AND b = '$b'";
