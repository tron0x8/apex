<?php
$id = $_GET['id'];
if ($condition) {
    $id = intval($id);  // sanitized in true branch
} else {
    // not sanitized in else branch
}
// phi node: $id could be tainted or sanitized
$result = mysql_query("SELECT * FROM users WHERE id = " . $id);
?>
