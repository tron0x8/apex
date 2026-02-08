<?php
$input = $_GET['value'];
if (is_int($input)) {
    $result = mysql_query("SELECT * FROM users WHERE id = " . $input);  // safe: type-narrowed to int
}
$val = intval($_GET['num']);
echo $val;  // safe: intval returns int
$cast = (int)$_POST['id'];
mysql_query("SELECT * FROM t WHERE id = " . $cast);  // safe: int cast
?>
