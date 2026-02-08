<?php
$input = $_GET['data'];
$ref = &$input;  // $ref aliases $input
mysql_query("SELECT * FROM t WHERE x = " . $ref);  // SQLi via alias
$obj = new stdClass();
$obj->val = $_POST['val'];
echo $obj->val;  // XSS via object property
?>
