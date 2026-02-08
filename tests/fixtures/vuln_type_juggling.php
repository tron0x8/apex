<?php
$token = $_GET['token'];
if ($token == "0") {  // loose comparison - type juggling
    $admin = true;
}
$data = $_POST['data'];
$count = $data + 0;  // arithmetic coercion, but $data could be string
echo $count;
?>
