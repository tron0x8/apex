<?php
// VULNERABLE: Direct echo XSS
echo $_GET['name'];

// VULNERABLE: Concatenated echo XSS
echo "Welcome " . $_POST['user'];

// VULNERABLE: Print XSS
print($_REQUEST['msg']);

// VULNERABLE: Multi-line XSS
$comment = $_POST['comment'];
echo "<div>" . $comment . "</div>";

// VULNERABLE: In attribute context
$value = $_GET['val'];
echo '<input value="' . $value . '">';
?>
