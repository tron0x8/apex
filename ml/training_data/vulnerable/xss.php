<?php
// XSS - VULNERABLE EXAMPLES

// Example 1: Direct echo
echo $_GET['name'];

// Example 2: Print
print $_POST['message'];

// Example 3: Concatenation
echo "Hello " . $_GET['user'];

// Example 4: Double quotes interpolation
$name = $_GET['name'];
echo "Welcome $name";

// Example 5: In HTML attribute
$value = $_POST['value'];
echo "<input type='text' value='$value'>";

// Example 6: In JavaScript
$data = $_GET['data'];
echo "<script>var x = '$data';</script>";

// Example 7: In href
$url = $_GET['url'];
echo "<a href='$url'>Click</a>";

// Example 8: In onclick
$action = $_POST['action'];
echo "<button onclick='$action'>Submit</button>";

// Example 9: Printf
printf("User: %s", $_GET['user']);

// Example 10: Sprintf to echo
$msg = sprintf("Message: %s", $_POST['msg']);
echo $msg;

// Example 11: Heredoc
$name = $_GET['name'];
echo <<<HTML
<div>Hello $name</div>
HTML;

// Example 12: In title
$title = $_GET['title'];
echo "<title>$title</title>";

// Example 13: In meta
$desc = $_POST['desc'];
echo "<meta name='description' content='$desc'>";

// Example 14: In img src
$src = $_GET['src'];
echo "<img src='$src'>";

// Example 15: JSON output
$data = $_GET['callback'];
echo $data . "(" . json_encode($result) . ")";
