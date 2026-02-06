<?php
// XSS - ADVANCED VULNERABLE EXAMPLES

// Example 1: Direct echo
echo $_GET['name'];

// Example 2: Print
print $_POST['message'];

// Example 3: In HTML attribute
echo '<input value="' . $_GET['value'] . '">';

// Example 4: In href
echo '<a href="' . $_GET['url'] . '">Link</a>';

// Example 5: In onclick
echo '<button onclick="' . $_POST['action'] . '">Click</button>';

// Example 6: In script tag
echo '<script>var x = "' . $_GET['data'] . '";</script>';

// Example 7: Variable echo
$name = $_GET['name'];
echo $name;

// Example 8: Concatenation
$msg = "Hello " . $_POST['user'];
echo $msg;

// Example 9: Double quotes
echo "Welcome $_GET[name]";

// Example 10: printf
printf("Hello %s", $_GET['name']);

// Example 11: sprintf then echo
$html = sprintf("<div>%s</div>", $_POST['content']);
echo $html;

// Example 12: In title
echo '<title>' . $_GET['title'] . '</title>';

// Example 13: In meta
echo '<meta name="desc" content="' . $_REQUEST['desc'] . '">';

// Example 14: In style
echo '<div style="' . $_GET['style'] . '">Content</div>';

// Example 15: In img src
echo '<img src="' . $_POST['image'] . '">';

// Example 16: In iframe
echo '<iframe src="' . $_GET['frame'] . '"></iframe>';

// Example 17: Cookie value
echo $_COOKIE['preference'];

// Example 18: SERVER variable
echo $_SERVER['HTTP_USER_AGENT'];

// Example 19: In textarea
echo '<textarea>' . $_POST['text'] . '</textarea>';

// Example 20: Multiple outputs
$a = $_GET['a'];
$b = $_POST['b'];
echo $a . " - " . $b;
