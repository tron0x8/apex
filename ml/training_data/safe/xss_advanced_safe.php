<?php
// XSS - ADVANCED SAFE EXAMPLES

// Example 1: htmlspecialchars
echo htmlspecialchars($_GET['name']);

// Example 2: htmlspecialchars with flags
echo htmlspecialchars($_POST['msg'], ENT_QUOTES, 'UTF-8');

// Example 3: htmlentities
echo htmlentities($_GET['data']);

// Example 4: strip_tags
echo strip_tags($_POST['content']);

// Example 5: Variable then escape
$name = $_GET['name'];
echo htmlspecialchars($name, ENT_QUOTES);

// Example 6: In attribute escaped
$val = htmlspecialchars($_POST['value'], ENT_QUOTES);
echo '<input value="' . $val . '">';

// Example 7: json_encode for JS
echo '<script>var x = ' . json_encode($_GET['data']) . ';</script>';

// Example 8: urlencode for URL
$param = urlencode($_GET['q']);
echo '<a href="search.php?q=' . $param . '">Search</a>';

// Example 9: intval for numbers
$id = intval($_GET['id']);
echo "ID: " . $id;

// Example 10: filter_var email
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
echo htmlspecialchars($email);

// Example 11: WordPress esc_html
echo esc_html($_GET['title']);

// Example 12: WordPress esc_attr
echo '<input value="' . esc_attr($_POST['value']) . '">';

// Example 13: WordPress esc_url
echo '<a href="' . esc_url($_GET['url']) . '">Link</a>';

// Example 14: Laravel Blade {{ }}
{{ $user->name }}

// Example 15: Twig auto-escape
{{ user.name }}

// Example 16: HTMLPurifier
$clean = $purifier->purify($_POST['html']);
echo $clean;

// Example 17: Double escape check
$safe = htmlspecialchars(htmlspecialchars($_GET['x']));

// Example 18: JSON response
header('Content-Type: application/json');
echo json_encode(['name' => $_GET['name']]);

// Example 19: Text content type
header('Content-Type: text/plain');
echo $_GET['data'];

// Example 20: preg_replace clean
$clean = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['input']);
echo $clean;
