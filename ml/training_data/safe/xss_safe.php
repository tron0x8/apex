<?php
// XSS - SAFE EXAMPLES

// Example 1: htmlspecialchars
echo htmlspecialchars($_GET['name']);

// Example 2: htmlspecialchars with ENT_QUOTES
echo htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');

// Example 3: htmlentities
echo htmlentities($_GET['input']);

// Example 4: strip_tags
echo strip_tags($_POST['content']);

// Example 5: Variable then escape
$name = $_GET['name'];
echo htmlspecialchars($name, ENT_QUOTES);

// Example 6: In attribute escaped
$value = htmlspecialchars($_POST['value'], ENT_QUOTES);
echo "<input type='text' value='$value'>";

// Example 7: JSON encode for JavaScript
$data = $_GET['data'];
echo "<script>var x = " . json_encode($data) . ";</script>";

// Example 8: urlencode for URL
$param = urlencode($_GET['param']);
echo "<a href='page.php?q=$param'>Link</a>";

// Example 9: Laravel Blade
{{ $user->name }}
{!! $trusted_html !!}

// Example 10: Twig auto-escape
{{ user.name }}
{{ user.bio|raw }}

// Example 11: WordPress esc_html
echo esc_html($_GET['title']);

// Example 12: WordPress esc_attr
echo '<input value="' . esc_attr($_POST['value']) . '">';

// Example 13: filter_var
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
echo "Email: " . htmlspecialchars($email);

// Example 14: intval for numbers
$id = intval($_GET['id']);
echo "ID: $id";

// Example 15: Purifier
$clean = $purifier->purify($_POST['html']);
echo $clean;
