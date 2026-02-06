<?php
// RCE - SAFE EXAMPLES

// Example 1: No user input in eval
eval('$x = 1 + 1;');

// Example 2: Whitelisted functions
$allowed = ['strlen', 'strtoupper', 'trim'];
$func = $_GET['func'];
if (in_array($func, $allowed)) {
    $result = $func($_GET['arg']);
}

// Example 3: Validated callback
$callbacks = [
    'format_date' => 'formatDate',
    'format_money' => 'formatMoney'
];
$action = $_GET['action'];
if (isset($callbacks[$action])) {
    call_user_func($callbacks[$action], $data);
}

// Example 4: Static methods only
$methods = ['User::validate', 'Order::calculate'];
$method = $_POST['method'];
if (in_array($method, $methods)) {
    call_user_func($method);
}

// Example 5: Class whitelist
$classes = ['User', 'Product', 'Order'];
$class = $_GET['class'];
if (in_array($class, $classes)) {
    $obj = new $class();
}

// Example 6: Sandbox evaluation
$sandbox = new Sandbox();
$result = $sandbox->evaluate($_POST['code']);

// Example 7: Template engine
$twig = new Twig\Environment($loader);
echo $twig->render('template.html', ['name' => $_GET['name']]);

// Example 8: Expression language
$expr = new ExpressionLanguage();
$result = $expr->evaluate('1 + 1');

// Example 9: Math only
$expression = $_GET['expr'];
if (preg_match('/^[0-9+\-*\/\(\)\s]+$/', $expression)) {
    $result = eval("return $expression;");
}

// Example 10: JSON decode (not eval)
$data = json_decode($_POST['json'], true);

// Example 11: Serialized whitelist
$allowed = ['stdClass', 'DateTime'];
$obj = unserialize($_GET['data'], ['allowed_classes' => $allowed]);

// Example 12: Closure with fixed body
$processor = function($x) {
    return $x * 2;
};
$result = $processor($_GET['value']);

// Example 13: Strategy pattern
$strategies = [
    'sum' => new SumStrategy(),
    'avg' => new AvgStrategy()
];
$strategy = $_GET['strategy'];
if (isset($strategies[$strategy])) {
    $result = $strategies[$strategy]->execute($data);
}

// Example 14: Validated PHP code
$code = $_POST['code'];
$tokens = token_get_all('<?php ' . $code);
if (validateTokens($tokens)) {
    eval($code);
}

// Example 15: No dynamic code
$name = htmlspecialchars($_GET['name']);
echo "Hello, " . $name;
