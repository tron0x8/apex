<?php
// RCE (Remote Code Execution) - VULNERABLE EXAMPLES

// Example 1: eval direct
eval($_GET['code']);

// Example 2: eval from POST
eval($_POST['php']);

// Example 3: assert
assert($_REQUEST['code']);

// Example 4: create_function
$func = create_function('$x', $_GET['body']);

// Example 5: preg_replace /e
preg_replace('/.*/e', $_POST['code'], '');

// Example 6: call_user_func
call_user_func($_GET['func'], $_GET['arg']);

// Example 7: call_user_func_array
call_user_func_array($_POST['func'], $_POST['args']);

// Example 8: Variable function
$func = $_GET['function'];
$func();

// Example 9: Variable function with args
$func = $_POST['func'];
$arg = $_POST['arg'];
$func($arg);

// Example 10: array_map with callback
array_map($_GET['callback'], $data);

// Example 11: array_filter callback
array_filter($arr, $_POST['filter']);

// Example 12: usort callback
usort($arr, $_GET['compare']);

// Example 13: Include eval
$code = $_POST['code'];
eval("function test() { $code }");

// Example 14: Double eval
$inner = $_GET['inner'];
eval('eval("' . $inner . '");');

// Example 15: Eval with base64
$encoded = $_POST['data'];
eval(base64_decode($encoded));

// Example 16: Eval with gzinflate
$compressed = $_REQUEST['payload'];
eval(gzinflate(base64_decode($compressed)));

// Example 17: Anonymous function body
$body = $_GET['body'];
$fn = eval("return function(\$x) { $body };");

// Example 18: ReflectionFunction
$code = $_POST['code'];
eval($code);
$rf = new ReflectionFunction('malicious');

// Example 19: Variable class instantiation
$class = $_GET['class'];
$obj = new $class();

// Example 20: Variable static method
$class = $_POST['class'];
$method = $_POST['method'];
$class::$method();

// Example 21: Dynamic include with code
$file = $_GET['file'];
include($file);

// Example 22: file_put_contents + include
file_put_contents('/tmp/evil.php', $_POST['code']);
include('/tmp/evil.php');

// Example 23: extract + variable overwrite
extract($_GET);
$func();

// Example 24: parse_str overwrite
parse_str($_SERVER['QUERY_STRING']);
eval($code);

// Example 25: Closure from string
$code = $_GET['code'];
eval("\$fn = $code;");
$fn();
