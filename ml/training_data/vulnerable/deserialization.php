<?php
// DESERIALIZATION - VULNERABLE EXAMPLES

// Example 1: Direct unserialize
$data = $_COOKIE['session'];
$obj = unserialize($data);

// Example 2: From GET
$input = $_GET['data'];
$result = unserialize($input);

// Example 3: From POST
$payload = $_POST['object'];
unserialize($payload);

// Example 4: base64 + unserialize
$encoded = $_REQUEST['payload'];
$data = base64_decode($encoded);
unserialize($data);

// Example 5: gzuncompress + unserialize
$compressed = $_POST['data'];
$data = gzuncompress(base64_decode($compressed));
unserialize($data);

// Example 6: From file
$file = $_GET['cache'];
$data = file_get_contents($file);
unserialize($data);

// Example 7: PHAR wrapper
$file = $_GET['file'];
include("phar://" . $file);

// Example 8: Phar::loadPhar
$phar = $_POST['phar'];
Phar::loadPhar($phar);

// Example 9: file_exists with phar
$path = $_GET['path'];
file_exists("phar://" . $path);

// Example 10: getimagesize phar
$img = $_POST['image'];
getimagesize("phar://" . $img);

// Example 11: Variable unserialize
$cache = $_COOKIE['cache'];
$obj = unserialize($cache);
$obj->execute();

// Example 12: json then unserialize
$json = $_POST['json'];
$arr = json_decode($json, true);
unserialize($arr['data']);

// Example 13: From session
$sess = $_COOKIE['PHPSESSID'];
$data = file_get_contents("/tmp/sess_" . $sess);
unserialize($data);

// Example 14: Redis cache
$key = $_GET['key'];
$data = $redis->get($key);
unserialize($data);

// Example 15: Memcached
$id = $_REQUEST['id'];
$obj = unserialize($memcache->get($id));
