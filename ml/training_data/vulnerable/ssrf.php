<?php
// SSRF - VULNERABLE EXAMPLES

// Example 1: Direct file_get_contents
$url = $_GET['url'];
$content = file_get_contents($url);

// Example 2: curl with user URL
$ch = curl_init($_POST['target']);
curl_exec($ch);

// Example 3: curl_setopt URL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['endpoint']);
curl_exec($ch);

// Example 4: fsockopen
$host = $_REQUEST['host'];
$fp = fsockopen($host, 80);

// Example 5: fopen with URL
$url = $_GET['file'];
$fp = fopen($url, 'r');

// Example 6: get_headers
$url = $_POST['check_url'];
$headers = get_headers($url);

// Example 7: Variable URL
$api = $_GET['api'];
$data = file_get_contents("http://" . $api . "/data");

// Example 8: SoapClient
$wsdl = $_GET['wsdl'];
$client = new SoapClient($wsdl);

// Example 9: simplexml_load_file
$xml_url = $_POST['xml'];
$xml = simplexml_load_file($xml_url);

// Example 10: DOMDocument load
$doc = new DOMDocument();
$doc->load($_GET['xml_file']);

// Example 11: Image from URL
$img_url = $_REQUEST['image'];
$img = imagecreatefromjpeg($img_url);

// Example 12: getimagesize
$url = $_GET['pic'];
$size = getimagesize($url);

// Example 13: copy from URL
$src = $_POST['source'];
copy($src, '/tmp/file.txt');

// Example 14: Guzzle client
$url = $_GET['url'];
$client->request('GET', $url);

// Example 15: stream_context
$url = $_POST['url'];
$ctx = stream_context_create();
file_get_contents($url, false, $ctx);
