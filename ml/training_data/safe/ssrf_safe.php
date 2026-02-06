<?php
// SSRF - SAFE EXAMPLES

// Example 1: Hardcoded URL
$content = file_get_contents("https://api.example.com/data");

// Example 2: Whitelist check
$allowed = ['api.internal.com', 'cdn.example.com'];
$host = parse_url($_GET['url'], PHP_URL_HOST);
if (in_array($host, $allowed)) {
    file_get_contents($_GET['url']);
}

// Example 3: filter_var validation
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL)) {
    $parsed = parse_url($url);
    if ($parsed['host'] === 'trusted.com') {
        file_get_contents($url);
    }
}

// Example 4: Internal only
$path = $_GET['path'];
if (preg_match('/^\/api\//', $path)) {
    file_get_contents("http://localhost" . $path);
}

// Example 5: Schema whitelist
$url = $_POST['url'];
if (strpos($url, 'https://allowed.com') === 0) {
    curl_init($url);
}

// Example 6: IP validation
$ip = $_GET['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
    fsockopen($ip, 80);
}

// Example 7: Guzzle with base_uri
$client = new Client(['base_uri' => 'https://api.example.com']);
$client->get('/users/' . intval($_GET['id']));

// Example 8: Config URL
$url = $config['api_endpoint'];
file_get_contents($url);

// Example 9: Environment URL
$api = getenv('API_URL');
$data = file_get_contents($api . '/data');

// Example 10: Static resource
$asset = basename($_GET['asset']);
$content = file_get_contents("https://cdn.example.com/assets/" . $asset);
