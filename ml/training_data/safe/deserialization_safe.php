<?php
// DESERIALIZATION - SAFE EXAMPLES

// Example 1: json_decode instead
$data = $_POST['data'];
$obj = json_decode($data, true);

// Example 2: Allowed classes only
$data = $_COOKIE['session'];
$obj = unserialize($data, ['allowed_classes' => ['User', 'Session']]);

// Example 3: Allowed classes false
$input = $_GET['data'];
$arr = unserialize($input, ['allowed_classes' => false]);

// Example 4: HMAC verification
$data = $_POST['object'];
$sig = $_POST['signature'];
if (hash_equals(hash_hmac('sha256', $data, $secret), $sig)) {
    unserialize($data);
}

// Example 5: Internal data only
$cached = $cache->get('user_' . $userId);
$user = unserialize($cached);

// Example 6: Trusted file
$data = file_get_contents('/var/cache/app.cache');
unserialize($data);

// Example 7: Session handler
$data = session_decode($session_data);

// Example 8: igbinary
$data = $_POST['data'];
$obj = igbinary_unserialize($data);

// Example 9: MessagePack
$packed = $_POST['packed'];
$data = msgpack_unpack($packed);

// Example 10: Type check after
$data = $_POST['data'];
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
if ($obj instanceof SafeClass) {
    $obj->process();
}

// Example 11: Symfony serializer
$serializer = new Serializer();
$obj = $serializer->deserialize($_POST['data'], User::class, 'json');

// Example 12: Laravel encrypted
$data = decrypt($_COOKIE['data']);

// Example 13: Database stored
$row = $db->query("SELECT data FROM cache WHERE id = ?", [$id]);
$obj = unserialize($row['data']);

// Example 14: Redis with namespace
$key = 'cache:' . preg_replace('/[^a-z0-9]/', '', $_GET['key']);
$obj = unserialize($redis->get($key));

// Example 15: Validation before
$data = $_POST['data'];
if (preg_match('/^[a-zA-Z0-9+\/=]+$/', $data)) {
    $decoded = base64_decode($data);
    if (strpos($decoded, 'O:') !== 0) {
        $arr = unserialize($decoded, ['allowed_classes' => false]);
    }
}
