<?php
// TEST FILE - Contains intentional vulnerabilities for testing APEX

// ==================== TRUE POSITIVES (Should be detected) ====================

// 1. SQL Injection - Direct
function vuln_sqli_direct($id) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    mysql_query($query);
}

// 2. SQL Injection - Variable
function vuln_sqli_var() {
    $user = $_POST['username'];
    $sql = "SELECT * FROM users WHERE name = '$user'";
    mysqli_query($conn, $sql);
}

// 3. Command Injection
function vuln_command() {
    $file = $_GET['file'];
    system("cat " . $file);
}

// 4. Code Injection - eval
function vuln_eval() {
    $code = $_REQUEST['code'];
    eval($code);
}

// 5. XSS - Reflected
function vuln_xss() {
    echo "Hello " . $_GET['name'];
}

// 6. File Inclusion - LFI
function vuln_lfi() {
    $page = $_GET['page'];
    include($page);
}

// 7. Path Traversal
function vuln_path_traversal() {
    $file = $_GET['file'];
    $content = file_get_contents("/var/www/files/" . $file);
    echo $content;
}

// 8. Deserialization
function vuln_unserialize() {
    $data = $_COOKIE['session'];
    $obj = unserialize($data);
}

// 9. SSRF
function vuln_ssrf() {
    $url = $_GET['url'];
    $content = file_get_contents($url);
}

// 10. Open Redirect
function vuln_redirect() {
    $url = $_GET['redirect'];
    header("Location: " . $url);
}

// ==================== FALSE POSITIVES (Should NOT be detected) ====================

// 1. SQL - Prepared Statement (SAFE)
function safe_sqli_prepared($id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_GET['id']]);
}

// 2. SQL - Integer Cast (SAFE)
function safe_sqli_intval() {
    $id = intval($_GET['id']);
    $query = "SELECT * FROM users WHERE id = $id";
    mysql_query($query);
}

// 3. SQL - Escape Function (SAFE)
function safe_sqli_escape($conn) {
    $user = mysqli_real_escape_string($conn, $_POST['username']);
    $sql = "SELECT * FROM users WHERE name = '$user'";
    mysqli_query($conn, $sql);
}

// 4. XSS - htmlspecialchars (SAFE)
function safe_xss_escape() {
    $name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
    echo "Hello " . $name;
}

// 5. Command - escapeshellarg (SAFE)
function safe_command() {
    $file = escapeshellarg($_GET['file']);
    system("cat " . $file);
}

// 6. File Inclusion - basename (SAFE)
function safe_lfi() {
    $page = basename($_GET['page']);
    include("/templates/" . $page);
}

// 7. File Inclusion - Whitelist (SAFE)
function safe_lfi_whitelist() {
    $allowed = ['home', 'about', 'contact'];
    $page = $_GET['page'];
    if (in_array($page, $allowed)) {
        include("/templates/" . $page . ".php");
    }
}

// 8. Path Traversal - realpath check (SAFE)
function safe_path_traversal() {
    $file = $_GET['file'];
    $base = '/var/www/files/';
    $path = realpath($base . $file);
    if (strpos($path, $base) === 0) {
        $content = file_get_contents($path);
    }
}

// 9. SSRF - URL Validation (SAFE)
function safe_ssrf() {
    $url = $_GET['url'];
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        $parsed = parse_url($url);
        $allowed_hosts = ['api.example.com', 'cdn.example.com'];
        if (in_array($parsed['host'], $allowed_hosts)) {
            $content = file_get_contents($url);
        }
    }
}

// 10. Redirect - Domain Check (SAFE)
function safe_redirect() {
    $url = $_GET['redirect'];
    if (strpos($url, '/') === 0 && strpos($url, '//') !== 0) {
        header("Location: " . $url);
    }
}

// 11. Laravel Eloquent (SAFE)
function safe_laravel_eloquent() {
    $user = User::where('id', request()->input('id'))->first();
}

// 12. Laravel Validation (SAFE)
function safe_laravel_validated(Request $request) {
    $validated = $request->validate([
        'email' => 'required|email',
        'name' => 'required|string|max:255',
    ]);
    User::create($validated);
}

// 13. Symfony Doctrine (SAFE)
function safe_symfony_doctrine($em) {
    $user = $em->getRepository(User::class)
        ->findOneBy(['id' => $request->query->get('id')]);
}

// 14. WordPress wpdb prepare (SAFE)
function safe_wordpress() {
    global $wpdb;
    $id = $_GET['id'];
    $result = $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM users WHERE id = %d", $id)
    );
}

// 15. JSON Response (SAFE - not HTML context)
function safe_json_response() {
    header('Content-Type: application/json');
    echo json_encode(['name' => $_GET['name']]);
}

// ==================== EDGE CASES ====================

// Should detect - DB::raw in Laravel
function edge_laravel_raw() {
    $id = request()->input('id');
    $users = DB::select(DB::raw("SELECT * FROM users WHERE id = $id"));
}

// Should detect - whereRaw in Laravel
function edge_laravel_whereraw() {
    $name = request()->input('name');
    $users = User::whereRaw("name = '$name'")->get();
}

// Should NOT detect - static include
function edge_static_include() {
    include 'header.php';
    require_once 'config.php';
}

// Should detect - preg_replace /e modifier
function edge_preg_replace_e() {
    $input = $_GET['input'];
    $output = preg_replace('/test/e', $input, $text);
}
?>
