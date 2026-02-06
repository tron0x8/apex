<?php
// PATH TRAVERSAL - SAFE EXAMPLES

// Example 1: basename
$file = basename($_GET['file']);
$content = file_get_contents("/docs/" . $file);

// Example 2: realpath check
$file = $_GET['file'];
$path = realpath("/uploads/" . $file);
if (strpos($path, "/uploads/") === 0) {
    readfile($path);
}

// Example 3: Whitelist
$allowed = ['readme.txt', 'license.txt', 'changelog.txt'];
$file = $_GET['file'];
if (in_array($file, $allowed)) {
    include("/docs/" . $file);
}

// Example 4: preg_match validation
$file = $_POST['file'];
if (preg_match('/^[a-zA-Z0-9_-]+\.txt$/', $file)) {
    file_get_contents("/data/" . $file);
}

// Example 5: pathinfo check
$file = $_GET['doc'];
$info = pathinfo($file);
if ($info['dirname'] === '.' && $info['extension'] === 'pdf') {
    readfile("/docs/" . $info['basename']);
}

// Example 6: ctype_alnum
$id = $_GET['id'];
if (ctype_alnum($id)) {
    include("/cache/" . $id . ".php");
}

// Example 7: intval for ID
$id = intval($_GET['id']);
$file = "/data/file_" . $id . ".json";
$content = file_get_contents($file);

// Example 8: Symfony Finder
$finder = new Finder();
$finder->in('/uploads')->name($_GET['pattern']);

// Example 9: Laravel storage
$file = basename($_GET['file']);
$content = Storage::get('uploads/' . $file);

// Example 10: Remove path chars
$file = $_POST['file'];
$safe = str_replace(['..', '/', '\'], '', $file);
include("/templates/" . $safe . ".php");

// Example 11: Extension whitelist
$file = $_GET['file'];
$ext = pathinfo($file, PATHINFO_EXTENSION);
if (in_array($ext, ['jpg', 'png', 'gif'])) {
    $safe = basename($file);
    readfile("/images/" . $safe);
}

// Example 12: Static path
include("/templates/header.php");
require_once("config.php");

// Example 13: Hash-based filename
$file = md5($_GET['id']) . ".cache";
$content = file_get_contents("/cache/" . $file);

// Example 14: Database lookup
$id = intval($_GET['id']);
$row = $db->query("SELECT path FROM files WHERE id = ?", [$id]);
readfile($row['path']);

// Example 15: SplFileInfo
$file = new SplFileInfo($_GET['file']);
if ($file->getPath() === '/uploads') {
    readfile($file->getRealPath());
}
