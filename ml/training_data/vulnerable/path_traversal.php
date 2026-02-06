<?php
// PATH TRAVERSAL - VULNERABLE EXAMPLES

// Example 1: Direct file read
$file = $_GET['file'];
$content = file_get_contents($file);

// Example 2: With base path
$doc = $_GET['doc'];
readfile("/var/www/docs/" . $doc);

// Example 3: fopen
$name = $_POST['name'];
$fp = fopen("/uploads/" . $name, 'r');

// Example 4: include with path
$template = $_GET['tpl'];
include("/templates/" . $template);

// Example 5: show_source
$src = $_REQUEST['src'];
show_source($src);

// Example 6: highlight_file
$file = $_GET['f'];
highlight_file($file);

// Example 7: file() function
$log = $_POST['log'];
$lines = file("/var/log/" . $log);

// Example 8: fpassthru
$doc = $_GET['download'];
$fp = fopen("/docs/" . $doc, 'r');
fpassthru($fp);

// Example 9: copy
$src = $_GET['from'];
$dst = $_POST['to'];
copy($src, $dst);

// Example 10: rename
$old = $_GET['old'];
$new = $_GET['new'];
rename($old, $new);

// Example 11: unlink
$file = $_POST['delete'];
unlink("/uploads/" . $file);

// Example 12: mkdir
$dir = $_GET['folder'];
mkdir("/data/" . $dir);

// Example 13: file_put_contents
$path = $_POST['path'];
file_put_contents($path, $_POST['content']);

// Example 14: ZIP extraction
$zip = new ZipArchive();
$zip->open($_FILES['zip']['tmp_name']);
$zip->extractTo("/uploads/" . $_GET['dir']);

// Example 15: image resize
$img = $_GET['image'];
$im = imagecreatefromjpeg("/images/" . $img);
