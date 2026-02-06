<?php
// FILE INCLUSION - VULNERABLE EXAMPLES

// Example 1: Direct include
include($_GET['page']);

// Example 2: With extension
$page = $_GET['page'];
include($page . ".php");

// Example 3: Require
require($_POST['module']);

// Example 4: Include once
include_once($_GET['file']);

// Example 5: Require once
require_once($_REQUEST['lib']);

// Example 6: In path
$lang = $_GET['lang'];
include("languages/" . $lang . ".php");

// Example 7: Template include
$template = $_POST['template'];
include("templates/$template");

// Example 8: Theme include
$theme = $_COOKIE['theme'];
require("themes/" . $theme . "/header.php");

// Example 9: Plugin include
$plugin = $_GET['plugin'];
include_once("plugins/" . $plugin . "/init.php");

// Example 10: Config include
$config = $_POST['config'];
require("config/" . $config);

// Example 11: Module loading
$module = $_GET['mod'];
$action = $_GET['act'];
include("modules/{$module}/{$action}.php");

// Example 12: Dynamic class loading
$class = $_GET['class'];
require_once("classes/" . $class . ".class.php");

// Example 13: View include
$view = $_POST['view'];
include "views/" . $view;

// Example 14: Wrapper bypass attempt
$file = $_GET['file'];
include("php://filter/convert.base64-encode/resource=" . $file);

// Example 15: Path with variable
$path = $_GET['path'];
$file = $_GET['file'];
include($path . "/" . $file);
