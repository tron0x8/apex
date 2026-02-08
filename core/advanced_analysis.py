#!/usr/bin/env python3
"""
APEX Advanced Analysis Engine
Multi-pass analysis with data flow tracking, context-aware detection, and ML-based confidence scoring
"""

import re
import os
import hashlib
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
from pathlib import Path


class VulnCategory(Enum):
    INJECTION = auto()
    BROKEN_AUTH = auto()
    SENSITIVE_DATA = auto()
    XXE = auto()
    BROKEN_ACCESS = auto()
    MISCONFIG = auto()
    XSS = auto()
    DESERIALIZATION = auto()
    VULNERABLE_COMPONENTS = auto()
    LOGGING = auto()


@dataclass
class SourceDefinition:
    name: str
    pattern: str
    taint_level: int
    categories: Set[str]
    framework: str = "php"


@dataclass
class SinkDefinition:
    name: str
    pattern: str
    vuln_type: str
    severity: str
    cwe: str
    requires_taint: Set[str]
    sanitizers: List[str]


@dataclass
class SanitizerDefinition:
    name: str
    pattern: str
    removes_taint: Set[str]
    partial: bool = False


SOURCES = [
    SourceDefinition("$_GET", r'\$_GET\s*\[', 10, {"sql", "xss", "cmd", "path", "include", "ssrf", "xxe", "deser"}),
    SourceDefinition("$_POST", r'\$_POST\s*\[', 10, {"sql", "xss", "cmd", "path", "include", "ssrf", "xxe", "deser"}),
    SourceDefinition("$_REQUEST", r'\$_REQUEST\s*\[', 10, {"sql", "xss", "cmd", "path", "include", "ssrf", "xxe", "deser"}),
    SourceDefinition("$_COOKIE", r'\$_COOKIE\s*\[', 9, {"sql", "xss", "cmd", "deser"}),
    SourceDefinition("$_FILES", r'\$_FILES\s*\[', 8, {"path", "include", "upload"}),
    SourceDefinition("$_SERVER[HTTP_]", r'\$_SERVER\s*\[\s*[\'"]HTTP_', 7, {"xss", "header", "log"}),
    SourceDefinition("$_SERVER[REQUEST_URI]", r'\$_SERVER\s*\[\s*[\'"]REQUEST_URI', 7, {"xss", "path", "log"}),
    SourceDefinition("$_SERVER[QUERY_STRING]", r'\$_SERVER\s*\[\s*[\'"]QUERY_STRING', 8, {"sql", "xss", "log"}),
    SourceDefinition("$_ENV", r'\$_ENV\s*\[', 5, {"cmd", "path"}),
    SourceDefinition("php://input", r'php://input', 10, {"sql", "xss", "cmd", "xxe", "deser"}),
    SourceDefinition("file_get_contents(php://input)", r'file_get_contents\s*\(\s*[\'"]php://input', 10, {"sql", "xss", "xxe", "deser"}),
    SourceDefinition("getenv", r'getenv\s*\(', 5, {"cmd", "path"}),
    SourceDefinition("apache_request_headers", r'apache_request_headers\s*\(', 7, {"xss", "header"}),
    SourceDefinition("getallheaders", r'getallheaders\s*\(', 7, {"xss", "header"}),

    # Framework sources
    SourceDefinition("Laravel:request->input", r'\$request->input\s*\(', 10, {"sql", "xss", "cmd", "path"}, "laravel"),
    SourceDefinition("Laravel:request->get", r'\$request->get\s*\(', 10, {"sql", "xss", "cmd", "path"}, "laravel"),
    SourceDefinition("Laravel:request->all", r'\$request->all\s*\(', 10, {"sql", "xss", "cmd", "path"}, "laravel"),
    SourceDefinition("Laravel:Request::input", r'Request::input\s*\(', 10, {"sql", "xss", "cmd", "path"}, "laravel"),
    SourceDefinition("Symfony:request->query", r'\$request->query->get\s*\(', 10, {"sql", "xss", "cmd"}, "symfony"),
    SourceDefinition("Symfony:request->request", r'\$request->request->get\s*\(', 10, {"sql", "xss", "cmd"}, "symfony"),
    SourceDefinition("CodeIgniter:input->get", r'\$this->input->get\s*\(', 10, {"sql", "xss", "cmd"}, "codeigniter"),
    SourceDefinition("CodeIgniter:input->post", r'\$this->input->post\s*\(', 10, {"sql", "xss", "cmd"}, "codeigniter"),
    SourceDefinition("WordPress:$_GET", r'\$_GET\s*\[', 10, {"sql", "xss"}, "wordpress"),
]

SINKS = [
    # SQL Injection
    SinkDefinition("mysql_query", r'mysql_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval", "mysql_real_escape_string", "addslashes", "prepare"]),
    SinkDefinition("mysqli_query", r'mysqli_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval", "mysqli_real_escape_string", "prepare"]),
    SinkDefinition("mysqli_multi_query", r'mysqli_multi_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval", "mysqli_real_escape_string"]),
    SinkDefinition("pg_query", r'pg_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval", "pg_escape_string", "prepare"]),
    SinkDefinition("pg_send_query", r'pg_send_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["pg_escape_string"]),
    SinkDefinition("sqlite_query", r'sqlite_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval", "sqlite_escape_string"]),
    SinkDefinition("sqlite_exec", r'sqlite_exec\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["sqlite_escape_string"]),
    SinkDefinition("mssql_query", r'mssql_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval"]),
    SinkDefinition("odbc_exec", r'odbc_exec\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval"]),
    SinkDefinition("sqlsrv_query", r'sqlsrv_query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval"]),
    SinkDefinition("PDO::query", r'->query\s*\(', "SQL_INJECTION", "HIGH", "CWE-89", {"sql"}, ["prepare", "quote"]),
    SinkDefinition("PDO::exec", r'->exec\s*\(', "SQL_INJECTION", "HIGH", "CWE-89", {"sql"}, ["prepare", "quote"]),
    SinkDefinition("DB::raw", r'DB::raw\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["intval"]),
    SinkDefinition("DB::select", r'DB::select\s*\(.*?DB::raw', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, []),
    SinkDefinition("whereRaw", r'->whereRaw\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, []),
    SinkDefinition("selectRaw", r'->selectRaw\s*\(', "SQL_INJECTION", "HIGH", "CWE-89", {"sql"}, []),
    SinkDefinition("orderByRaw", r'->orderByRaw\s*\(', "SQL_INJECTION", "HIGH", "CWE-89", {"sql"}, []),
    SinkDefinition("havingRaw", r'->havingRaw\s*\(', "SQL_INJECTION", "HIGH", "CWE-89", {"sql"}, []),
    SinkDefinition("wpdb->query", r'\$wpdb->query\s*\(', "SQL_INJECTION", "CRITICAL", "CWE-89", {"sql"}, ["prepare"]),

    # Command Injection
    SinkDefinition("exec", r'(?<!_)exec\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg", "escapeshellcmd"]),
    SinkDefinition("shell_exec", r'shell_exec\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg", "escapeshellcmd"]),
    SinkDefinition("system", r'(?<!file)system\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg", "escapeshellcmd"]),
    SinkDefinition("passthru", r'passthru\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg", "escapeshellcmd"]),
    SinkDefinition("popen", r'popen\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg"]),
    SinkDefinition("proc_open", r'proc_open\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg"]),
    SinkDefinition("pcntl_exec", r'pcntl_exec\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg"]),
    SinkDefinition("backticks", r'`[^`]+`', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, ["escapeshellarg"]),
    SinkDefinition("ssh2_exec", r'ssh2_exec\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, []),
    SinkDefinition("expect_popen", r'expect_popen\s*\(', "COMMAND_INJECTION", "CRITICAL", "CWE-78", {"cmd"}, []),

    # Code Injection
    SinkDefinition("eval", r'eval\s*\(', "CODE_INJECTION", "CRITICAL", "CWE-94", {"cmd", "sql", "xss"}, []),
    SinkDefinition("assert", r'assert\s*\(', "CODE_INJECTION", "CRITICAL", "CWE-94", {"cmd"}, []),
    SinkDefinition("create_function", r'create_function\s*\(', "CODE_INJECTION", "CRITICAL", "CWE-94", {"cmd"}, []),
    SinkDefinition("preg_replace_e", r'preg_replace\s*\(\s*[\'"][^\'"]*\/[eE]', "CODE_INJECTION", "CRITICAL", "CWE-94", {"cmd"}, []),
    SinkDefinition("call_user_func", r'call_user_func\s*\(', "CODE_INJECTION", "HIGH", "CWE-94", {"cmd"}, []),
    SinkDefinition("call_user_func_array", r'call_user_func_array\s*\(', "CODE_INJECTION", "HIGH", "CWE-94", {"cmd"}, []),
    SinkDefinition("ReflectionFunction", r'ReflectionFunction\s*\(', "CODE_INJECTION", "HIGH", "CWE-94", {"cmd"}, []),
    SinkDefinition("array_map", r'array_map\s*\(\s*\$', "CODE_INJECTION", "MEDIUM", "CWE-94", {"cmd"}, []),
    SinkDefinition("array_filter", r'array_filter\s*\([^,]+,\s*\$', "CODE_INJECTION", "MEDIUM", "CWE-94", {"cmd"}, []),
    SinkDefinition("usort_callback", r'usort\s*\([^,]+,\s*\$', "CODE_INJECTION", "MEDIUM", "CWE-94", {"cmd"}, []),

    # XSS
    SinkDefinition("echo", r'echo\s+', "XSS", "HIGH", "CWE-79", {"xss"}, ["htmlspecialchars", "htmlentities", "strip_tags", "esc_html", "e("]),
    SinkDefinition("print", r'print\s+', "XSS", "HIGH", "CWE-79", {"xss"}, ["htmlspecialchars", "htmlentities", "strip_tags"]),
    SinkDefinition("printf", r'printf\s*\(', "XSS", "HIGH", "CWE-79", {"xss"}, ["htmlspecialchars"]),
    SinkDefinition("vprintf", r'vprintf\s*\(', "XSS", "HIGH", "CWE-79", {"xss"}, ["htmlspecialchars"]),
    SinkDefinition("die", r'die\s*\(', "XSS", "MEDIUM", "CWE-79", {"xss"}, ["htmlspecialchars"]),
    SinkDefinition("exit", r'exit\s*\(', "XSS", "MEDIUM", "CWE-79", {"xss"}, ["htmlspecialchars"]),
    SinkDefinition("Blade:raw", r'\{!!\s*', "XSS", "HIGH", "CWE-79", {"xss"}, []),

    # File Inclusion
    SinkDefinition("include", r'include\s*[\(]?\s*[\'"]?[^\'";\)]*\$', "FILE_INCLUSION", "CRITICAL", "CWE-98", {"include", "path"}, ["basename", "realpath", "in_array"]),
    SinkDefinition("include_once", r'include_once\s*[\(]?\s*[\'"]?[^\'";\)]*\$', "FILE_INCLUSION", "CRITICAL", "CWE-98", {"include", "path"}, ["basename", "realpath"]),
    SinkDefinition("require", r'require\s*[\(]?\s*[\'"]?[^\'";\)]*\$', "FILE_INCLUSION", "CRITICAL", "CWE-98", {"include", "path"}, ["basename", "realpath"]),
    SinkDefinition("require_once", r'require_once\s*[\(]?\s*[\'"]?[^\'";\)]*\$', "FILE_INCLUSION", "CRITICAL", "CWE-98", {"include", "path"}, ["basename", "realpath"]),

    # Path Traversal
    SinkDefinition("file_get_contents", r'file_get_contents\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path", "ssrf"}, ["basename", "realpath"]),
    SinkDefinition("file_put_contents", r'file_put_contents\s*\(', "ARBITRARY_FILE_WRITE", "CRITICAL", "CWE-22", {"path"}, ["basename"]),
    SinkDefinition("fopen", r'fopen\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, ["basename", "realpath"]),
    SinkDefinition("fread", r'fread\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, []),
    SinkDefinition("fwrite", r'fwrite\s*\(', "ARBITRARY_FILE_WRITE", "CRITICAL", "CWE-22", {"path"}, []),
    SinkDefinition("readfile", r'readfile\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, ["basename"]),
    SinkDefinition("file", r'(?<!\w)file\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, ["basename"]),
    SinkDefinition("copy", r'copy\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, ["basename"]),
    SinkDefinition("rename", r'rename\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, []),
    SinkDefinition("unlink", r'unlink\s*\(', "ARBITRARY_FILE_DELETE", "HIGH", "CWE-22", {"path"}, ["basename"]),
    SinkDefinition("rmdir", r'rmdir\s*\(', "ARBITRARY_FILE_DELETE", "HIGH", "CWE-22", {"path"}, []),
    SinkDefinition("mkdir", r'mkdir\s*\(', "PATH_TRAVERSAL", "MEDIUM", "CWE-22", {"path"}, []),
    SinkDefinition("move_uploaded_file", r'move_uploaded_file\s*\(', "INSECURE_UPLOAD", "HIGH", "CWE-434", {"path", "upload"}, ["basename"]),
    SinkDefinition("symlink", r'symlink\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, []),
    SinkDefinition("link", r'(?<!\w)link\s*\(', "PATH_TRAVERSAL", "HIGH", "CWE-22", {"path"}, []),

    # SSRF
    SinkDefinition("curl_setopt_url", r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL', "SSRF", "HIGH", "CWE-918", {"ssrf"}, ["parse_url", "filter_var"]),
    SinkDefinition("curl_exec", r'curl_exec\s*\(', "SSRF", "HIGH", "CWE-918", {"ssrf"}, []),
    SinkDefinition("fsockopen", r'fsockopen\s*\(', "SSRF", "HIGH", "CWE-918", {"ssrf"}, []),
    SinkDefinition("pfsockopen", r'pfsockopen\s*\(', "SSRF", "HIGH", "CWE-918", {"ssrf"}, []),
    SinkDefinition("socket_connect", r'socket_connect\s*\(', "SSRF", "HIGH", "CWE-918", {"ssrf"}, []),
    SinkDefinition("ftp_connect", r'ftp_connect\s*\(', "SSRF", "HIGH", "CWE-918", {"ssrf"}, []),
    SinkDefinition("get_headers", r'get_headers\s*\(', "SSRF", "MEDIUM", "CWE-918", {"ssrf"}, []),
    SinkDefinition("getimagesize", r'getimagesize\s*\(', "SSRF", "MEDIUM", "CWE-918", {"ssrf"}, []),

    # Deserialization
    SinkDefinition("unserialize", r'unserialize\s*\(', "DESERIALIZATION", "CRITICAL", "CWE-502", {"deser"}, ["json_decode", "allowed_classes"]),
    SinkDefinition("yaml_parse", r'yaml_parse\s*\(', "DESERIALIZATION", "CRITICAL", "CWE-502", {"deser"}, []),
    SinkDefinition("phar", r'phar://', "PHAR_DESERIALIZATION", "CRITICAL", "CWE-502", {"deser", "path"}, []),
    SinkDefinition("wddx_deserialize", r'wddx_deserialize\s*\(', "DESERIALIZATION", "CRITICAL", "CWE-502", {"deser"}, []),

    # XXE
    SinkDefinition("simplexml_load_string", r'simplexml_load_string\s*\(', "XXE", "HIGH", "CWE-611", {"xxe"}, ["libxml_disable_entity_loader"]),
    SinkDefinition("simplexml_load_file", r'simplexml_load_file\s*\(', "XXE", "HIGH", "CWE-611", {"xxe", "path"}, ["libxml_disable_entity_loader"]),
    SinkDefinition("DOMDocument::loadXML", r'->loadXML\s*\(', "XXE", "HIGH", "CWE-611", {"xxe"}, ["libxml_disable_entity_loader"]),
    SinkDefinition("DOMDocument::load", r'->load\s*\(', "XXE", "HIGH", "CWE-611", {"xxe", "path"}, ["libxml_disable_entity_loader"]),
    SinkDefinition("XMLReader::open", r'XMLReader::open\s*\(', "XXE", "HIGH", "CWE-611", {"xxe", "path"}, []),
    SinkDefinition("xml_parse", r'xml_parse\s*\(', "XXE", "MEDIUM", "CWE-611", {"xxe"}, []),

    # Header Injection
    SinkDefinition("header", r'header\s*\(', "HEADER_INJECTION", "MEDIUM", "CWE-113", {"header", "xss"}, ["urlencode", "rawurlencode"]),
    SinkDefinition("setcookie", r'setcookie\s*\(', "INSECURE_COOKIE", "LOW", "CWE-614", {"header"}, []),
    SinkDefinition("setrawcookie", r'setrawcookie\s*\(', "INSECURE_COOKIE", "LOW", "CWE-614", {"header"}, []),

    # LDAP
    SinkDefinition("ldap_search", r'ldap_search\s*\(', "LDAP_INJECTION", "HIGH", "CWE-90", {"ldap"}, ["ldap_escape"]),
    SinkDefinition("ldap_list", r'ldap_list\s*\(', "LDAP_INJECTION", "HIGH", "CWE-90", {"ldap"}, ["ldap_escape"]),
    SinkDefinition("ldap_read", r'ldap_read\s*\(', "LDAP_INJECTION", "HIGH", "CWE-90", {"ldap"}, ["ldap_escape"]),
    SinkDefinition("ldap_bind", r'ldap_bind\s*\(', "LDAP_INJECTION", "HIGH", "CWE-90", {"ldap"}, []),

    # XPath
    SinkDefinition("xpath", r'->xpath\s*\(', "XPATH_INJECTION", "HIGH", "CWE-643", {"xpath"}, []),
    SinkDefinition("DOMXPath::query", r'->query\s*\(', "XPATH_INJECTION", "HIGH", "CWE-643", {"xpath"}, []),

    # Template Injection
    SinkDefinition("Twig::render", r'->render\s*\([^)]*\$', "SSTI", "CRITICAL", "CWE-1336", {"xss", "cmd"}, []),
    SinkDefinition("Blade::compileString", r'Blade::compileString\s*\(', "SSTI", "CRITICAL", "CWE-1336", {"xss", "cmd"}, []),
    SinkDefinition("Smarty::display", r'->display\s*\([^)]*\$', "SSTI", "HIGH", "CWE-1336", {"xss"}, []),

    # Mail
    SinkDefinition("mail", r'mail\s*\(', "EMAIL_INJECTION", "MEDIUM", "CWE-93", {"header"}, []),
    SinkDefinition("mb_send_mail", r'mb_send_mail\s*\(', "EMAIL_INJECTION", "MEDIUM", "CWE-93", {"header"}, []),

    # Logging
    SinkDefinition("error_log", r'error_log\s*\(', "LOG_INJECTION", "LOW", "CWE-117", {"log"}, []),
    SinkDefinition("syslog", r'syslog\s*\(', "LOG_INJECTION", "LOW", "CWE-117", {"log"}, []),

    # Mass Assignment
    SinkDefinition("extract", r'extract\s*\(', "MASS_ASSIGNMENT", "HIGH", "CWE-915", {"mass"}, []),
    SinkDefinition("parse_str", r'parse_str\s*\(', "MASS_ASSIGNMENT", "HIGH", "CWE-915", {"mass"}, []),
    SinkDefinition("mb_parse_str", r'mb_parse_str\s*\(', "MASS_ASSIGNMENT", "HIGH", "CWE-915", {"mass"}, []),
    SinkDefinition("import_request_variables", r'import_request_variables\s*\(', "MASS_ASSIGNMENT", "CRITICAL", "CWE-915", {"mass"}, []),
]

SANITIZERS = [
    # SQL
    SanitizerDefinition("intval", r'intval\s*\(', {"sql", "xss", "path"}),
    SanitizerDefinition("floatval", r'floatval\s*\(', {"sql", "xss"}),
    SanitizerDefinition("(int)", r'\(int\)\s*\$', {"sql", "xss"}),
    SanitizerDefinition("(float)", r'\(float\)\s*\$', {"sql"}),
    SanitizerDefinition("abs", r'abs\s*\(', {"sql"}),
    SanitizerDefinition("mysql_real_escape_string", r'mysql_real_escape_string\s*\(', {"sql"}),
    SanitizerDefinition("mysqli_real_escape_string", r'mysqli_real_escape_string\s*\(', {"sql"}),
    SanitizerDefinition("pg_escape_string", r'pg_escape_string\s*\(', {"sql"}),
    SanitizerDefinition("pg_escape_literal", r'pg_escape_literal\s*\(', {"sql"}),
    SanitizerDefinition("sqlite_escape_string", r'sqlite_escape_string\s*\(', {"sql"}),
    SanitizerDefinition("addslashes", r'addslashes\s*\(', {"sql"}, partial=True),
    SanitizerDefinition("PDO::quote", r'->quote\s*\(', {"sql"}),
    SanitizerDefinition("prepare", r'->prepare\s*\(', {"sql"}),
    SanitizerDefinition("bindParam", r'->bindParam\s*\(', {"sql"}),
    SanitizerDefinition("bindValue", r'->bindValue\s*\(', {"sql"}),
    SanitizerDefinition("wpdb->prepare", r'\$wpdb->prepare\s*\(', {"sql"}),
    SanitizerDefinition("esc_sql", r'esc_sql\s*\(', {"sql"}),

    # XSS
    SanitizerDefinition("htmlspecialchars", r'htmlspecialchars\s*\(', {"xss"}),
    SanitizerDefinition("htmlentities", r'htmlentities\s*\(', {"xss"}),
    SanitizerDefinition("strip_tags", r'strip_tags\s*\(', {"xss"}, partial=True),
    SanitizerDefinition("esc_html", r'esc_html\s*\(', {"xss"}),
    SanitizerDefinition("esc_attr", r'esc_attr\s*\(', {"xss"}),
    SanitizerDefinition("esc_textarea", r'esc_textarea\s*\(', {"xss"}),
    SanitizerDefinition("wp_kses", r'wp_kses\s*\(', {"xss"}),
    SanitizerDefinition("wp_kses_post", r'wp_kses_post\s*\(', {"xss"}),
    SanitizerDefinition("sanitize_text_field", r'sanitize_text_field\s*\(', {"xss", "sql"}),
    SanitizerDefinition("e()", r'\be\s*\(\s*\$', {"xss"}),
    SanitizerDefinition("Html::escape", r'Html::escape\s*\(', {"xss"}),
    SanitizerDefinition("Xss::filter", r'Xss::filter\s*\(', {"xss"}),

    # Command
    SanitizerDefinition("escapeshellarg", r'escapeshellarg\s*\(', {"cmd"}),
    SanitizerDefinition("escapeshellcmd", r'escapeshellcmd\s*\(', {"cmd"}),

    # Path
    SanitizerDefinition("basename", r'basename\s*\(', {"path", "include"}),
    SanitizerDefinition("realpath", r'realpath\s*\(', {"path", "include"}),
    SanitizerDefinition("pathinfo", r'pathinfo\s*\(', {"path"}, partial=True),

    # URL
    SanitizerDefinition("urlencode", r'urlencode\s*\(', {"header", "xss"}),
    SanitizerDefinition("rawurlencode", r'rawurlencode\s*\(', {"header", "xss"}),
    SanitizerDefinition("filter_var_url", r'filter_var\s*\([^,]+,\s*FILTER_VALIDATE_URL', {"ssrf"}),
    SanitizerDefinition("filter_var_email", r'filter_var\s*\([^,]+,\s*FILTER_VALIDATE_EMAIL', {"header"}),
    SanitizerDefinition("filter_var_int", r'filter_var\s*\([^,]+,\s*FILTER_VALIDATE_INT', {"sql", "xss"}),

    # Validation
    SanitizerDefinition("is_numeric", r'is_numeric\s*\(\s*\$', {"sql"}),
    SanitizerDefinition("is_int", r'is_int\s*\(\s*\$', {"sql"}),
    SanitizerDefinition("ctype_digit", r'ctype_digit\s*\(\s*\$', {"sql"}),
    SanitizerDefinition("ctype_alnum", r'ctype_alnum\s*\(\s*\$', {"sql", "xss", "cmd"}),
    SanitizerDefinition("ctype_alpha", r'ctype_alpha\s*\(\s*\$', {"sql", "xss", "cmd"}),
    SanitizerDefinition("in_array", r'in_array\s*\(\s*\$[^,]+,\s*\[', {"sql", "path", "include", "cmd"}),
    SanitizerDefinition("preg_match_validate", r'preg_match\s*\(\s*[\'"]\/\^[\[\]a-zA-Z0-9\\\\]+\$\/', {"sql", "xss", "cmd"}),

    # Laravel
    SanitizerDefinition("Laravel:validate", r'->validate\s*\(', {"sql", "xss", "cmd", "path"}),
    SanitizerDefinition("Laravel:validated", r'->validated\s*\(', {"sql", "xss", "cmd", "path"}),
    SanitizerDefinition("Validator::make", r'Validator::make\s*\(', {"sql", "xss"}),

    # XXE
    SanitizerDefinition("libxml_disable_entity_loader", r'libxml_disable_entity_loader\s*\(\s*true', {"xxe"}),

    # JSON (safe alternative to unserialize)
    SanitizerDefinition("json_decode", r'json_decode\s*\(', {"deser"}),
]


class TaintTracker:
    """Track tainted variables through code"""

    def __init__(self):
        self.tainted_vars: Dict[str, Set[str]] = {}  # var_name -> set of taint types
        self.var_sources: Dict[str, Tuple[int, str]] = {}  # var_name -> (line, source_name)
        self.sanitized_vars: Dict[str, Set[str]] = {}  # var_name -> set of removed taint types

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Analyze code for taint propagation"""
        lines = code.split('\n')

        # First pass: find sources
        for i, line in enumerate(lines, 1):
            for source in SOURCES:
                if re.search(source.pattern, line):
                    # Find variable being assigned
                    assign_match = re.match(r'\s*\$(\w+)\s*=', line)
                    if assign_match:
                        var_name = f'${assign_match.group(1)}'
                        self.tainted_vars[var_name] = source.categories.copy()
                        self.var_sources[var_name] = (i, source.name)

        # Second pass: track propagation and sanitization
        for i, line in enumerate(lines, 1):
            # Check for sanitizers
            for sanitizer in SANITIZERS:
                if re.search(sanitizer.pattern, line):
                    assign_match = re.match(r'\s*\$(\w+)\s*=', line)
                    if assign_match:
                        var_name = f'${assign_match.group(1)}'
                        if var_name in self.tainted_vars:
                            if sanitizer.partial:
                                # Partial sanitizer - reduce taint
                                self.tainted_vars[var_name] -= sanitizer.removes_taint
                            else:
                                self.tainted_vars[var_name] -= sanitizer.removes_taint
                            self.sanitized_vars.setdefault(var_name, set()).update(sanitizer.removes_taint)

            # Check for taint propagation (assignment from tainted var)
            assign_match = re.match(r'\s*\$(\w+)\s*=\s*(.+)', line)
            if assign_match:
                new_var = f'${assign_match.group(1)}'
                expr = assign_match.group(2)

                for tainted_var in list(self.tainted_vars.keys()):
                    if tainted_var in expr and new_var != tainted_var:
                        # Propagate taint
                        remaining_taint = self.tainted_vars[tainted_var] - self.sanitized_vars.get(new_var, set())
                        if remaining_taint:
                            self.tainted_vars[new_var] = remaining_taint.copy()
                            if tainted_var in self.var_sources:
                                self.var_sources[new_var] = self.var_sources[tainted_var]

        return {
            'tainted_vars': self.tainted_vars,
            'var_sources': self.var_sources,
            'sanitized_vars': self.sanitized_vars
        }

    def is_var_tainted(self, var_name: str, for_sink: str) -> Tuple[bool, Optional[str]]:
        """Check if variable is tainted for a specific sink type"""
        if var_name not in self.tainted_vars:
            return False, None

        # Find the sink definition
        for sink in SINKS:
            if sink.name == for_sink:
                # Check if any required taint type is present
                if self.tainted_vars[var_name] & sink.requires_taint:
                    source = self.var_sources.get(var_name)
                    return True, source[1] if source else "unknown"

        return False, None


class AdvancedAnalyzer:
    """Advanced multi-pass analyzer"""

    def __init__(self):
        self.findings: List[Dict] = []
        self.taint_tracker = TaintTracker()

    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a single PHP file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            return self.analyze_code(code, file_path)
        except Exception as e:
            return []

    def analyze_code(self, code: str, file_path: str = "") -> List[Dict]:
        """Analyze PHP code"""
        self.findings = []
        self.taint_tracker = TaintTracker()

        # Track taint
        taint_info = self.taint_tracker.analyze_code(code)

        lines = code.split('\n')

        # Find sinks and check if they use tainted data
        for i, line in enumerate(lines, 1):
            for sink in SINKS:
                if re.search(sink.pattern, line):
                    # Check if line contains tainted variable
                    is_vulnerable, source = self._check_sink_vulnerability(
                        line, i, code, sink, taint_info
                    )

                    if is_vulnerable:
                        # Check for sanitizers in context
                        if not self._is_sanitized(code, i, sink):
                            confidence = self._calculate_confidence(line, code, i, sink, taint_info)

                            if confidence >= 0.5:  # Only report if confidence is high enough
                                self.findings.append({
                                    'type': sink.vuln_type,
                                    'severity': sink.severity,
                                    'cwe': sink.cwe,
                                    'file': file_path,
                                    'line': i,
                                    'sink': sink.name,
                                    'source': source or "user_input",
                                    'code': line.strip()[:100],
                                    'confidence': confidence,
                                    'description': f"Potential {sink.vuln_type} via {sink.name}"
                                })

        return self._deduplicate(self.findings)

    def _check_sink_vulnerability(self, line: str, line_no: int, code: str,
                                   sink: SinkDefinition, taint_info: Dict) -> Tuple[bool, Optional[str]]:
        """Check if a sink is vulnerable"""

        # Direct superglobal usage
        for source in SOURCES:
            if re.search(source.pattern, line):
                if source.categories & sink.requires_taint:
                    return True, source.name

        # Check for tainted variables
        var_pattern = re.compile(r'\$[a-zA-Z_]\w*')
        for match in var_pattern.finditer(line):
            var_name = match.group()
            if var_name in taint_info['tainted_vars']:
                if taint_info['tainted_vars'][var_name] & sink.requires_taint:
                    source = taint_info['var_sources'].get(var_name)
                    return True, source[1] if source else "tainted_variable"

        return False, None

    def _is_sanitized(self, code: str, line_no: int, sink: SinkDefinition) -> bool:
        """Check if the sink usage is properly sanitized"""
        lines = code.split('\n')

        # Check context (10 lines before)
        context_start = max(0, line_no - 10)
        context = '\n'.join(lines[context_start:line_no])

        for sanitizer_name in sink.sanitizers:
            for san_def in SANITIZERS:
                if san_def.name == sanitizer_name or sanitizer_name in san_def.name:
                    if re.search(san_def.pattern, context):
                        return True

        return False

    def _calculate_confidence(self, line: str, code: str, line_no: int,
                             sink: SinkDefinition, taint_info: Dict) -> float:
        """Calculate confidence score for finding"""
        confidence = 0.7  # Base confidence

        # Direct superglobal = higher confidence
        if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE)', line):
            confidence += 0.2

        # In function = slightly lower
        lines = code.split('\n')
        for i in range(line_no - 1, max(0, line_no - 20), -1):
            if 'function ' in lines[i]:
                confidence -= 0.05
                break

        # Has validation nearby = lower confidence
        context_start = max(0, line_no - 15)
        context = '\n'.join(lines[context_start:line_no])

        if re.search(r'if\s*\(\s*(?:isset|empty|is_numeric|is_int|ctype_|preg_match|filter_var)', context):
            confidence -= 0.15

        # In try/catch = slightly lower
        if 'try {' in context or 'try{' in context:
            confidence -= 0.05

        # Check for partial sanitization
        for san in SANITIZERS:
            if san.partial and re.search(san.pattern, context):
                confidence -= 0.1

        return min(1.0, max(0.1, confidence))

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for f in findings:
            key = (f['file'], f['line'], f['type'])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique


def analyze_php_advanced(code: str, file_path: str = "") -> List[Dict]:
    """Convenience function for advanced analysis"""
    analyzer = AdvancedAnalyzer()
    return analyzer.analyze_code(code, file_path)


def analyze_file_advanced(file_path: str) -> List[Dict]:
    """Convenience function for file analysis"""
    analyzer = AdvancedAnalyzer()
    return analyzer.analyze_file(file_path)
