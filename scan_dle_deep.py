#!/usr/bin/env python3
import sys
import os
import re
sys.path.insert(0, 'C:/Users/User/Desktop/apex')
from core.patterns import PatternScanner
from core.security_checks import SecurityChecker

base_path = 'C:/Users/User/Downloads/Telegram Desktop/dle_trial_extracted/upload'

scanner = PatternScanner()
sec_checker = SecurityChecker()

# Dangerous patterns to search for
dangerous_patterns = [
    (r'eval\s*\(\s*\$_', "EVAL with user input"),
    (r'eval\s*\(\s*base64_decode', "EVAL with base64"),
    (r'assert\s*\(\s*\$_', "ASSERT with user input"),
    (r'create_function\s*\([^)]*\$_', "create_function with user input"),
    (r'preg_replace\s*\([^)]+/e[^)]+\$_', "preg_replace /e with user input"),
    (r'\$\w+\s*\(\s*\$_', "Variable function with user input"),
    (r'call_user_func\s*\(\s*\$_', "call_user_func with user input"),
    (r'shell_exec\s*\(\s*\$_', "shell_exec with user input"),
    (r'system\s*\(\s*\$_', "system with user input"),
    (r'passthru\s*\(\s*\$_', "passthru with user input"),
    (r'exec\s*\(\s*\$_', "exec with user input"),
    (r'`[^`]*\$_', "Backticks with user input"),
    (r'file_put_contents\s*\([^,]*\$_[^,]*,\s*\$_', "File write with user data"),
    (r'move_uploaded_file[^;]*\$_(?:GET|POST|REQUEST)', "Upload path injection"),
    (r'extract\s*\(\s*\$_', "extract() with superglobal"),
    (r'(?:include|require)(?:_once)?\s*\(\s*\$_', "Include with user input"),
]

# Webshell signatures
webshell_patterns = [
    (r'c99|r57|b374k|wso|webshell', "Known webshell signature"),
    (r'FilesMan|WSO|Shell|Backdoor', "Webshell keyword"),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*eval', "Obfuscated eval"),
    (r'chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\).*chr', "chr() obfuscation"),
    (r'gzinflate\s*\(\s*base64_decode', "gzinflate+base64 (common obfuscation)"),
    (r'str_rot13\s*\([^)]*base64', "rot13+base64 obfuscation"),
    (r'base64_decode\s*\([^)]+\)\s*\)', "Nested base64_decode"),
]

print("=" * 80)
print("SCANNING FOR DANGEROUS PATTERNS")
print("=" * 80)

findings = []

for root, dirs, files in os.walk(base_path):
    # Skip vendor
    if 'vendor' in root or 'composer' in root or 'htmlpurifier' in root:
        continue
    for f in files:
        if f.endswith('.php'):
            full_path = os.path.join(root, f)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()
                    lines = content.split('\n')

                # Check dangerous patterns
                for pattern, desc in dangerous_patterns + webshell_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            rel_path = full_path.replace(base_path, '').lstrip('/\\')
                            findings.append({
                                'type': desc,
                                'file': rel_path,
                                'line': i,
                                'code': line.strip()[:80]
                            })
            except:
                pass

# Print findings
for f in findings:
    print(f"\n[!] {f['type']}")
    print(f"    File: {f['file']}:{f['line']}")
    print(f"    Code: {f['code']}")

print(f"\n\nTotal dangerous patterns found: {len(findings)}")
