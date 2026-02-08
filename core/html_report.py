"""
APEX HTML Security Report Generator

Generates professional HTML reports with:
- Executive summary with severity breakdown
- Interactive filtering by severity/type
- Code snippets with highlighted vulnerable lines
- CWE mapping and remediation guidance
- Sortable findings table
"""

import os
import html
from datetime import datetime
from typing import Dict, List, Optional


# CWE mapping for vulnerability types
CWE_MAP = {
    'SQL Injection': ('CWE-89', 'SQL Injection', 'Use parameterized queries (prepared statements) with bound parameters. Never concatenate user input into SQL.'),
    'Cross-Site Scripting': ('CWE-79', 'XSS', 'Escape output with htmlspecialchars($var, ENT_QUOTES, "UTF-8"). Use Content-Security-Policy headers.'),
    'Command Injection': ('CWE-78', 'OS Command Injection', 'Use escapeshellarg() for arguments. Avoid shell commands when PHP functions exist (e.g., copy() instead of exec("cp ...")).'),
    'Code Injection': ('CWE-94', 'Code Injection', 'Never use eval() with user input. Use whitelists or switch/case for dynamic dispatch.'),
    'File Inclusion': ('CWE-98', 'File Inclusion', 'Use a whitelist of allowed files. Never pass user input directly to include/require.'),
    'Path Traversal': ('CWE-22', 'Path Traversal', 'Use basename() to strip directory components. Validate against a whitelist of allowed paths.'),
    'Arbitrary File Write': ('CWE-434', 'Unrestricted Upload', 'Validate file type, size, and name. Store uploads outside webroot with random names.'),
    'Arbitrary File Read': ('CWE-22', 'Path Traversal', 'Validate file paths against a whitelist. Use realpath() and check that path starts with expected base.'),
    'Server-Side Request Forgery': ('CWE-918', 'SSRF', 'Validate and whitelist URLs. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).'),
    'Insecure Deserialization': ('CWE-502', 'Deserialization', 'Use json_decode() instead of unserialize(). If unserialize() is needed, use allowed_classes option.'),
    'Open Redirect': ('CWE-601', 'Open Redirect', 'Validate redirect URLs against a whitelist of allowed domains. Use relative URLs when possible.'),
    'Remote Code Execution': ('CWE-94', 'RCE', 'Never use user input in dynamic function calls. Use a whitelist/switch for allowed operations.'),
    'Type Juggling': ('CWE-697', 'Type Confusion', 'Use strict comparison (===) instead of loose (==). Use hash_equals() for timing-safe comparisons.'),
    'Weak Cryptography': ('CWE-327', 'Broken Crypto', 'Use password_hash()/password_verify() for passwords. Use random_bytes() for tokens. Avoid MD5/SHA1 for security.'),
    'Hardcoded Credentials': ('CWE-798', 'Hardcoded Credentials', 'Move credentials to environment variables or secure vault. Never commit secrets to source control.'),
    'Information Disclosure': ('CWE-200', 'Info Disclosure', 'Disable error display in production (display_errors=Off). Remove debug endpoints and phpinfo().'),
    'Insecure Direct Object Reference': ('CWE-639', 'IDOR', 'Verify user authorization for each resource access. Use indirect references mapped to user sessions.'),
    'Auth Bypass': ('CWE-287', 'Auth Bypass', 'Use centralized authentication middleware. Validate session on every request. Avoid client-side auth checks.'),
    'CSRF': ('CWE-352', 'CSRF', 'Include CSRF tokens in all state-changing forms. Verify token server-side on each POST request.'),
    'Unsafe Upload': ('CWE-434', 'Unrestricted Upload', 'Check MIME type and extension against whitelist. Validate file content (e.g., getimagesize). Rename uploaded files.'),
    'XXE': ('CWE-611', 'XXE', 'Disable external entity loading: libxml_disable_entity_loader(true). Use LIBXML_NOENT flag.'),
    'HTTP Header Injection': ('CWE-113', 'Header Injection', 'Strip \\r\\n from header values. Use framework header methods that sanitize automatically.'),
    'Mass Assignment': ('CWE-915', 'Mass Assignment', 'Use $fillable or $guarded in models. Never pass raw request data to create/fill. Use ->only() for whitelisting.'),
    'Insecure Randomness': ('CWE-330', 'Insecure PRNG', 'Use random_bytes() or random_int() instead of rand()/mt_rand()/uniqid() for security-sensitive values.'),
    'Race Condition': ('CWE-362', 'Race Condition', 'Use file locking (flock). Use database transactions with proper isolation. Implement mutex/semaphore for shared resources.'),
    'Log Injection': ('CWE-117', 'Log Injection', 'Strip newlines from log data. Encode user input before logging. Use structured logging formats.'),
    'Regular Expression DoS': ('CWE-1333', 'ReDoS', 'Avoid nested quantifiers (e.g., (a+)+). Set pcre.backtrack_limit. Never use user-controlled regex patterns.'),
}

# Severity colors and icons
SEVERITY_CONFIG = {
    'CRITICAL': {'color': '#dc2626', 'bg': '#fef2f2', 'border': '#fecaca', 'icon': '!!'},
    'HIGH': {'color': '#ea580c', 'bg': '#fff7ed', 'border': '#fed7aa', 'icon': '!'},
    'MEDIUM': {'color': '#ca8a04', 'bg': '#fefce8', 'border': '#fef08a', 'icon': '~'},
    'LOW': {'color': '#2563eb', 'bg': '#eff6ff', 'border': '#bfdbfe', 'icon': 'i'},
}


def generate_html_report(results: Dict, target: str, output_path: Optional[str] = None) -> str:
    """Generate a comprehensive HTML security report.

    Args:
        results: Scan results dictionary from apex.py
        target: Target path that was scanned
        output_path: Optional output file path. If None, returns HTML string.

    Returns:
        HTML string if output_path is None, otherwise the output_path.
    """
    findings = results.get('findings', [])
    llm_findings = results.get('llm_findings', [])

    # Group findings by file
    by_file = {}
    for f in findings:
        fp = f.get('file', 'unknown')
        if fp not in by_file:
            by_file[fp] = []
        by_file[fp].append(f)

    # Group by severity
    by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for f in findings:
        sev = f.get('severity', 'MEDIUM')
        if sev in by_severity:
            by_severity[sev].append(f)

    # Group by type
    by_type = {}
    for f in findings:
        vtype = f.get('type', 'Unknown')
        if vtype not in by_type:
            by_type[vtype] = []
        by_type[vtype].append(f)

    scan_date = results.get('scan_date', datetime.now().isoformat())
    total = results.get('total_findings', len(findings))
    total_files = results.get('total_files', 0)
    skipped = results.get('skipped_vendor_files', 0)
    ml_eliminated = results.get('ml_fps_eliminated', 0)
    llm_eliminated = results.get('llm_fps_eliminated', 0)

    # Calculate risk score (0-100)
    risk_score = min(100, (
        results.get('critical', 0) * 25 +
        results.get('high', 0) * 10 +
        results.get('medium', 0) * 3 +
        results.get('low', 0) * 1
    ))

    risk_level = 'Critical' if risk_score >= 75 else 'High' if risk_score >= 50 else 'Medium' if risk_score >= 25 else 'Low'
    risk_color = '#dc2626' if risk_score >= 75 else '#ea580c' if risk_score >= 50 else '#ca8a04' if risk_score >= 25 else '#16a34a'

    # Build HTML
    html_parts = []
    html_parts.append(_html_header(target, scan_date))
    html_parts.append(_html_summary(results, risk_score, risk_level, risk_color,
                                    total, total_files, skipped, ml_eliminated, llm_eliminated,
                                    findings=findings))
    html_parts.append(_html_severity_chart(results))
    html_parts.append(_html_type_breakdown(by_type))
    html_parts.append(_html_findings_table(findings, by_file))
    if llm_findings:
        html_parts.append(_html_llm_findings(llm_findings))
    html_parts.append(_html_remediation(by_type))
    html_parts.append(_html_footer())

    report = '\n'.join(html_parts)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        return output_path
    return report


def _html_header(target: str, scan_date: str) -> str:
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APEX Security Report - {html.escape(os.path.basename(target))}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 30px 0; margin-bottom: 30px; }}
header .container {{ display: flex; justify-content: space-between; align-items: center; }}
h1 {{ font-size: 1.8em; font-weight: 700; }}
h1 span {{ color: #60a5fa; }}
.meta {{ font-size: 0.85em; color: #94a3b8; text-align: right; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }}
.card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.card h3 {{ font-size: 0.8em; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }}
.card .value {{ font-size: 2em; font-weight: 700; }}
.card .value.critical {{ color: #dc2626; }}
.card .value.high {{ color: #ea580c; }}
.card .value.medium {{ color: #ca8a04; }}
.card .value.low {{ color: #2563eb; }}
.card .value.clean {{ color: #16a34a; }}
.risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85em; }}
section {{ background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
section h2 {{ font-size: 1.3em; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
.bar-chart {{ margin: 16px 0; }}
.bar-row {{ display: flex; align-items: center; margin-bottom: 8px; }}
.bar-label {{ width: 180px; font-size: 0.85em; font-weight: 500; }}
.bar-track {{ flex: 1; height: 24px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 4px; display: flex; align-items: center; padding: 0 8px; color: white; font-size: 0.75em; font-weight: 600; min-width: fit-content; transition: width 0.3s ease; }}
.bar-count {{ width: 40px; text-align: right; font-size: 0.85em; font-weight: 600; margin-left: 8px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
th {{ background: #f8fafc; text-align: left; padding: 10px 12px; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; cursor: pointer; }}
th:hover {{ background: #f1f5f9; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
tr:hover td {{ background: #f8fafc; }}
.sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }}
.sev-CRITICAL {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
.sev-HIGH {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
.sev-MEDIUM {{ background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }}
.sev-LOW {{ background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }}
.code-snippet {{ background: #1e293b; color: #e2e8f0; padding: 12px 16px; border-radius: 6px; font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 0.8em; overflow-x: auto; white-space: pre; margin: 4px 0; }}
.code-snippet .vuln-line {{ color: #fbbf24; font-weight: 600; }}
.confidence {{ display: inline-block; width: 50px; }}
.conf-bar {{ display: inline-block; height: 6px; border-radius: 3px; }}
.filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
.filter-btn {{ padding: 6px 14px; border: 1px solid #e2e8f0; border-radius: 6px; background: white; cursor: pointer; font-size: 0.8em; font-weight: 500; transition: all 0.2s; }}
.filter-btn:hover {{ background: #f1f5f9; }}
.filter-btn.active {{ background: #1e293b; color: white; border-color: #1e293b; }}
.remediation {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 16px; margin-bottom: 12px; }}
.remediation h4 {{ color: #166534; margin-bottom: 4px; }}
.remediation p {{ font-size: 0.85em; color: #15803d; }}
.remediation .cwe {{ font-size: 0.75em; color: #64748b; margin-top: 4px; }}
.llm-finding {{ border-left: 3px solid #8b5cf6; padding: 12px 16px; margin-bottom: 12px; background: #faf5ff; border-radius: 0 6px 6px 0; }}
.llm-finding h4 {{ color: #6d28d9; }}
footer {{ text-align: center; padding: 20px; color: #94a3b8; font-size: 0.8em; }}
.hidden {{ display: none; }}
@media print {{ body {{ background: white; }} header {{ background: #1e293b; -webkit-print-color-adjust: exact; }} }}
</style>
</head>
<body>
<header>
<div class="container">
<div>
<h1><span>APEX</span> Security Report</h1>
<p style="color:#94a3b8;margin-top:4px">Advanced PHP Exploitation Scanner v3.0</p>
</div>
<div class="meta">
<div>Target: <strong>{html.escape(os.path.basename(target))}</strong></div>
<div>{html.escape(scan_date[:19].replace("T", " "))}</div>
</div>
</div>
</header>
<div class="container">'''


def _html_summary(results: Dict, risk_score: int, risk_level: str, risk_color: str,
                  total: int, total_files: int, skipped: int,
                  ml_eliminated: int, llm_eliminated: int,
                  findings: Optional[List[Dict]] = None) -> str:
    crit = results.get('critical', 0)
    high = results.get('high', 0)
    med = results.get('medium', 0)
    low = results.get('low', 0)

    cards = f'''
<div class="cards">
<div class="card">
<h3>Risk Score</h3>
<div class="value" style="color:{risk_color}">{risk_score}</div>
<span class="risk-badge" style="background:{risk_color}20;color:{risk_color}">{risk_level} Risk</span>
</div>
<div class="card">
<h3>Total Findings</h3>
<div class="value">{total}</div>
<span style="font-size:0.8em;color:#64748b">{total_files} files scanned</span>
</div>
<div class="card">
<h3>Critical</h3>
<div class="value critical">{crit}</div>
</div>
<div class="card">
<h3>High</h3>
<div class="value high">{high}</div>
</div>
<div class="card">
<h3>Medium</h3>
<div class="value medium">{med}</div>
</div>'''

    if ml_eliminated or llm_eliminated:
        fp_total = ml_eliminated + llm_eliminated
        cards += f'''
<div class="card">
<h3>FPs Eliminated</h3>
<div class="value clean">{fp_total}</div>
<span style="font-size:0.8em;color:#64748b">{"ML: " + str(ml_eliminated) if ml_eliminated else ""}{"  " if ml_eliminated and llm_eliminated else ""}{"LLM: " + str(llm_eliminated) if llm_eliminated else ""}</span>
</div>'''

    cards += '</div>'

    # ML classification summary
    if findings:
        ml_tp = sum(1 for f in findings if f.get('ml_is_tp', True))
        ml_fp = sum(1 for f in findings if f.get('ml_score') is not None and not f.get('ml_is_tp', True))
        if ml_tp + ml_fp > 0:
            cards += f'<p style="margin-top:12px;font-size:0.9em;color:#475569">ML Classification: {ml_tp} likely real, {ml_fp} likely false positive</p>'

    return cards


def _html_severity_chart(results: Dict) -> str:
    crit = results.get('critical', 0)
    high = results.get('high', 0)
    med = results.get('medium', 0)
    low = results.get('low', 0)
    total = max(crit + high + med + low, 1)

    return f'''
<section>
<h2>Severity Distribution</h2>
<div class="bar-chart">
<div class="bar-row">
<div class="bar-label">Critical</div>
<div class="bar-track"><div class="bar-fill" style="width:{max(crit/total*100, 0.5 if crit else 0):.1f}%;background:#dc2626">{crit}</div></div>
<div class="bar-count" style="color:#dc2626">{crit}</div>
</div>
<div class="bar-row">
<div class="bar-label">High</div>
<div class="bar-track"><div class="bar-fill" style="width:{max(high/total*100, 0.5 if high else 0):.1f}%;background:#ea580c">{high}</div></div>
<div class="bar-count" style="color:#ea580c">{high}</div>
</div>
<div class="bar-row">
<div class="bar-label">Medium</div>
<div class="bar-track"><div class="bar-fill" style="width:{max(med/total*100, 0.5 if med else 0):.1f}%;background:#ca8a04">{med}</div></div>
<div class="bar-count" style="color:#ca8a04">{med}</div>
</div>
<div class="bar-row">
<div class="bar-label">Low</div>
<div class="bar-track"><div class="bar-fill" style="width:{max(low/total*100, 0.5 if low else 0):.1f}%;background:#2563eb">{low}</div></div>
<div class="bar-count" style="color:#2563eb">{low}</div>
</div>
</div>
</section>'''


def _html_type_breakdown(by_type: Dict) -> str:
    if not by_type:
        return ''

    sorted_types = sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True)
    total = sum(len(v) for v in by_type.values()) or 1

    rows = []
    colors = ['#6366f1', '#8b5cf6', '#a855f7', '#c084fc', '#d8b4fe', '#e9d5ff',
              '#818cf8', '#a78bfa', '#7c3aed', '#5b21b6']
    for i, (vtype, findings) in enumerate(sorted_types[:10]):
        color = colors[i % len(colors)]
        count = len(findings)
        cwe_info = CWE_MAP.get(vtype, ('', '', ''))
        cwe = cwe_info[0]
        pct = count / total * 100
        rows.append(f'''<div class="bar-row">
<div class="bar-label">{html.escape(vtype)} <span style="font-size:0.75em;color:#94a3b8">{cwe}</span></div>
<div class="bar-track"><div class="bar-fill" style="width:{max(pct, 2):.1f}%;background:{color}">{count}</div></div>
<div class="bar-count">{count}</div>
</div>''')

    return f'''
<section>
<h2>Vulnerability Types</h2>
<div class="bar-chart">
{"".join(rows)}
</div>
</section>'''


def _html_findings_table(findings: List[Dict], by_file: Dict) -> str:
    if not findings:
        return '''
<section>
<h2>Findings</h2>
<p style="text-align:center;color:#16a34a;padding:40px;font-size:1.2em">No vulnerabilities found!</p>
</section>'''

    # Filter buttons
    severity_set = sorted(set(f.get('severity', 'MEDIUM') for f in findings),
                         key=lambda s: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(s) if s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 4)

    filter_btns = ['<button class="filter-btn active" onclick="filterFindings(\'all\')">All</button>']
    for sev in severity_set:
        conf = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG['MEDIUM'])
        filter_btns.append(f'<button class="filter-btn" onclick="filterFindings(\'{sev}\')" '
                          f'style="border-color:{conf["border"]}">{sev}</button>')

    # Sort: CRITICAL first, then HIGH, etc.
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(findings, key=lambda f: (
        sev_order.get(f.get('severity', 'MEDIUM'), 4),
        f.get('file', ''),
        f.get('line', 0)
    ))

    rows = []
    for i, f in enumerate(sorted_findings):
        sev = f.get('severity', 'MEDIUM')
        vtype = f.get('type', 'Unknown')
        filepath = f.get('file', 'unknown')
        short_file = os.path.basename(filepath)
        line = f.get('line', 0)
        code = f.get('code', '')
        confidence = f.get('confidence', '0%')
        source = f.get('source', '')
        sanitizers = f.get('sanitizers', [])

        cwe_info = CWE_MAP.get(vtype, ('', '', ''))
        cwe = cwe_info[0]

        # Confidence bar color
        try:
            conf_val = float(str(confidence).rstrip('%')) / 100 if '%' in str(confidence) else float(confidence)
        except (ValueError, TypeError):
            conf_val = 0.5
        conf_color = '#dc2626' if conf_val >= 0.9 else '#ea580c' if conf_val >= 0.7 else '#ca8a04' if conf_val >= 0.5 else '#94a3b8'

        code_escaped = html.escape(code[:120])

        san_str = ''
        if sanitizers:
            san_str = f'<br><span style="font-size:0.75em;color:#16a34a">Sanitizers: {html.escape(", ".join(sanitizers[:3]))}</span>'

        source_str = ''
        if source:
            source_str = f'<span style="font-size:0.75em;color:#6366f1">Source: {html.escape(str(source))}</span>'

        # ML score display
        ml_score = f.get('ml_score', None)
        ml_method = f.get('ml_method', '')
        if ml_score is not None:
            if ml_score > 0.7:
                ml_color = '#dc3545'  # Red - likely real vulnerability
                ml_label = 'TP'
            elif ml_score > 0.4:
                ml_color = '#ffc107'  # Yellow - uncertain
                ml_label = '?'
            else:
                ml_color = '#28a745'  # Green - likely false positive
                ml_label = 'FP'
            ml_cell = f'<td><span style="color:{ml_color};font-weight:bold" title="{ml_method}: {ml_score:.2f}">{ml_label} ({ml_score:.0%})</span></td>'
        else:
            ml_cell = '<td>-</td>'

        rows.append(f'''<tr class="finding-row" data-severity="{sev}">
<td><span class="sev-badge sev-{sev}">{sev}</span></td>
<td><strong>{html.escape(vtype)}</strong><br><span style="font-size:0.75em;color:#94a3b8">{cwe}</span></td>
<td title="{html.escape(filepath)}"><strong>{html.escape(short_file)}</strong>:{line}</td>
<td><div class="code-snippet"><span class="vuln-line">{code_escaped}</span></div>{source_str}{san_str}</td>
<td><div class="confidence"><div class="conf-bar" style="width:{conf_val*50}px;background:{conf_color}"></div></div>{confidence}</td>
{ml_cell}
</tr>''')

    return f'''
<section>
<h2>Detailed Findings ({len(findings)})</h2>
<div class="filter-bar">
{"".join(filter_btns)}
</div>
<table id="findings-table">
<thead>
<tr>
<th onclick="sortTable(0)">Severity</th>
<th onclick="sortTable(1)">Type</th>
<th onclick="sortTable(2)">Location</th>
<th>Code</th>
<th onclick="sortTable(4)">Confidence</th>
<th>ML Score</th>
</tr>
</thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</section>

<script>
function filterFindings(severity) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.finding-row').forEach(row => {{
        if (severity === 'all' || row.dataset.severity === severity) {{
            row.classList.remove('hidden');
        }} else {{
            row.classList.add('hidden');
        }}
    }});
}}

function sortTable(col) {{
    const table = document.getElementById('findings-table');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
    table.dataset.sortDir = dir;
    rows.sort((a, b) => {{
        const aVal = a.cells[col].textContent.trim();
        const bVal = b.cells[col].textContent.trim();
        const cmp = aVal.localeCompare(bVal, undefined, {{numeric: true}});
        return dir === 'asc' ? cmp : -cmp;
    }});
    rows.forEach(row => tbody.appendChild(row));
}}
</script>'''


def _html_llm_findings(llm_findings: List[Dict]) -> str:
    if not llm_findings:
        return ''

    items = []
    for f in llm_findings:
        sev = f.get('severity', 'MEDIUM')
        vtype = f.get('vuln_type', 'Unknown')
        filepath = f.get('file', 'unknown')
        line = f.get('line', 0)
        desc = f.get('description', '')
        attack = f.get('attack_scenario', '')
        fix = f.get('fix', '')
        cwe = f.get('cwe', '')

        items.append(f'''<div class="llm-finding">
<h4><span class="sev-badge sev-{sev}">{sev}</span> {html.escape(vtype)}</h4>
<p><strong>{html.escape(os.path.basename(filepath))}:{line}</strong>{" - " + html.escape(cwe) if cwe else ""}</p>
<p>{html.escape(desc[:200])}</p>
{f'<p style="color:#9333ea"><strong>Attack:</strong> {html.escape(attack[:200])}</p>' if attack else ''}
{f'<p style="color:#16a34a"><strong>Fix:</strong> {html.escape(fix[:200])}</p>' if fix else ''}
</div>''')

    return f'''
<section>
<h2>LLM Deep Analysis ({len(llm_findings)} findings)</h2>
<p style="color:#6d28d9;font-size:0.85em;margin-bottom:12px">Additional vulnerabilities discovered by AI-powered deep analysis</p>
{"".join(items)}
</section>'''


def _html_remediation(by_type: Dict) -> str:
    if not by_type:
        return ''

    items = []
    for vtype in sorted(by_type.keys()):
        count = len(by_type[vtype])
        cwe_info = CWE_MAP.get(vtype, ('', vtype, 'Review and fix this vulnerability type.'))
        cwe, short_name, fix = cwe_info

        items.append(f'''<div class="remediation">
<h4>{html.escape(vtype)} ({count} finding{"s" if count != 1 else ""})</h4>
<p>{html.escape(fix)}</p>
<div class="cwe">{html.escape(cwe)} - {html.escape(short_name)}</div>
</div>''')

    return f'''
<section>
<h2>Remediation Guide</h2>
<p style="font-size:0.85em;color:#64748b;margin-bottom:16px">Prioritize fixes by severity. Address Critical and High findings first.</p>
{"".join(items)}
</section>'''


def _html_footer() -> str:
    return f'''
</div>
<footer>
Generated by APEX v3.0 - Advanced PHP Exploitation Scanner | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</footer>
</body>
</html>'''
