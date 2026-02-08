#!/usr/bin/env python3
"""
APEX ML/Heuristic False Positive Classifier

Two modes:
  1. Heuristic mode (default): Weighted feature scoring, instant, no training needed
  2. ML mode: Trained GradientBoosting classifier for higher accuracy

Features extracted from findings + code context:
  - Vulnerability type, severity, confidence
  - Source type (GET/POST/COOKIE/etc), sink function
  - Sanitizer presence and type match
  - Prepared statement / ORM proximity
  - Type casting proximity
  - Framework detection
  - Auth/admin context
  - Code complexity indicators
  - Validation before sink
"""

import os
import re
import json
import pickle
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path

from dataclasses import field as dataclass_field

try:
    from .rule_engine import get_rule_engine
except ImportError:
    get_rule_engine = None

# Optional v4.0 module imports - used when real analysis results available
try:
    from .type_inference import TypeInference, PHPType, TypeState
    _HAS_TYPE_INFERENCE = True
except ImportError:
    _HAS_TYPE_INFERENCE = False

try:
    from .alias_analysis import AliasAnalyzer
    _HAS_ALIAS = True
except ImportError:
    _HAS_ALIAS = False

try:
    from .string_domain import StringAnalyzer, StringValue
    _HAS_STRING_DOMAIN = True
except ImportError:
    _HAS_STRING_DOMAIN = False

try:
    from .abstract_interp import AbstractInterpreter, AbstractState, TaintLattice
    _HAS_ABSTRACT_INTERP = True
except ImportError:
    _HAS_ABSTRACT_INTERP = False

try:
    from .framework_models import FrameworkModelEngine
    _HAS_FRAMEWORK_MODELS = True
except ImportError:
    _HAS_FRAMEWORK_MODELS = False

try:
    from .interprocedural_v2 import InterproceduralEngine, FunctionSummary
    _HAS_INTERPROC_V2 = True
except ImportError:
    _HAS_INTERPROC_V2 = False

try:
    from .ts_adapter import parse_php_ts
    from .cfg import CFGBuilder
    _HAS_CFG = True
except ImportError:
    _HAS_CFG = False


# =========================================================================
# Pre-computed v4.0 Analysis Results (passed to FeatureExtractor)
# =========================================================================

@dataclass
class FileAnalysisResults:
    """Pre-computed v4.0 analysis results for a single file.

    Built by apex_core.py after running v4.0 modules. Passed to
    FeatureExtractor.extract() so ML features use REAL analysis
    instead of regex heuristics.

    All types are basic Python types (no v4.0 module imports required).
    """
    file_path: str = ""
    # TypeInference: var -> set of type strings ('INT', 'STRING', 'BOOL', etc.)
    type_map: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    # AliasAnalyzer: var -> set of alias variable names
    alias_sets: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    # StringAnalyzer: line_num -> {safe: bool, ratio: float, context: str}
    string_contexts: Dict[int, Dict] = dataclass_field(default_factory=dict)
    # AbstractInterpreter: var -> taint level (0=BOTTOM, 1=UNTAINTED, 2=WEAK, 3=TAINTED, 4=TOP)
    taint_levels: Dict[str, int] = dataclass_field(default_factory=dict)
    # AbstractInterpreter: var -> set of sanitized vuln types
    sanitized_types: Dict[str, Set[str]] = dataclass_field(default_factory=dict)
    # InterproceduralEngine: func -> {params_to_sink: Set[str], sanitizer_for: Set[str]}
    func_summaries: Dict[str, Dict] = dataclass_field(default_factory=dict)
    # FrameworkModelEngine: validated variable names
    validated_vars: Set[str] = dataclass_field(default_factory=set)
    framework: str = ""
    middleware: Set[str] = dataclass_field(default_factory=set)
    orm_vars: Set[str] = dataclass_field(default_factory=set)


def build_file_analysis(file_path: str, code: str,
                         rule_engine=None) -> Optional['FileAnalysisResults']:
    """Run v4.0 analysis modules on a file and return results.

    This is the bridge between v4.0 analysis and ML feature extraction.
    Returns None if essential modules are not available.
    """
    if not _HAS_CFG:
        return None

    results = FileAnalysisResults(file_path=file_path)

    try:
        root = parse_php_ts(code)
    except Exception:
        return None

    # Find function bodies for CFG analysis
    cfg_blocks_all = []
    func_bodies = {}
    for node in root.walk_descendants():
        if node.type in ('function_definition', 'method_declaration'):
            fname_node = node.child_by_field('name')
            fname = fname_node.text if fname_node else ''
            body = node.child_by_field('body')
            if body:
                try:
                    blocks = CFGBuilder().build(body)
                    cfg_blocks_all.extend(blocks)
                    if fname:
                        func_bodies[fname] = blocks
                except Exception:
                    pass

    # Also try top-level code
    if not cfg_blocks_all:
        try:
            cfg_blocks_all = CFGBuilder().build(root)
        except Exception:
            pass

    if not cfg_blocks_all:
        return results

    # TypeInference
    if _HAS_TYPE_INFERENCE:
        try:
            re_arg = rule_engine or (get_rule_engine() if get_rule_engine else None)
            if re_arg:
                ti = TypeInference(re_arg)
                type_map = ti.infer(cfg_blocks_all)
                for var, types in type_map.items():
                    results.type_map[var] = {t.value if hasattr(t, 'value') else str(t) for t in types}
        except Exception:
            pass

    # AliasAnalyzer
    if _HAS_ALIAS:
        try:
            aa = AliasAnalyzer()
            aa.analyze(cfg_blocks_all)
            for var in list(aa._points_to.keys()):
                if var.startswith('$'):
                    aliases = aa.get_aliases(var)
                    if len(aliases) > 1:
                        results.alias_sets[var] = aliases
        except Exception:
            pass

    # FrameworkModelEngine
    if _HAS_FRAMEWORK_MODELS:
        try:
            re_arg = rule_engine or (get_rule_engine() if get_rule_engine else None)
            if re_arg:
                fme = FrameworkModelEngine(re_arg)
                results.middleware = fme.detect_route_middleware(code)
                results.orm_vars = fme.detect_orm_usage(code)
                # Detect framework validation
                from .abstract_interp import AbstractState, TaintLattice, TaintInfo
                dummy_state = AbstractState()
                # Make common input variables tainted in dummy state
                for var in ['$id', '$name', '$email', '$input', '$data',
                            '$request', '$value', '$param', '$query']:
                    dummy_state.set(var, TaintInfo(
                        level=TaintLattice.TAINTED,
                        taint_types={'SQL', 'XSS', 'COMMAND'},
                        sources={var}
                    ))
                new_state = fme.apply_validation_constraints('laravel', code, dummy_state)
                # Find which variables got sanitized
                for var in ['$id', '$name', '$email', '$input', '$data',
                            '$request', '$value', '$param', '$query']:
                    info = new_state.get(var)
                    if info and info.sanitized_types:
                        results.validated_vars.add(var)
        except Exception:
            pass

    return results


# =========================================================================
# Feature Extraction
# =========================================================================

# Sanitizer → vulnerability type mapping (which sanitizers fix which vulns)
SANITIZER_TYPE_MAP = {
    # SQL sanitizers
    'mysql_real_escape_string': {'SQL Injection'},
    'mysqli_real_escape_string': {'SQL Injection'},
    'addslashes': {'SQL Injection'},
    'pg_escape_string': {'SQL Injection'},
    'PDO::quote': {'SQL Injection'},
    'safesql': {'SQL Injection'},
    'intval': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection', 'Path Traversal'},
    'floatval': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'abs': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    # XSS sanitizers
    'htmlspecialchars': {'Cross-Site Scripting'},
    'htmlentities': {'Cross-Site Scripting'},
    'strip_tags': {'Cross-Site Scripting'},
    'wp_kses': {'Cross-Site Scripting'},
    'esc_html': {'Cross-Site Scripting'},
    'esc_attr': {'Cross-Site Scripting'},
    'e()': {'Cross-Site Scripting'},
    # Command sanitizers
    'escapeshellarg': {'Command Injection'},
    'escapeshellcmd': {'Command Injection'},
    # File sanitizers
    'basename': {'Path Traversal', 'File Inclusion', 'Arbitrary File Read', 'Arbitrary File Write'},
    'realpath': {'Path Traversal', 'File Inclusion'},
    # General
    'filter_var': {'Cross-Site Scripting', 'SQL Injection', 'Server-Side Request Forgery'},
    'preg_replace': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_alnum': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_alpha': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'ctype_digit': {'SQL Injection', 'Cross-Site Scripting', 'Command Injection'},
    'is_numeric': {'SQL Injection', 'Cross-Site Scripting'},
}

# Source risk levels (higher = more likely user-controlled)
SOURCE_RISK = {
    '$_GET': 1.0,
    '$_POST': 1.0,
    '$_REQUEST': 1.0,
    '$_COOKIE': 0.9,
    '$_FILES': 0.85,
    '$_SERVER': 0.5,
    '$_ENV': 0.3,
    '$_SESSION': 0.1,  # Usually safe (server-side)
}

# Sink danger levels
SINK_DANGER = {
    'eval': 1.0, 'assert': 1.0, 'create_function': 1.0,
    'system': 1.0, 'exec': 1.0, 'passthru': 1.0, 'shell_exec': 1.0,
    'popen': 0.95, 'proc_open': 0.95, 'pcntl_exec': 1.0,
    'unserialize': 0.95,
    'mysql_query': 0.9, 'mysqli_query': 0.9, 'pg_query': 0.9,
    'query': 0.85, 'prepare': 0.3,  # prepare is usually safe
    'echo': 0.7, 'print': 0.7, 'die': 0.6,
    'include': 0.9, 'require': 0.9, 'include_once': 0.85, 'require_once': 0.85,
    'file_get_contents': 0.8, 'file_put_contents': 0.9,
    'fopen': 0.8, 'fwrite': 0.85,
    'header': 0.7, 'setcookie': 0.6,
    'curl_setopt': 0.8, 'file': 0.75,
    'mail': 0.6, 'preg_replace': 0.5,
    'ldap_search': 0.85, 'ldap_bind': 0.8,
    'simplexml_load_string': 0.85,
}

# Patterns for detecting various code context features
PREPARED_STMT_PATTERNS = [
    r'->prepare\s*\(',
    r'\?\s*,',  # Positional placeholders
    r':\w+\s*[,\)]',  # Named placeholders
    r'bindParam|bindValue|bind_param',
    r'PDO::\w+',
    r'execute\s*\(\s*\[',
    r'->where\s*\(',  # ORM where clause
    r'->find\s*\(',
    r'->findOrFail\s*\(',
    r'Eloquent|Doctrine|ActiveRecord',
    r'DB::table|DB::select|DB::insert',
]

TYPE_CAST_PATTERNS = [
    r'\(int\)\s*\$',
    r'\(float\)\s*\$',
    r'\(bool\)\s*\$',
    r'\(integer\)\s*\$',
    r'intval\s*\(\s*\$',
    r'floatval\s*\(\s*\$',
    r'boolval\s*\(\s*\$',
    r'abs\s*\(\s*\$',
    r'settype\s*\(',
]

VALIDATION_PATTERNS = [
    r'is_numeric\s*\(',
    r'is_int\s*\(',
    r'is_string\s*\(',
    r'ctype_\w+\s*\(',
    r'filter_var\s*\(.*FILTER_VALIDATE',
    r'preg_match\s*\(\s*[\'"][\/~#]\^',  # Anchored regex
    r'in_array\s*\(',
    r'array_key_exists\s*\(',
    r'isset\s*\(\s*\$\w+\[',
    r'switch\s*\(\s*\$',  # Switch on var (whitelist)
    r'FILTER_SANITIZE',
]

AUTH_CHECK_PATTERNS = [
    r'(?:check|is|has|verify)_?(?:auth|login|logged|admin|permission|role|access)',
    r'->isAuthenticated|->isLoggedIn|->hasRole|->can\(',
    r'\$_SESSION\s*\[\s*[\'"](?:user|admin|auth|login|token)',
    r'Auth::|Gate::|Policy::',
    r'wp_verify_nonce|check_admin_referer|current_user_can',
    r'session_start.*?(?:if|unless).*?(?:user|login|auth)',
    r'@login_required|@auth|@middleware\([\'"]auth',
]

COMMENT_PATTERNS = [
    r'^\s*(?://|#)',
    r'^\s*/?\*',
    r'^\s*\*\s',
]

# CMS-specific FP patterns: things commonly found in CMS code that look
# dangerous but are actually safe due to framework protections
CMS_SAFE_PATTERNS = [
    # DLE CMS encoded files (commercial license protection, not backdoor)
    r'\$_F\s*=\s*__FILE__',
    r'\$_X\s*=\s*["\']',
    r'eval\s*\(\s*\$_X\)',
    # WordPress safe patterns
    r'wp_kses\s*\(',
    r'esc_sql\s*\(',
    r'wp_nonce\s*\(',
    r'\$wpdb->prepare\s*\(',
    r'sanitize_text_field\s*\(',
    r'absint\s*\(',
    # Laravel safe patterns
    r'Validator::make\s*\(',
    r'\$request->validate\(',
    r'->validated\(\)',
    r'Crypt::|encrypt\s*\(',
    # Symfony safe patterns
    r'->createQueryBuilder\(',
    r'ParamConverter',
    # General CMS safety
    r'nonce_check|verify_nonce|check_referer',
    r'htmlPurifier|HTMLPurifier',
]

FRAMEWORK_PATTERNS = {
    'laravel': r'Illuminate\\|Route::|Eloquent|Auth::|\$request->input|blade\.php',
    'symfony': r'Symfony\\|AbstractController|@Route|->getRepository\(',
    'wordpress': r'wp_|WP_|WordPress|add_action|add_filter|get_option',
    'codeigniter': r'CI_Controller|->input->|->db->|codeigniter',
    'yii': r'Yii::|CActiveRecord|yii\\|Yii2',
    'drupal': r'drupal_|Drupal\\|hook_|\.module$',
    'cakephp': r'CakePlugin|AppController|cake|TableRegistry',
}


def _extend_ml_patterns_from_rule_engine():
    """Extend feature extraction patterns from RuleEngine fp_rules. Hardcoded values are kept as fallback."""
    try:
        if get_rule_engine is None:
            return
        engine = get_rule_engine()
        if engine is None:
            return

        fp_rules = engine.get_fp_rules()
        if not fp_rules:
            return

        # Extend PREPARED_STMT_PATTERNS from 'prepared_stmt' category
        prep_rules = fp_rules.get('prepared_stmt', [])
        existing_prep = set(PREPARED_STMT_PATTERNS)
        for rule in prep_rules:
            if rule.pattern and rule.pattern not in existing_prep:
                PREPARED_STMT_PATTERNS.append(rule.pattern)

        # Extend TYPE_CAST_PATTERNS from 'type_cast' category
        cast_rules = fp_rules.get('type_cast', [])
        existing_cast = set(TYPE_CAST_PATTERNS)
        for rule in cast_rules:
            if rule.pattern and rule.pattern not in existing_cast:
                TYPE_CAST_PATTERNS.append(rule.pattern)

        # Extend VALIDATION_PATTERNS from 'validation' category
        val_rules = fp_rules.get('validation', [])
        existing_val = set(VALIDATION_PATTERNS)
        for rule in val_rules:
            if rule.pattern and rule.pattern not in existing_val:
                VALIDATION_PATTERNS.append(rule.pattern)

        # Extend AUTH_CHECK_PATTERNS from 'auth' category
        auth_rules = fp_rules.get('auth', [])
        existing_auth = set(AUTH_CHECK_PATTERNS)
        for rule in auth_rules:
            if rule.pattern and rule.pattern not in existing_auth:
                AUTH_CHECK_PATTERNS.append(rule.pattern)

        # Extend CMS_SAFE_PATTERNS from 'cms_safe' category
        cms_rules = fp_rules.get('cms_safe', [])
        existing_cms = set(CMS_SAFE_PATTERNS)
        for rule in cms_rules:
            if rule.pattern and rule.pattern not in existing_cms:
                CMS_SAFE_PATTERNS.append(rule.pattern)

        # Extend SANITIZER_TYPE_MAP from RuleEngine sanitizers
        all_sanitizers = engine.get_sanitizers()
        if all_sanitizers:
            # Map RuleEngine protects_against to the vuln type names used in SANITIZER_TYPE_MAP
            _vuln_name_map = {
                'SQL_INJECTION': 'SQL Injection',
                'SQL': 'SQL Injection',
                'XSS': 'Cross-Site Scripting',
                'CROSS_SITE_SCRIPTING': 'Cross-Site Scripting',
                'COMMAND_INJECTION': 'Command Injection',
                'COMMAND': 'Command Injection',
                'PATH_TRAVERSAL': 'Path Traversal',
                'FILE_INCLUSION': 'File Inclusion',
                'FILE': 'Path Traversal',
                'SSRF': 'Server-Side Request Forgery',
                'CODE_INJECTION': 'Code Injection',
                'CODE': 'Code Injection',
            }
            for san_name, san_def in all_sanitizers.items():
                if san_name not in SANITIZER_TYPE_MAP:
                    vuln_types = set()
                    for prot in san_def.protects_against:
                        mapped = _vuln_name_map.get(prot.upper())
                        if mapped:
                            vuln_types.add(mapped)
                    if vuln_types:
                        SANITIZER_TYPE_MAP[san_name] = vuln_types

    except Exception:
        # If RuleEngine fails, fall back to hardcoded patterns silently
        pass


# Extend patterns from RuleEngine at module load time
_extend_ml_patterns_from_rule_engine()


@dataclass
class FeatureVector:
    """Features extracted from a single finding for classification."""
    # Vulnerability characteristics
    vuln_type: str = ""
    severity: int = 0  # 0-4
    rule_confidence: float = 0.0

    # Source characteristics
    source_type: str = ""  # GET, POST, REQUEST, etc.
    source_risk: float = 0.0
    has_direct_source: bool = False  # $_GET directly in sink vs through variable

    # Sink characteristics
    sink_function: str = ""
    sink_danger: float = 0.0

    # Sanitization
    sanitizer_present: bool = False
    sanitizer_count: int = 0
    sanitizer_type_match: bool = False  # Does sanitizer match vuln type?
    sanitizer_distance: int = 999  # Lines between sanitizer and sink

    # Context patterns
    prepared_stmt_nearby: bool = False
    type_cast_nearby: bool = False
    validation_nearby: bool = False
    orm_detected: bool = False

    # Code context
    in_comment: bool = False
    in_admin_path: bool = False
    auth_check_nearby: bool = False
    in_try_catch: bool = False
    in_loop: bool = False

    # Framework
    framework_detected: str = ""
    is_framework_safe_pattern: bool = False

    # File characteristics
    file_lines: int = 0
    is_ajax_handler: bool = False
    is_public_endpoint: bool = False

    # Variable tracking
    var_reassigned: bool = False
    uses_string_concat: bool = False
    uses_interpolation: bool = False

    # CMS/framework safety
    cms_safe_pattern: bool = False

    # --- v4.0 features (from new analysis modules) ---
    # SSA-based: variable sanitized in one branch but not the other (phi node)
    ssa_branch_sanitized: bool = False
    # String domain: tainted fragment in safe SQL position (FROM/INTO vs WHERE)
    string_context_safe: bool = False
    # String domain: ratio of tainted fragments to total fragments
    string_tainted_ratio: float = 0.0
    # Type inference: variable narrowed to safe type (INT/BOOL/FLOAT)
    type_narrowed_safe: bool = False
    # Alias analysis: number of aliases for tainted variable
    alias_count: int = 0
    # Inter-procedural: taint flows through function call to sink
    interproc_flow_to_sink: bool = False
    # Inter-procedural: callee function wraps a sanitizer
    interproc_sanitized: bool = False
    # Framework models: Laravel/Symfony validation applied to input
    framework_validated: bool = False

    def to_dict(self) -> Dict:
        """Convert to dict for ML model input."""
        return {
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'rule_confidence': self.rule_confidence,
            'source_risk': self.source_risk,
            'has_direct_source': int(self.has_direct_source),
            'sink_danger': self.sink_danger,
            'sanitizer_present': int(self.sanitizer_present),
            'sanitizer_count': self.sanitizer_count,
            'sanitizer_type_match': int(self.sanitizer_type_match),
            'sanitizer_distance': min(self.sanitizer_distance, 100),
            'prepared_stmt_nearby': int(self.prepared_stmt_nearby),
            'type_cast_nearby': int(self.type_cast_nearby),
            'validation_nearby': int(self.validation_nearby),
            'orm_detected': int(self.orm_detected),
            'in_comment': int(self.in_comment),
            'in_admin_path': int(self.in_admin_path),
            'auth_check_nearby': int(self.auth_check_nearby),
            'in_try_catch': int(self.in_try_catch),
            'is_ajax_handler': int(self.is_ajax_handler),
            'var_reassigned': int(self.var_reassigned),
            'uses_string_concat': int(self.uses_string_concat),
            'uses_interpolation': int(self.uses_interpolation),
            'cms_safe_pattern': int(self.cms_safe_pattern),
            # v4.0 features
            'ssa_branch_sanitized': int(self.ssa_branch_sanitized),
            'string_context_safe': int(self.string_context_safe),
            'string_tainted_ratio': self.string_tainted_ratio,
            'type_narrowed_safe': int(self.type_narrowed_safe),
            'alias_count': min(self.alias_count, 10),
            'interproc_flow_to_sink': int(self.interproc_flow_to_sink),
            'interproc_sanitized': int(self.interproc_sanitized),
            'framework_validated': int(self.framework_validated),
        }

    def to_numeric_array(self) -> List[float]:
        """Convert to flat numeric array for ML model."""
        d = self.to_dict()
        # Remove vuln_type (categorical - encode separately)
        del d['vuln_type']
        return list(d.values())


class FeatureExtractor:
    """Extract features from a finding + code context for FP classification."""

    # Common sanitizer function names
    SANITIZER_NAMES = set(SANITIZER_TYPE_MAP.keys()) | {
        'clean', 'sanitize', 'escape', 'filter', 'safe', 'validate',
        'purify', 'secure', 'protect', 'encode', 'strip', 'trim',
        'totranslit', 'DLEPlugins::Check',
    }

    def extract(self, finding_dict: Dict, code: str = "",
                file_lines: List[str] = None,
                analysis: Optional[FileAnalysisResults] = None) -> FeatureVector:
        """Extract features from a finding dictionary and its file code."""
        fv = FeatureVector()

        # Basic finding info
        fv.vuln_type = finding_dict.get('type', '')
        sev = finding_dict.get('severity', 'MEDIUM')
        fv.severity = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(sev, 2)

        conf_str = finding_dict.get('confidence', '50%')
        if isinstance(conf_str, str) and '%' in conf_str:
            fv.rule_confidence = float(conf_str.replace('%', '')) / 100.0
        elif isinstance(conf_str, (int, float)):
            fv.rule_confidence = float(conf_str) if conf_str <= 1 else float(conf_str) / 100.0
        else:
            fv.rule_confidence = 0.5

        code_line = finding_dict.get('code', '')
        line_num = finding_dict.get('line', 0)
        filepath = finding_dict.get('file', '')

        if file_lines is None and code:
            file_lines = code.split('\n')
        elif file_lines is None:
            file_lines = []

        fv.file_lines = len(file_lines)

        # Source detection
        fv.source_type, fv.source_risk, fv.has_direct_source = (
            self._detect_source(code_line, file_lines, line_num)
        )

        # Sink detection
        fv.sink_function, fv.sink_danger = self._detect_sink(code_line, fv.vuln_type)

        # Context window (lines around finding)
        ctx_start = max(0, line_num - 20)
        ctx_end = min(len(file_lines), line_num + 10)
        context_lines = file_lines[ctx_start:ctx_end] if file_lines else []
        context_text = '\n'.join(context_lines)

        # Sanitizer detection
        (fv.sanitizer_present, fv.sanitizer_count,
         fv.sanitizer_type_match, fv.sanitizer_distance) = (
            self._detect_sanitizers(context_lines, fv.vuln_type, line_num, ctx_start)
        )

        # Prepared statements / ORM
        fv.prepared_stmt_nearby = any(
            re.search(p, context_text) for p in PREPARED_STMT_PATTERNS
        )
        fv.orm_detected = fv.prepared_stmt_nearby  # Alias for now

        # Type casting
        fv.type_cast_nearby = any(
            re.search(p, context_text) for p in TYPE_CAST_PATTERNS
        )

        # Validation
        fv.validation_nearby = any(
            re.search(p, context_text) for p in VALIDATION_PATTERNS
        )

        # Comment detection
        fv.in_comment = self._is_in_comment(code_line)

        # Admin path
        fv.in_admin_path = bool(re.search(
            r'(?:admin|backend|manage|cpanel|dashboard)',
            filepath, re.IGNORECASE
        ))

        # Auth check
        fv.auth_check_nearby = any(
            re.search(p, context_text, re.IGNORECASE) for p in AUTH_CHECK_PATTERNS
        )

        # Try-catch
        fv.in_try_catch = bool(re.search(r'\btry\s*\{', context_text))

        # Loop detection
        fv.in_loop = bool(re.search(
            r'\b(?:for|foreach|while|do)\s*[\(\{]', context_text
        ))

        # Framework detection
        fv.framework_detected = self._detect_framework(code)

        # Ajax handler detection
        fv.is_ajax_handler = bool(re.search(
            r'ajax|api|json|endpoint|xmlhttp|X-Requested-With',
            filepath + code_line, re.IGNORECASE
        ))

        # String operations
        fv.uses_string_concat = bool(re.search(r'\.\s*\$\w+|\$\w+\s*\.', code_line))
        fv.uses_interpolation = bool(re.search(r'"\$\w+|"\{?\$', code_line))

        # Variable reassignment check (look for same var being reassigned before sink)
        fv.var_reassigned = self._check_var_reassigned(context_lines, code_line, line_num, ctx_start)

        # CMS safe pattern detection
        fv.cms_safe_pattern = self._check_cms_safe_patterns(context_text, code_line)

        # --- v4.0 feature extraction ---
        # Use REAL analysis results when available, fall back to regex heuristics
        if analysis:
            fv.type_narrowed_safe = self._real_type_narrowed(
                code_line, fv.vuln_type, analysis
            )
            fv.alias_count = self._real_alias_count(code_line, analysis)
            fv.string_context_safe = self._real_string_context(
                line_num, code_line, fv.vuln_type, analysis
            )
            fv.framework_validated = self._real_framework_validated(
                code_line, analysis
            )
            fv.interproc_sanitized = self._real_interproc_sanitized(
                code_line, context_lines, analysis
            )
            # ORM detection from real analysis
            if analysis.orm_vars:
                fv.orm_detected = True
            # These still use heuristics even with analysis (hard to derive from v4.0)
            fv.ssa_branch_sanitized = self._detect_branch_sanitization(
                context_lines, code_line, line_num, ctx_start
            )
            fv.string_tainted_ratio = self._calc_tainted_ratio(code_line)
            fv.interproc_flow_to_sink = self._detect_interproc_flow(
                context_lines, code_line, line_num, ctx_start
            )
        else:
            # Regex heuristic fallback (no v4.0 analysis available)
            fv.ssa_branch_sanitized = self._detect_branch_sanitization(
                context_lines, code_line, line_num, ctx_start
            )
            fv.string_context_safe = self._detect_string_context_safe(
                code_line, fv.vuln_type
            )
            fv.string_tainted_ratio = self._calc_tainted_ratio(code_line)
            fv.type_narrowed_safe = self._detect_type_narrowing(
                context_lines, code_line, fv.vuln_type
            )
            fv.alias_count = self._count_aliases(context_text, code_line)
            fv.interproc_flow_to_sink = self._detect_interproc_flow(
                context_lines, code_line, line_num, ctx_start
            )
            fv.interproc_sanitized = self._detect_interproc_sanitizer(
                context_lines, code_line
            )
            fv.framework_validated = self._detect_framework_validation(
                context_text, code_line
            )

        return fv

    def _detect_source(self, code_line: str, file_lines: List[str],
                       line_num: int) -> Tuple[str, float, bool]:
        """Detect taint source type and risk level."""
        # Check direct source in code line
        for source, risk in SOURCE_RISK.items():
            if source in code_line:
                return source.replace('$_', ''), risk, True

        # Check context lines for source
        start = max(0, line_num - 30)
        context = '\n'.join(file_lines[start:line_num]) if file_lines else ''
        for source, risk in SOURCE_RISK.items():
            if source in context:
                return source.replace('$_', ''), risk * 0.7, False

        return '', 0.3, False  # Unknown source, moderate risk

    def _detect_sink(self, code_line: str, vuln_type: str) -> Tuple[str, float]:
        """Detect sink function and danger level."""
        for func, danger in SINK_DANGER.items():
            if re.search(rf'\b{re.escape(func)}\s*\(', code_line):
                return func, danger
            # Check method call style
            if re.search(rf'->{re.escape(func)}\s*\(', code_line):
                return func, danger

        # Infer from vuln type
        type_danger = {
            'Code Injection': 0.95,
            'Remote Code Execution': 1.0,
            'Command Injection': 0.95,
            'SQL Injection': 0.85,
            'File Inclusion': 0.9,
            'Insecure Deserialization': 0.9,
            'Cross-Site Scripting': 0.7,
            'Path Traversal': 0.75,
            'Open Redirect': 0.5,
            'Information Disclosure': 0.3,
            'Weak Cryptography': 0.4,
            'Type Juggling': 0.5,
        }
        return '', type_danger.get(vuln_type, 0.5)

    def _detect_sanitizers(self, context_lines: List[str], vuln_type: str,
                           line_num: int, ctx_start: int
                           ) -> Tuple[bool, int, bool, int]:
        """Detect sanitizers, count them, check type match, measure distance."""
        found = False
        count = 0
        type_match = False
        min_distance = 999

        context_text = '\n'.join(context_lines)

        # Check each sanitizer
        for san_name, vuln_types in SANITIZER_TYPE_MAP.items():
            # Escape for regex
            pattern = re.escape(san_name).replace(r'\:', ':')
            if re.search(pattern, context_text, re.IGNORECASE):
                found = True
                count += 1
                if vuln_type in vuln_types:
                    type_match = True

                # Find distance to finding line
                for i, line in enumerate(context_lines):
                    if re.search(pattern, line, re.IGNORECASE):
                        actual_line = ctx_start + i + 1
                        dist = abs(actual_line - line_num)
                        min_distance = min(min_distance, dist)

        # Also check generic sanitizer patterns
        for line in context_lines:
            for name in ['clean', 'sanitize', 'escape', 'filter', 'safe',
                         'validate', 'purify', 'protect']:
                if re.search(rf'\b\w*{name}\w*\s*\(', line, re.IGNORECASE):
                    found = True
                    count += 1
                    break

        return found, count, type_match, min_distance

    def _is_in_comment(self, code_line: str) -> bool:
        """Check if code line is a comment."""
        stripped = code_line.strip()
        return (stripped.startswith('//') or stripped.startswith('#') or
                stripped.startswith('*') or stripped.startswith('/*'))

    def _detect_framework(self, code: str) -> str:
        """Detect PHP framework from code."""
        if not code:
            return ''
        sample = code[:5000]  # Only check first 5000 chars
        for name, pattern in FRAMEWORK_PATTERNS.items():
            if re.search(pattern, sample):
                return name
        return ''

    def _check_cms_safe_patterns(self, context_text: str, code_line: str) -> bool:
        """Check if CMS/framework-specific safe patterns are present."""
        for pattern in CMS_SAFE_PATTERNS:
            if re.search(pattern, context_text, re.IGNORECASE):
                return True
        return False

    # ------------------------------------------------------------------
    # v4.0 REAL analysis methods (use pre-computed FileAnalysisResults)
    # ------------------------------------------------------------------

    def _real_type_narrowed(self, code_line: str, vuln_type: str,
                             analysis: FileAnalysisResults) -> bool:
        """Check type narrowing using REAL TypeInference results."""
        if not analysis.type_map:
            return False
        # Safe types for SQL/XSS: INT, FLOAT, BOOL
        safe_types = {'INT', 'FLOAT', 'BOOL', 'NULL', 'int', 'float', 'bool', 'null'}
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.type_map:
                types = analysis.type_map[var]
                # All types are safe → variable is safe
                if types and types.issubset(safe_types):
                    return True
        return False

    def _real_alias_count(self, code_line: str,
                           analysis: FileAnalysisResults) -> int:
        """Count aliases using REAL AliasAnalyzer results."""
        if not analysis.alias_sets:
            return 0
        max_aliases = 0
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.alias_sets:
                count = len(analysis.alias_sets[var]) - 1  # Exclude self
                max_aliases = max(max_aliases, count)
        return max_aliases

    def _real_string_context(self, line_num: int, code_line: str,
                              vuln_type: str,
                              analysis: FileAnalysisResults) -> bool:
        """Check string context safety using REAL StringAnalyzer results."""
        if analysis.string_contexts and line_num in analysis.string_contexts:
            ctx = analysis.string_contexts[line_num]
            return ctx.get('safe', False)
        # Fall back to regex if no pre-computed string context
        return self._detect_string_context_safe(code_line, vuln_type)

    def _real_framework_validated(self, code_line: str,
                                   analysis: FileAnalysisResults) -> bool:
        """Check framework validation using REAL FrameworkModelEngine results."""
        if not analysis.validated_vars:
            return False
        for var_match in re.finditer(r'\$\w+', code_line):
            var = var_match.group(0)
            if var in analysis.validated_vars:
                return True
        # Also check ORM-protected variables
        if analysis.orm_vars:
            for var_match in re.finditer(r'\$\w+', code_line):
                var = var_match.group(0)
                if var in analysis.orm_vars:
                    return True
        return False

    def _real_interproc_sanitized(self, code_line: str,
                                   context_lines: List[str],
                                   analysis: FileAnalysisResults) -> bool:
        """Check inter-procedural sanitization using REAL analysis results."""
        if not analysis.func_summaries:
            return self._detect_interproc_sanitizer(context_lines, code_line)
        # Check if any function called in context is a known sanitizer
        context_text = '\n'.join(context_lines)
        for func_name, summary in analysis.func_summaries.items():
            sanitizer_for = summary.get('sanitizer_for', set())
            if sanitizer_for and re.search(rf'\b{re.escape(func_name)}\s*\(', context_text):
                return True
        return False

    # ------------------------------------------------------------------
    # v4.0 HEURISTIC feature extraction methods (regex fallback)
    # ------------------------------------------------------------------

    def _detect_branch_sanitization(self, context_lines: List[str],
                                     code_line: str, line_num: int,
                                     ctx_start: int) -> bool:
        """Detect if variable is sanitized in one branch but not the other.

        Approximates SSA phi-node analysis: if there's an if/else where
        the variable is sanitized (intval, htmlspecialchars, etc.) in one
        branch but used raw in the other, this is a branch-sanitized pattern.
        """
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))

        # Look for if/else structure with sanitization of same variable
        context_text = '\n'.join(context_lines)
        # Pattern: if(...) { ... sanitizer($var) ... } else { ... $var ... }
        san_funcs = '|'.join(['intval', 'floatval', 'htmlspecialchars',
                              'htmlentities', 'strip_tags', 'addslashes',
                              'escapeshellarg', 'basename', 'filter_var',
                              'mysql_real_escape_string', 'mysqli_real_escape_string'])
        has_branch = bool(re.search(r'\b(?:if|else)\b', context_text))
        has_sanitizer_on_var = bool(re.search(
            rf'(?:{san_funcs})\s*\(\s*{var_name}', context_text
        ))
        has_raw_usage = bool(re.search(
            rf'(?:echo|query|exec|system|include|eval|header)\s*\(.*?{var_name}',
            context_text
        ))
        return has_branch and has_sanitizer_on_var and has_raw_usage

    def _detect_string_context_safe(self, code_line: str,
                                     vuln_type: str) -> bool:
        """Detect if tainted data is in a safe string context.

        For SQL: variable after FROM/INTO/TABLE = table name position (safe).
        For XSS: inside HTML comment or after safe attribute.
        For CMD: variable as argument, not command name.
        """
        if 'SQL' in vuln_type or vuln_type == 'SQL Injection':
            # Tainted var after FROM/INTO/JOIN = table name, generally safe
            if re.search(r'\b(?:FROM|INTO|JOIN|TABLE)\s+["\']?\s*\.\s*\$\w+',
                         code_line, re.IGNORECASE):
                return True
            # Hardcoded value in WHERE (no variable)
            if re.search(r'WHERE\s+\w+\s*=\s*[\'"][^$]*[\'"]', code_line):
                return True

        if 'XSS' in vuln_type or vuln_type == 'Cross-Site Scripting':
            # Inside HTML comment
            if re.search(r'<!--.*\$\w+.*-->', code_line):
                return True
            # In meta tag (not displayed)
            if re.search(r'<meta\b.*\$\w+', code_line, re.IGNORECASE):
                return True

        if 'Command' in vuln_type:
            # Variable is an argument, not the command itself
            # Pattern: exec("fixed_cmd " . $var) - var is argument
            if re.search(r'(?:exec|system|passthru|shell_exec)\s*\(\s*["\'][a-zA-Z_/]+\s',
                         code_line):
                return True

        return False

    def _calc_tainted_ratio(self, code_line: str) -> float:
        """Calculate ratio of tainted (variable) fragments in a string expression.

        Higher ratio = more of the string is user-controlled.
        """
        # Count string literal parts vs variable parts in concatenation
        parts = re.split(r'\s*\.\s*', code_line)
        if not parts:
            return 0.0
        n_total = len(parts)
        n_tainted = 0
        for part in parts:
            if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)', part):
                n_tainted += 1
            elif re.search(r'\$\w+', part) and not re.search(r'["\'][^$]*["\']', part):
                n_tainted += 1  # Variable (potentially tainted)
        return n_tainted / n_total if n_total > 0 else 0.0

    def _detect_type_narrowing(self, context_lines: List[str],
                                code_line: str, vuln_type: str) -> bool:
        """Detect if type narrowing makes the variable safe.

        Looks for is_int()/is_numeric() guards or intval()/(int) casts
        on the variable BEFORE it reaches the sink, in a way that
        guarantees an integer type (safe for SQLi, XSS).
        """
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))
        context_text = '\n'.join(context_lines)

        # Type check in condition: if (is_int($var)) { ...use $var... }
        type_guard = bool(re.search(
            rf'(?:is_int|is_numeric|is_float|is_bool|ctype_digit)\s*\(\s*{var_name}\s*\)',
            context_text
        ))

        # Cast before use: $var = (int)$var; or $var = intval($input);
        type_cast = bool(re.search(
            rf'{var_name}\s*=\s*(?:\(int\)|\(float\)|\(bool\)|\(integer\)|intval\s*\(|floatval\s*\(|boolval\s*\(|abs\s*\()',
            context_text
        ))

        # settype($var, 'integer')
        settype = bool(re.search(
            rf'settype\s*\(\s*{var_name}\s*,\s*[\'"](?:int|integer|float|bool|boolean)[\'"]',
            context_text
        ))

        return type_guard or type_cast or settype

    def _count_aliases(self, context_text: str, code_line: str) -> int:
        """Count PHP reference aliases for variables in the code line.

        Detects: $b = &$a patterns. More aliases = harder to track taint.
        """
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return 0
        var_name = re.escape(var_match.group(0))
        # Count reference assignments involving this variable
        refs = re.findall(rf'=\s*&\s*{var_name}\b', context_text)
        refs += re.findall(rf'{var_name}\s*=\s*&\s*\$\w+', context_text)
        return len(refs)

    def _detect_interproc_flow(self, context_lines: List[str],
                                code_line: str, line_num: int,
                                ctx_start: int) -> bool:
        """Detect if taint flows through a function call to reach the sink.

        Pattern: $result = custom_func($_GET['x']); ... query($result);
        The variable in the sink comes from a custom function return value.
        """
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))

        finding_idx = line_num - ctx_start - 1
        for line in context_lines[:finding_idx]:
            # $var = someFunction($input)
            if re.search(
                rf'{var_name}\s*=\s*\w+\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)',
                line
            ):
                return True
            # $var = someFunction($other_var)
            if re.search(rf'{var_name}\s*=\s*(?!(?:intval|htmlspecialchars|escapeshellarg|addslashes|strip_tags|basename|filter_var|floatval|abs)\b)\w+\s*\(\s*\$\w+', line):
                return True
        return False

    def _detect_interproc_sanitizer(self, context_lines: List[str],
                                     code_line: str) -> bool:
        """Detect if the tainted variable was sanitized through a custom function.

        Pattern: $clean = sanitize_input($dirty); ... query($clean);
        The custom function name contains sanitize/clean/escape/filter/safe.
        """
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = re.escape(var_match.group(0))
        context_text = '\n'.join(context_lines)

        return bool(re.search(
            rf'{var_name}\s*=\s*\w*(?:sanitize|clean|escape|filter|safe|protect|purify|validate|secure)\w*\s*\(',
            context_text, re.IGNORECASE
        ))

    def _detect_framework_validation(self, context_text: str,
                                      code_line: str) -> bool:
        """Detect if Laravel/Symfony/etc validation is applied to the input.

        Patterns:
        - $request->validate([...])
        - Validator::make(...)
        - $this->validate($request, [...])
        - $form->isValid()
        """
        validation_patterns = [
            r'\$request->validate\s*\(',
            r'Validator::make\s*\(',
            r'->validate\s*\(\s*\$request',
            r'->isValid\s*\(\s*\)',
            r'\$validated\s*=\s*\$request->validated\(',
            r'->validateWithBag\s*\(',
            r'FormRequest',
            r'@validated',
        ]
        return any(re.search(p, context_text) for p in validation_patterns)

    def _check_var_reassigned(self, context_lines: List[str], code_line: str,
                              line_num: int, ctx_start: int) -> bool:
        """Check if the variable in the finding was reassigned (potentially sanitized)."""
        # Extract variable from code line
        var_match = re.search(r'\$(\w+)', code_line)
        if not var_match:
            return False
        var_name = var_match.group(0)

        # Look for assignment to this variable before the finding line
        finding_idx = line_num - ctx_start - 1
        for i, line in enumerate(context_lines[:finding_idx]):
            if re.search(rf'{re.escape(var_name)}\s*=', line):
                return True
        return False


# =========================================================================
# Heuristic Classifier (no training needed)
# =========================================================================

class HeuristicClassifier:
    """
    Rule-based FP classifier using weighted feature scoring.
    Works instantly without training data.

    Score > 0.5 = likely true positive
    Score <= 0.5 = likely false positive
    """

    # Feature weights (positive = increases TP likelihood)
    WEIGHTS = {
        # High-impact features
        'source_risk': 0.25,          # Higher source risk → more likely TP
        'sink_danger': 0.20,          # Higher sink danger → more likely TP
        'rule_confidence': 0.15,      # Higher rule confidence → more likely TP

        # Strong FP indicators (negative weight)
        'sanitizer_type_match': -0.55,  # Matching sanitizer → very strong FP signal
        'prepared_stmt_nearby': -0.30,  # Prepared statement → very likely FP for SQL
        'type_cast_nearby': -0.25,      # Type cast → likely FP
        'validation_nearby': -0.15,     # Validation → moderately FP

        # Moderate indicators
        'sanitizer_present': -0.10,     # Any sanitizer → slight FP signal
        'in_comment': -0.50,            # Comment → definitely FP
        'auth_check_nearby': -0.05,     # Auth check → slight FP signal
        'orm_detected': -0.25,          # ORM → likely FP for SQL

        # Context modifiers
        'has_direct_source': 0.10,      # Direct source → more likely TP
        'uses_string_concat': 0.05,     # String concat in query → TP signal
        'uses_interpolation': 0.05,     # Interpolation → TP signal
        'var_reassigned': -0.08,        # Reassigned var → might be sanitized
        'is_ajax_handler': 0.05,        # AJAX handlers → slightly more risky

        # v4.0 features
        'ssa_branch_sanitized': -0.15,  # Sanitized in one branch → weaker FP signal
        'string_context_safe': -0.25,   # Tainted part in safe position → FP
        'string_tainted_ratio': 0.15,   # Higher ratio → more dangerous → TP
        'type_narrowed_safe': -0.35,    # Type narrowed to INT → strong FP
        'alias_count': 0.05,            # More aliases → harder to track → TP
        'interproc_flow_to_sink': 0.10, # Cross-function taint → TP
        'interproc_sanitized': -0.25,   # Custom sanitizer wrapper → FP
        'framework_validated': -0.30,   # Framework validation → strong FP
    }

    # Base scores by vulnerability type (some types have higher TP rates)
    VULN_TYPE_BASE = {
        'Code Injection': 0.60,          # eval() findings are usually real
        'Remote Code Execution': 0.60,
        'Command Injection': 0.55,
        'SQL Injection': 0.45,           # Many SQL FPs from safe patterns
        'Insecure Deserialization': 0.60,
        'File Inclusion': 0.55,
        'Arbitrary File Write': 0.55,
        'Arbitrary File Read': 0.50,
        'Cross-Site Scripting': 0.40,    # Many XSS FPs
        'Path Traversal': 0.45,
        'Server-Side Request Forgery': 0.45,
        'Open Redirect': 0.40,
        'Type Juggling': 0.45,
        'Weak Cryptography': 0.55,       # Usually real if detected
        'Hardcoded Credentials': 0.50,
        'Information Disclosure': 0.35,
        'Authentication Bypass': 0.55,
        'Insecure Direct Object Reference': 0.40,
        'XML External Entity': 0.55,
        'LDAP Injection': 0.50,
        # New v3.0 types
        'HTTP Header Injection': 0.50,
        'Mass Assignment': 0.55,         # extract($_POST) is usually real
        'Insecure Randomness': 0.50,
        'Race Condition': 0.40,          # High FP rate in practice
        'Log Injection': 0.40,           # Many benign logging patterns
        'Regular Expression DoS': 0.45,
        'Cross-Site Request Forgery': 0.35,  # Very high FP rate
        'Unsafe File Upload': 0.50,
        'Template Injection': 0.55,
    }

    # CMS_SAFE_PATTERNS used from module level

    def predict(self, features: FeatureVector) -> Tuple[bool, float, str]:
        """
        Predict if finding is TP or FP.

        Returns:
            (is_true_positive, confidence, reasoning)
        """
        # Start with base score for vuln type
        score = self.VULN_TYPE_BASE.get(features.vuln_type, 0.45)
        reasons = []

        # Apply weighted features
        if features.in_comment:
            score += self.WEIGHTS['in_comment']
            reasons.append("in comment")

        if features.sanitizer_type_match:
            score += self.WEIGHTS['sanitizer_type_match']
            reasons.append(f"matching sanitizer found")

        if features.prepared_stmt_nearby and features.vuln_type in (
            'SQL Injection', 'LDAP Injection'
        ):
            score += self.WEIGHTS['prepared_stmt_nearby']
            reasons.append("prepared statement nearby")

        if features.type_cast_nearby:
            score += self.WEIGHTS['type_cast_nearby']
            reasons.append("type cast nearby")

        if features.validation_nearby:
            score += self.WEIGHTS['validation_nearby']
            reasons.append("validation found")

        if features.sanitizer_present and not features.sanitizer_type_match:
            score += self.WEIGHTS['sanitizer_present']
            reasons.append("generic sanitizer nearby")

        if features.orm_detected and features.vuln_type == 'SQL Injection':
            score += self.WEIGHTS['orm_detected']
            reasons.append("ORM detected")

        if features.auth_check_nearby:
            score += self.WEIGHTS['auth_check_nearby']
            reasons.append("auth check nearby")

        # Positive signals
        score += features.source_risk * self.WEIGHTS['source_risk']
        score += features.sink_danger * self.WEIGHTS['sink_danger']
        score += features.rule_confidence * self.WEIGHTS['rule_confidence']

        if features.has_direct_source:
            score += self.WEIGHTS['has_direct_source']
            reasons.append("direct user input in sink")

        if features.uses_string_concat:
            score += self.WEIGHTS['uses_string_concat']

        if features.uses_interpolation:
            score += self.WEIGHTS['uses_interpolation']

        if features.var_reassigned:
            score += self.WEIGHTS['var_reassigned']

        if features.is_ajax_handler:
            score += self.WEIGHTS['is_ajax_handler']

        # Sanitizer distance modifier (closer = stronger FP signal)
        if features.sanitizer_present and features.sanitizer_distance < 5:
            score -= 0.15  # Extremely close sanitizer
            reasons.append("sanitizer very close")
        elif features.sanitizer_present and features.sanitizer_distance < 10:
            score -= 0.10  # Very close sanitizer

        # Framework-specific safety bonus
        if features.framework_detected:
            score -= 0.05  # Frameworks generally safer
            if features.framework_detected in ('laravel', 'symfony') and features.orm_detected:
                score -= 0.10  # Modern framework with ORM = very likely safe SQL
                reasons.append(f"{features.framework_detected} ORM")

        # CMS safe pattern bonus
        if features.cms_safe_pattern:
            score -= 0.20  # CMS framework protection detected
            reasons.append("CMS safe pattern")

        # --- v4.0 feature scoring ---
        if features.ssa_branch_sanitized:
            score += self.WEIGHTS['ssa_branch_sanitized']
            reasons.append("branch-sanitized variable")

        if features.string_context_safe:
            score += self.WEIGHTS['string_context_safe']
            reasons.append("tainted data in safe string position")

        if features.string_tainted_ratio > 0:
            score += features.string_tainted_ratio * self.WEIGHTS['string_tainted_ratio']

        if features.type_narrowed_safe:
            score += self.WEIGHTS['type_narrowed_safe']
            reasons.append("type narrowed to safe type")

        if features.alias_count > 0:
            score += min(features.alias_count, 3) * self.WEIGHTS['alias_count']
            reasons.append(f"{features.alias_count} alias(es)")

        if features.interproc_flow_to_sink:
            score += self.WEIGHTS['interproc_flow_to_sink']
            reasons.append("cross-function taint flow")

        if features.interproc_sanitized:
            score += self.WEIGHTS['interproc_sanitized']
            reasons.append("custom sanitizer function")

        if features.framework_validated:
            score += self.WEIGHTS['framework_validated']
            reasons.append("framework validation applied")

        # Clamp score to [0, 1]
        score = max(0.0, min(1.0, score))

        is_tp = score > 0.45  # Slightly below 0.5 threshold to be conservative
        confidence = abs(score - 0.45) * 2  # Distance from threshold as confidence
        confidence = min(1.0, confidence)

        reason_str = "; ".join(reasons) if reasons else "baseline score"
        return is_tp, confidence, reason_str


# =========================================================================
# ML Classifier (trained model)
# =========================================================================

class MLClassifier:
    """
    Machine learning FP classifier using GradientBoosting.
    Requires training data. Falls back to heuristic if no model.
    """

    MODEL_FILE = "apex_fp_classifier_v4.pkl"

    def __init__(self, model_dir: str = None):
        self.model = None
        self.feature_names = None
        self.model_dir = model_dir or str(Path(__file__).parent.parent / "models")
        self._load_model()

    def _load_model(self):
        """Load trained model if available."""
        model_path = os.path.join(self.model_dir, self.MODEL_FILE)
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data.get('model')
                self.feature_names = data.get('feature_names')
            except Exception:
                self.model = None

    def is_trained(self) -> bool:
        return self.model is not None

    def predict(self, features: FeatureVector) -> Tuple[bool, float]:
        """Predict TP/FP using trained model with 3-class thresholds.

        Returns (is_tp, probability) where:
        - prob < 0.30 → SAFE (confident FP)
        - 0.30 <= prob < 0.55 → SUSPICIOUS (borderline, keep but lower confidence)
        - prob >= 0.55 → VULNERABLE (confident TP)
        """
        if not self.is_trained():
            raise RuntimeError("No trained model available")

        fv = features.to_numeric_array()
        import numpy as np
        X = np.array([fv])
        prob = self.model.predict_proba(X)[0][1]  # Probability of TP

        # 3-class decision thresholds:
        # - Below 0.30: confident FP → eliminate
        # - 0.30-0.55: suspicious → keep but flag as uncertain
        # - Above 0.55: confident TP → keep
        # This reduces the "cry wolf" tendency by raising the TP threshold
        return prob >= 0.30, prob

    def train(self, features_list: List[FeatureVector],
              labels: List[bool], verbose: bool = False) -> Dict:
        """
        Train the classifier on labeled data.

        Args:
            features_list: List of feature vectors
            labels: List of bool (True = TP, False = FP)
            verbose: Print training info

        Returns:
            Dict with training metrics
        """
        try:
            import numpy as np
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.model_selection import cross_val_score
        except ImportError:
            raise RuntimeError(
                "scikit-learn required for ML training.\n"
                "Install: pip install scikit-learn numpy"
            )

        X = np.array([f.to_numeric_array() for f in features_list])
        y = np.array([1 if l else 0 for l in labels])

        if verbose:
            print(f"[ML] Training on {len(X)} samples "
                  f"({sum(y)} TP, {len(y) - sum(y)} FP)")

        # Train GradientBoosting
        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            min_samples_leaf=3,
            random_state=42,
        )

        # Cross-validation if enough data
        metrics = {}
        if len(X) >= 20:
            cv_scores = cross_val_score(model, X, y, cv=min(5, len(X) // 4))
            metrics['cv_accuracy'] = float(np.mean(cv_scores))
            metrics['cv_std'] = float(np.std(cv_scores))
            if verbose:
                print(f"[ML] CV Accuracy: {metrics['cv_accuracy']:.1%} "
                      f"(+/- {metrics['cv_std']:.1%})")

        # Train on full data
        model.fit(X, y)
        self.model = model
        self.feature_names = list(FeatureVector().to_dict().keys())
        self.feature_names.remove('vuln_type')

        # Feature importance
        if verbose:
            importances = model.feature_importances_
            sorted_idx = np.argsort(importances)[::-1]
            print(f"[ML] Top features:")
            for i in sorted_idx[:10]:
                print(f"      {self.feature_names[i]}: {importances[i]:.3f}")

        metrics['n_samples'] = len(X)
        metrics['n_tp'] = int(sum(y))
        metrics['n_fp'] = int(len(y) - sum(y))

        # Save model
        os.makedirs(self.model_dir, exist_ok=True)
        model_path = os.path.join(self.model_dir, self.MODEL_FILE)
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': model,
                'feature_names': self.feature_names,
                'metrics': metrics,
            }, f)
        if verbose:
            print(f"[ML] Model saved to {model_path}")

        return metrics


# =========================================================================
# Training Data Generator
# =========================================================================

class TrainingDataGenerator:
    """Generate labeled training data from PHP code samples."""

    def __init__(self):
        self.extractor = FeatureExtractor()

    def from_fixture_dir(self, fixture_dir: str) -> Tuple[List[FeatureVector], List[bool]]:
        """
        Generate training data from fixture directory.

        Expects files named:
          vuln_*.php  → findings in these are TRUE positives
          safe_*.php  → findings in these are FALSE positives
        """
        features = []
        labels = []

        fixture_path = Path(fixture_dir)
        if not fixture_path.exists():
            return features, labels

        for php_file in fixture_path.glob('*.php'):
            is_vuln = php_file.name.startswith('vuln_')
            is_safe = php_file.name.startswith('safe_')
            if not (is_vuln or is_safe):
                continue

            code = php_file.read_text(encoding='utf-8', errors='ignore')
            file_lines = code.split('\n')

            # Scan file and label findings
            try:
                from .unified_scanner import UnifiedScanner
            except ImportError:
                from core.unified_scanner import UnifiedScanner
            scanner = UnifiedScanner()
            findings = scanner.scan_code(code, str(php_file))

            for f in findings:
                fdict = f.to_dict() if hasattr(f, 'to_dict') else f
                fv = self.extractor.extract(fdict, code, file_lines)
                features.append(fv)
                labels.append(is_vuln)  # True if file is known vulnerable

        return features, labels

    def from_synthetic(self) -> Tuple[List[FeatureVector], List[bool]]:
        """Generate synthetic training examples from common patterns."""
        features = []
        labels = []

        # TRUE POSITIVE patterns
        tp_patterns = [
            # Direct SQL injection - no sanitization
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '85%',
             'code': '$db->query("SELECT * FROM users WHERE id=" . $_GET["id"])',
             'line': 10, 'file': 'handler.php'},
            # Direct XSS
            {'type': 'Cross-Site Scripting', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'echo $_GET["name"];',
             'line': 5, 'file': 'page.php'},
            # eval with user input
            {'type': 'Code Injection', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'eval($_POST["code"]);',
             'line': 15, 'file': 'ajax/exec.php'},
            # Command injection
            {'type': 'Command Injection', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'system("ls " . $_GET["dir"]);',
             'line': 20, 'file': 'admin/tools.php'},
            # File inclusion
            {'type': 'File Inclusion', 'severity': 'HIGH', 'confidence': '80%',
             'code': 'include($_GET["page"] . ".php");',
             'line': 8, 'file': 'index.php'},
            # Unserialize
            {'type': 'Insecure Deserialization', 'severity': 'CRITICAL', 'confidence': '90%',
             'code': 'unserialize($_COOKIE["data"]);',
             'line': 30, 'file': 'session.php'},
            # Type juggling
            {'type': 'Type Juggling', 'severity': 'HIGH', 'confidence': '85%',
             'code': 'if ($hash == $_GET["hash"]) {',
             'line': 12, 'file': 'verify.php'},
            # SSRF
            {'type': 'Server-Side Request Forgery', 'severity': 'HIGH', 'confidence': '75%',
             'code': 'file_get_contents($_POST["url"]);',
             'line': 25, 'file': 'api/fetch.php'},
        ]

        # FALSE POSITIVE patterns
        fp_patterns = [
            # SQL with prepared statement
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': '$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");',
             'line': 10, 'file': 'model.php'},
            # XSS with htmlspecialchars
            {'type': 'Cross-Site Scripting', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': 'echo htmlspecialchars($_GET["name"]);',
             'line': 5, 'file': 'view.php'},
            # SQL with intval
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
             'code': '$db->query("SELECT * FROM posts WHERE id=" . intval($_GET["id"]))',
             'line': 10, 'file': 'post.php'},
            # Command with escapeshellarg
            {'type': 'Command Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': 'exec("find " . escapeshellarg($_GET["path"]));',
             'line': 20, 'file': 'search.php'},
            # In comment
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '70%',
             'code': '// $db->query("SELECT * FROM users WHERE id=$_GET[id]")',
             'line': 5, 'file': 'old.php'},
            # Hardcoded value
            {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '50%',
             'code': '$db->query("SELECT * FROM settings WHERE name=\'site_title\'")',
             'line': 15, 'file': 'config.php'},
            # ORM usage
            {'type': 'SQL Injection', 'severity': 'HIGH', 'confidence': '65%',
             'code': '$user = User::find($request->input("id"));',
             'line': 10, 'file': 'UserController.php'},
            # Validated input
            {'type': 'SQL Injection', 'severity': 'MEDIUM', 'confidence': '55%',
             'code': '$id = filter_var($_GET["id"], FILTER_VALIDATE_INT);',
             'line': 8, 'file': 'handler.php'},
        ]

        for pattern in tp_patterns:
            fv = self.extractor.extract(pattern, pattern['code'])
            features.append(fv)
            labels.append(True)

        for pattern in fp_patterns:
            fv = self.extractor.extract(pattern, pattern['code'])
            features.append(fv)
            labels.append(False)

        return features, labels


# =========================================================================
# Unified FP Classifier (public API)
# =========================================================================

class FPClassifier:
    """
    Main FP classification interface.
    Uses ML model if trained, falls back to heuristic scoring.

    Usage:
        classifier = FPClassifier()
        result = classifier.classify(finding_dict, code)
        if result.is_fp:
            # Skip this finding
    """

    def __init__(self, model_dir: str = None, use_ml: bool = True):
        self.extractor = FeatureExtractor()
        self.heuristic = HeuristicClassifier()
        self.ml = MLClassifier(model_dir) if use_ml else None
        self.stats = {
            'total_classified': 0,
            'true_positives': 0,
            'false_positives': 0,
            'method': 'heuristic',
        }
        if self.ml and self.ml.is_trained():
            self.stats['method'] = 'ml'

    @dataclass
    class Result:
        is_tp: bool
        confidence: float
        reasoning: str
        score: float
        method: str  # 'heuristic' or 'ml'
        classification: str = 'unknown'  # 'safe', 'suspicious', 'vulnerable'

    def classify(self, finding_dict: Dict, code: str = "",
                 file_lines: List[str] = None,
                 analysis: Optional[FileAnalysisResults] = None) -> 'FPClassifier.Result':
        """
        Classify a finding as TP or FP.

        Args:
            finding_dict: Finding dictionary with type, severity, code, line, file
            code: Full file source code
            file_lines: Pre-split file lines (optional, computed from code)
            analysis: Pre-computed v4.0 analysis results for the file

        Returns:
            Result with is_tp, confidence, reasoning
        """
        features = self.extractor.extract(finding_dict, code, file_lines, analysis)

        # Try ML first, fall back to heuristic
        if self.ml and self.ml.is_trained():
            try:
                is_tp, prob = self.ml.predict(features)
                self.stats['total_classified'] += 1
                if is_tp:
                    self.stats['true_positives'] += 1
                else:
                    self.stats['false_positives'] += 1

                # 3-class classification from probability
                if prob < 0.30:
                    classification = 'safe'
                elif prob < 0.55:
                    classification = 'suspicious'
                else:
                    classification = 'vulnerable'

                return self.Result(
                    is_tp=is_tp,
                    confidence=abs(prob - 0.5) * 2,
                    reasoning=f"ML model (prob={prob:.2f}, class={classification})",
                    score=prob,
                    method='ml',
                    classification=classification,
                )
            except Exception:
                pass  # Fall through to heuristic

        # Heuristic fallback
        is_tp, confidence, reasoning = self.heuristic.predict(features)
        self.stats['total_classified'] += 1
        if is_tp:
            self.stats['true_positives'] += 1
        else:
            self.stats['false_positives'] += 1

        # Calculate raw score for debugging
        score = 0.5 + (0.5 if is_tp else -0.5) * confidence

        return self.Result(
            is_tp=is_tp,
            confidence=confidence,
            reasoning=reasoning,
            score=score,
            method='heuristic',
        )

    def classify_batch(self, findings: List[Dict],
                       file_codes: Dict[str, str],
                       file_analyses: Optional[Dict[str, FileAnalysisResults]] = None
                       ) -> List[Dict]:
        """
        Classify a batch of findings. Returns filtered list (TPs only).

        Each finding gets additional fields:
          ml_is_tp, ml_confidence, ml_reasoning, ml_method, ml_score

        Args:
            findings: List of finding dicts
            file_codes: filepath -> source code
            file_analyses: filepath -> FileAnalysisResults (from v4.0 modules)
        """
        results = []
        file_lines_cache = {}
        analysis_cache = {}

        # Build analysis results if not provided but modules available
        if file_analyses is None and _HAS_CFG:
            file_analyses = {}
            re_engine = None
            if get_rule_engine:
                try:
                    re_engine = get_rule_engine()
                except Exception:
                    pass
            for filepath, code in file_codes.items():
                if filepath not in file_analyses and code:
                    try:
                        ar = build_file_analysis(filepath, code, re_engine)
                        if ar:
                            file_analyses[filepath] = ar
                    except Exception:
                        pass

        for f in findings:
            filepath = f.get('file', '')
            code = file_codes.get(filepath, '')

            # Cache file lines
            if filepath not in file_lines_cache:
                file_lines_cache[filepath] = code.split('\n') if code else []

            # Get analysis results for this file
            analysis = file_analyses.get(filepath) if file_analyses else None

            result = self.classify(f, code, file_lines_cache[filepath], analysis)

            f['ml_is_tp'] = result.is_tp
            f['ml_confidence'] = round(result.confidence, 2)
            f['ml_reasoning'] = result.reasoning
            f['ml_method'] = result.method
            f['ml_score'] = round(result.score, 3)
            f['ml_classification'] = result.classification

            if result.is_tp:
                results.append(f)

        return results

    def train_from_fixtures(self, fixture_dir: str = None,
                            verbose: bool = False) -> Dict:
        """Train the ML model from test fixtures + synthetic data."""
        if self.ml is None:
            self.ml = MLClassifier()

        gen = TrainingDataGenerator()

        # Collect training data
        all_features = []
        all_labels = []

        # Synthetic data (always available)
        syn_features, syn_labels = gen.from_synthetic()
        all_features.extend(syn_features)
        all_labels.extend(syn_labels)
        if verbose:
            print(f"[ML] Synthetic: {len(syn_features)} samples")

        # Fixture data (if available)
        if fixture_dir is None:
            fixture_dir = str(Path(__file__).parent.parent / "tests" / "fixtures")

        if os.path.isdir(fixture_dir):
            fix_features, fix_labels = gen.from_fixture_dir(fixture_dir)
            all_features.extend(fix_features)
            all_labels.extend(fix_labels)
            if verbose:
                print(f"[ML] Fixtures: {len(fix_features)} samples")

        if len(all_features) < 10:
            if verbose:
                print(f"[ML] Not enough data ({len(all_features)} samples). "
                      f"Need at least 10.")
            return {'error': 'not enough data'}

        return self.ml.train(all_features, all_labels, verbose=verbose)
