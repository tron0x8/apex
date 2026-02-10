#!/usr/bin/env python3
"""
APEX Cross-File Taint Analysis Engine

Resolves include/require dependencies, tracks global variable state
across files, resolves PSR-4 namespaces, and detects cross-file
taint flows where a tainted variable assigned in one file reaches
a dangerous sink in another.
"""

import os
import re
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional tree-sitter integration
# ---------------------------------------------------------------------------
try:
    from .ts_adapter import TSNode, parse_php_ts
    HAS_TS = True
except ImportError:
    HAS_TS = False

# Optional rule-engine integration (sources / sinks / sanitizers)
try:
    from .rule_engine import get_rule_engine
    HAS_RULES = True
except ImportError:
    HAS_RULES = False

# ---------------------------------------------------------------------------
# Taint-source superglobals recognised by the cross-file engine
# ---------------------------------------------------------------------------
SUPERGLOBAL_SOURCES: Set[str] = {
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
    "$_FILES", "$_SERVER", "$_ENV",
}

# Dangerous sinks (function name -> vuln_type, severity)
DEFAULT_SINKS: Dict[str, Tuple[str, str]] = {
    "mysql_query":          ("SQL Injection",          "CRITICAL"),
    "mysqli_query":         ("SQL Injection",          "CRITICAL"),
    "pg_query":             ("SQL Injection",          "CRITICAL"),
    "sqlite_query":         ("SQL Injection",          "CRITICAL"),
    "exec":                 ("Command Injection",      "CRITICAL"),
    "system":               ("Command Injection",      "CRITICAL"),
    "passthru":             ("Command Injection",      "CRITICAL"),
    "shell_exec":           ("Command Injection",      "CRITICAL"),
    "popen":                ("Command Injection",      "CRITICAL"),
    "proc_open":            ("Command Injection",      "CRITICAL"),
    "eval":                 ("Code Injection",         "CRITICAL"),
    "assert":               ("Code Injection",         "HIGH"),
    "preg_replace":         ("Code Injection",         "HIGH"),
    "include":              ("File Inclusion",         "CRITICAL"),
    "include_once":         ("File Inclusion",         "CRITICAL"),
    "require":              ("File Inclusion",         "CRITICAL"),
    "require_once":         ("File Inclusion",         "CRITICAL"),
    "file_get_contents":    ("SSRF / Path Traversal",  "HIGH"),
    "fopen":                ("Path Traversal",         "HIGH"),
    "readfile":             ("Path Traversal",         "HIGH"),
    "unserialize":          ("Insecure Deserialization","CRITICAL"),
    "header":               ("Open Redirect / Header Injection", "MEDIUM"),
    "echo":                 ("XSS",                    "HIGH"),
    "print":                ("XSS",                    "HIGH"),
    "printf":               ("XSS",                    "HIGH"),
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IncludeEdge:
    """A directed edge in the file-include dependency graph."""
    from_file: str
    to_file: str
    line: int
    include_type: str          # include | require | include_once | require_once
    is_resolved: bool = True


@dataclass
class GlobalVarInfo:
    """A global variable definition discovered in a PHP file."""
    name: str
    file: str
    line: int
    is_tainted: bool = False
    taint_source: Optional[str] = None   # e.g. '$_GET'
    value_pattern: Optional[str] = None  # rhs snippet


@dataclass
class CrossFileFlow:
    """A taint flow that crosses file boundaries."""
    source_file: str
    source_line: int
    source_var: str
    source_type: str           # e.g. '$_GET'
    sink_file: str
    sink_line: int
    sink_code: str
    vuln_type: str
    severity: str
    confidence: float
    flow_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "source_line": self.source_line,
            "source_var": self.source_var,
            "source_type": self.source_type,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_code": self.sink_code,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "flow_path": self.flow_path,
        }


@dataclass
class CrossFileContext:
    """Aggregated result of cross-file analysis."""
    include_graph: Dict[str, Set[str]] = field(
        default_factory=lambda: defaultdict(set))
    reverse_include: Dict[str, Set[str]] = field(
        default_factory=lambda: defaultdict(set))
    global_vars: Dict[str, List[GlobalVarInfo]] = field(
        default_factory=lambda: defaultdict(list))
    namespace_map: Dict[str, str] = field(default_factory=dict)   # FQCN -> path
    cross_file_flows: List[CrossFileFlow] = field(default_factory=list)
    file_codes: Dict[str, str] = field(default_factory=dict)
    include_edges: List[IncludeEdge] = field(default_factory=list)


# =========================================================================
#  IncludeResolver
# =========================================================================

class IncludeResolver:
    """Resolve PHP include / require statements to concrete file paths
    and construct the include dependency graph."""

    # Regex patterns for include/require in PHP source ---
    _INCLUDE_RE = re.compile(
        r"""(?:include|require)(?:_once)?\s*"""
        r"""[\(\s]*"""
        r"""(?:"""
        r"""  (?:dirname\s*\(\s*__FILE__\s*\)|__DIR__)\s*\.\s*"""  # __DIR__ . '...'
        r"""  ['\"]([^'\"]+)['\"]"""
        r"""|"""
        r"""  ['\"]([^'\"]+)['\"]"""                                # plain string
        r""")""",
        re.VERBOSE | re.IGNORECASE,
    )

    _INCLUDE_TYPE_RE = re.compile(
        r"\b(include_once|require_once|include|require)\b", re.IGNORECASE)

    def __init__(self, project_root: str):
        self.project_root = os.path.normpath(project_root)

    # ----- public API -----

    def resolve_file(self, code: str, file_path: str) -> List[IncludeEdge]:
        """Return all include edges found in *code* (which lives at
        *file_path*)."""
        if HAS_TS:
            try:
                return self._resolve_ts(code, file_path)
            except Exception:
                pass
        return self._resolve_regex(code, file_path)

    def build_graph(self, file_codes: Dict[str, str]) -> Tuple[
            Dict[str, Set[str]], Dict[str, Set[str]], List[IncludeEdge]]:
        """Build the full include graph for the project.

        Returns (forward_graph, reverse_graph, edges).
        """
        forward: Dict[str, Set[str]] = defaultdict(set)
        reverse: Dict[str, Set[str]] = defaultdict(set)
        all_edges: List[IncludeEdge] = []

        for fpath, code in file_codes.items():
            edges = self.resolve_file(code, fpath)
            for edge in edges:
                forward[edge.from_file].add(edge.to_file)
                reverse[edge.to_file].add(edge.from_file)
                all_edges.append(edge)

        return forward, reverse, all_edges

    # ----- tree-sitter path -----

    def _resolve_ts(self, code: str, file_path: str) -> List[IncludeEdge]:
        root = parse_php_ts(code)
        edges: List[IncludeEdge] = []
        self._walk_ts(root, file_path, edges)
        return edges

    def _walk_ts(self, node: "TSNode", file_path: str,
                 edges: List[IncludeEdge]) -> None:
        if node.type in ("include_expression", "include_once_expression",
                         "require_expression", "require_once_expression"):
            inc_type = node.type.replace("_expression", "")
            arg = node.named_children[-1] if node.named_children else None
            path_str = self._extract_path_from_ts(arg) if arg else None
            resolved = self._resolve_path(path_str, file_path) if path_str else None
            edges.append(IncludeEdge(
                from_file=os.path.normpath(file_path),
                to_file=resolved or (path_str or "<unresolved>"),
                line=node.line,
                include_type=inc_type,
                is_resolved=resolved is not None,
            ))
        for child in node.children:
            self._walk_ts(child, file_path, edges)

    @staticmethod
    def _extract_path_from_ts(node: "TSNode") -> Optional[str]:
        text = node.text.strip()
        # Strip concatenation with __DIR__ / dirname(__FILE__)
        text = re.sub(
            r"""(?:dirname\s*\(\s*__FILE__\s*\)|__DIR__)\s*\.\s*""",
            "", text, flags=re.IGNORECASE)
        # Remove surrounding quotes
        for q in ("'", '"'):
            if text.startswith(q) and text.endswith(q):
                return text[1:-1]
        # Could be a constant or variable -- not resolvable statically
        return None

    # ----- regex path -----

    def _resolve_regex(self, code: str, file_path: str) -> List[IncludeEdge]:
        edges: List[IncludeEdge] = []
        for lineno, line in enumerate(code.splitlines(), 1):
            m_type = self._INCLUDE_TYPE_RE.search(line)
            if not m_type:
                continue
            inc_type = m_type.group(1).lower()
            m_path = self._INCLUDE_RE.search(line)
            if not m_path:
                continue
            # group(1) = __DIR__-relative, group(2) = plain string
            raw_path = m_path.group(1) or m_path.group(2)
            resolved = self._resolve_path(raw_path, file_path)
            edges.append(IncludeEdge(
                from_file=os.path.normpath(file_path),
                to_file=resolved or raw_path,
                line=lineno,
                include_type=inc_type,
                is_resolved=resolved is not None,
            ))
        return edges

    # ----- path normalisation -----

    def _resolve_path(self, raw: Optional[str],
                      referrer: str) -> Optional[str]:
        """Try to map *raw* (a string found in the PHP source) to an
        existing file on disk.  Returns the normalised absolute path or
        ``None``."""
        if raw is None:
            return None

        # Strip leading path separator that represents the dir-concat
        raw = raw.lstrip("/\\")

        candidates = [
            os.path.join(os.path.dirname(referrer), raw),
            os.path.join(self.project_root, raw),
        ]
        for c in candidates:
            normed = os.path.normpath(c)
            if os.path.isfile(normed):
                return normed
        return None


# =========================================================================
#  GlobalStateTracker
# =========================================================================

class GlobalStateTracker:
    """Detect global variable assignments and superglobal usage across
    PHP source files.  Determines which variables carry tainted data."""

    # $GLOBALS['key'] = <expr>
    _GLOBALS_RE = re.compile(
        r"""\$GLOBALS\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*(.+?)\s*;""",
        re.IGNORECASE)

    # global $var1, $var2;
    _GLOBAL_DECL_RE = re.compile(
        r"""\bglobal\s+((?:\$\w+\s*,\s*)*\$\w+)\s*;""", re.IGNORECASE)

    # $var = $_GET[...] etc.
    _SUPERGLOBAL_ASSIGN_RE = re.compile(
        r"""(\$\w+)\s*=\s*(\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)"""
        r"""(?:\s*\[.*?\])?)\s*;""",
        re.IGNORECASE)

    # Detect superglobal on RHS of any assignment (broader)
    _TAINT_RHS_RE = re.compile(
        r"""(\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV))""",
        re.IGNORECASE)

    def track_file(self, code: str, file_path: str) -> List[GlobalVarInfo]:
        """Extract global variable information from a single file."""
        if HAS_TS:
            try:
                return self._track_ts(code, file_path)
            except Exception:
                pass
        return self._track_regex(code, file_path)

    # ----- tree-sitter path -----

    def _track_ts(self, code: str, file_path: str) -> List[GlobalVarInfo]:
        root = parse_php_ts(code)
        infos: List[GlobalVarInfo] = []
        self._walk_ts(root, file_path, infos, code)
        return infos

    def _walk_ts(self, node: "TSNode", file_path: str,
                 infos: List[GlobalVarInfo], code: str) -> None:
        # global $var declarations
        if node.type == "global_declaration":
            for child in node.named_children:
                var_name = child.text if hasattr(child, "text") else ""
                if var_name.startswith("$"):
                    infos.append(GlobalVarInfo(
                        name=var_name, file=file_path, line=node.line))

        # assignment_expression: look for $GLOBALS or superglobal RHS
        if node.type == "assignment_expression":
            lhs = node.child_by_field("left")
            rhs = node.child_by_field("right")
            if lhs and rhs:
                lhs_text = lhs.text
                rhs_text = rhs.text
                # $GLOBALS['key'] assignment
                m = re.match(r"""\$GLOBALS\s*\[\s*['\"](\w+)['"]\s*\]""",
                             lhs_text, re.IGNORECASE)
                if m:
                    var_name = "$" + m.group(1)
                    is_tainted, src = self._rhs_tainted(rhs_text)
                    infos.append(GlobalVarInfo(
                        name=var_name, file=file_path, line=node.line,
                        is_tainted=is_tainted, taint_source=src,
                        value_pattern=rhs_text[:120]))

                # $var = $_GET[...]
                elif lhs_text.startswith("$"):
                    is_tainted, src = self._rhs_tainted(rhs_text)
                    if is_tainted:
                        infos.append(GlobalVarInfo(
                            name=lhs_text, file=file_path, line=node.line,
                            is_tainted=True, taint_source=src,
                            value_pattern=rhs_text[:120]))

        for child in node.children:
            self._walk_ts(child, file_path, infos, code)

    # ----- regex path -----

    def _track_regex(self, code: str, file_path: str) -> List[GlobalVarInfo]:
        infos: List[GlobalVarInfo] = []
        lines = code.splitlines()

        for lineno, line in enumerate(lines, 1):
            # global $var declarations
            m = self._GLOBAL_DECL_RE.search(line)
            if m:
                for var in re.findall(r"\$\w+", m.group(1)):
                    infos.append(GlobalVarInfo(
                        name=var, file=file_path, line=lineno))

            # $GLOBALS['key'] = ...
            m = self._GLOBALS_RE.search(line)
            if m:
                var_name = "$" + m.group(1)
                rhs = m.group(2)
                is_tainted, src = self._rhs_tainted(rhs)
                infos.append(GlobalVarInfo(
                    name=var_name, file=file_path, line=lineno,
                    is_tainted=is_tainted, taint_source=src,
                    value_pattern=rhs[:120]))

            # $var = $_SUPERGLOBAL[...]
            m = self._SUPERGLOBAL_ASSIGN_RE.search(line)
            if m:
                var_name = m.group(1)
                rhs = m.group(2)
                is_tainted, src = self._rhs_tainted(rhs)
                infos.append(GlobalVarInfo(
                    name=var_name, file=file_path, line=lineno,
                    is_tainted=True, taint_source=src,
                    value_pattern=rhs[:120]))

        return infos

    # ----- helpers -----

    @staticmethod
    def _rhs_tainted(rhs: str) -> Tuple[bool, Optional[str]]:
        for sg in SUPERGLOBAL_SOURCES:
            if sg in rhs:
                return True, sg
        return False, None


# =========================================================================
#  NamespaceResolver  (PSR-4 autoloading)
# =========================================================================

class NamespaceResolver:
    """Parse composer.json for PSR-4 mappings and resolve fully-qualified
    class names to file paths.  Also resolves ``use`` statements."""

    def __init__(self, project_root: str):
        self.project_root = os.path.normpath(project_root)
        self.psr4_map: Dict[str, str] = {}   # namespace prefix -> directory
        self._load_composer()

    # ----- composer.json -----

    def _load_composer(self) -> None:
        composer_path = os.path.join(self.project_root, "composer.json")
        if not os.path.isfile(composer_path):
            return
        try:
            with open(composer_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return

        autoload = data.get("autoload", {})
        psr4 = autoload.get("psr-4", {})
        for prefix, path_val in psr4.items():
            # path_val can be a string or list of strings
            dirs = [path_val] if isinstance(path_val, str) else path_val
            for d in dirs:
                abs_dir = os.path.normpath(
                    os.path.join(self.project_root, d))
                self.psr4_map[prefix] = abs_dir

        # Also check autoload-dev
        autoload_dev = data.get("autoload-dev", {})
        psr4_dev = autoload_dev.get("psr-4", {})
        for prefix, path_val in psr4_dev.items():
            dirs = [path_val] if isinstance(path_val, str) else path_val
            for d in dirs:
                abs_dir = os.path.normpath(
                    os.path.join(self.project_root, d))
                self.psr4_map.setdefault(prefix, abs_dir)

    # ----- public API -----

    def resolve_class(self, fqcn: str) -> Optional[str]:
        """Resolve a fully-qualified class name (e.g. ``App\\User\\Repo``)
        to an absolute file path using PSR-4 rules.

        Returns *None* if no mapping matches or the file does not exist.
        """
        # Normalise to forward-slash for matching, but keep backslash
        normalised = fqcn.replace("/", "\\")
        # Try longest prefix first (most specific wins)
        for prefix in sorted(self.psr4_map, key=len, reverse=True):
            if normalised.startswith(prefix):
                relative = normalised[len(prefix):]
                rel_path = relative.replace("\\", os.sep) + ".php"
                full_path = os.path.join(self.psr4_map[prefix], rel_path)
                full_path = os.path.normpath(full_path)
                if os.path.isfile(full_path):
                    return full_path
        return None

    def build_namespace_map(self, php_files: List[str]) -> Dict[str, str]:
        """Scan *php_files* for ``namespace`` and ``class`` declarations
        and map every FQCN to its file path."""
        ns_map: Dict[str, str] = {}
        ns_re = re.compile(r"^\s*namespace\s+([\w\\]+)\s*;", re.MULTILINE)
        cls_re = re.compile(
            r"^\s*(?:abstract\s+|final\s+)?class\s+(\w+)", re.MULTILINE)

        for fpath in php_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read(64_000)    # first 64 KB is enough
            except OSError:
                continue

            ns_match = ns_re.search(code)
            namespace = ns_match.group(1) if ns_match else ""

            for cm in cls_re.finditer(code):
                class_name = cm.group(1)
                fqcn = (namespace + "\\" + class_name) if namespace else class_name
                ns_map[fqcn] = os.path.normpath(fpath)

        return ns_map

    def resolve_use_statements(self, code: str) -> Dict[str, str]:
        """Parse ``use`` statements and return {alias -> FQCN}."""
        use_re = re.compile(
            r"^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", re.MULTILINE)
        result: Dict[str, str] = {}
        for m in use_re.finditer(code):
            fqcn = m.group(1)
            alias = m.group(2) or fqcn.rsplit("\\", 1)[-1]
            result[alias] = fqcn
        return result


# =========================================================================
#  CrossFileAnalyzer  -- main entry point
# =========================================================================

class CrossFileAnalyzer:
    """Coordinate include resolution, global-state tracking, namespace
    resolution, and cross-file taint detection for a PHP project."""

    # Regex to detect sink calls (used in cross-file taint detection)
    _SINK_CALL_RE = re.compile(
        r"""\b("""
        + "|".join(re.escape(s) for s in DEFAULT_SINKS)
        + r""")\s*\(""",
        re.IGNORECASE,
    )

    def __init__(self, project_root: str):
        self.project_root = os.path.normpath(project_root)
        self.include_resolver = IncludeResolver(project_root)
        self.global_tracker = GlobalStateTracker()
        self.namespace_resolver = NamespaceResolver(project_root)

    # ------------------------------------------------------------------ #
    #  Public interface                                                    #
    # ------------------------------------------------------------------ #

    def analyze_project(self, project_root: Optional[str] = None,
                        php_files: Optional[List[str]] = None
                        ) -> CrossFileContext:
        """Run full cross-file analysis and return a
        :class:`CrossFileContext`."""
        root = os.path.normpath(project_root or self.project_root)
        ctx = CrossFileContext()

        # 1. Read all files
        if php_files is None:
            php_files = self._discover_php_files(root)

        for fpath in php_files:
            try:
                with open(fpath, "r", encoding="utf-8",
                          errors="replace") as fh:
                    ctx.file_codes[os.path.normpath(fpath)] = fh.read()
            except OSError:
                logger.debug("Could not read %s", fpath)

        # 2. Build include graph
        fwd, rev, edges = self.include_resolver.build_graph(ctx.file_codes)
        ctx.include_graph = fwd
        ctx.reverse_include = rev
        ctx.include_edges = edges

        # 3. Track global state per file
        for fpath, code in ctx.file_codes.items():
            for info in self.global_tracker.track_file(code, fpath):
                ctx.global_vars[info.name].append(info)

        # 4. Namespace map
        ns_from_scan = self.namespace_resolver.build_namespace_map(
            list(ctx.file_codes.keys()))
        ctx.namespace_map.update(ns_from_scan)

        # 5. Detect cross-file taint flows
        ctx.cross_file_flows = self._detect_cross_file_flows(ctx)

        return ctx

    # ------------------------------------------------------------------ #
    #  Cross-file taint detection                                          #
    # ------------------------------------------------------------------ #

    def _detect_cross_file_flows(self,
                                 ctx: CrossFileContext) -> List[CrossFileFlow]:
        """For every tainted global variable in file A, check whether any
        file that transitively includes A uses that variable in a
        dangerous sink."""
        flows: List[CrossFileFlow] = []

        # Collect tainted vars: var_name -> list of GlobalVarInfo
        tainted_vars: Dict[str, List[GlobalVarInfo]] = defaultdict(list)
        for var_name, info_list in ctx.global_vars.items():
            for info in info_list:
                if info.is_tainted:
                    tainted_vars[var_name].append(info)

        if not tainted_vars:
            return flows

        # For each tainted variable, find files that can see it
        for var_name, sources in tainted_vars.items():
            for src_info in sources:
                reachable = self._files_that_include(
                    src_info.file, ctx.include_graph, ctx.reverse_include)

                for target_file in reachable:
                    if target_file == src_info.file:
                        continue
                    target_code = ctx.file_codes.get(target_file, "")
                    hits = self._find_var_in_sinks(
                        var_name, target_code, target_file)
                    for sink_line, sink_code, vuln_type, severity in hits:
                        flow_path = self._build_flow_path(
                            src_info.file, target_file, ctx.include_graph)
                        confidence = self._compute_confidence(
                            src_info, target_file, flow_path, ctx)
                        flows.append(CrossFileFlow(
                            source_file=src_info.file,
                            source_line=src_info.line,
                            source_var=var_name,
                            source_type=src_info.taint_source or "unknown",
                            sink_file=target_file,
                            sink_line=sink_line,
                            sink_code=sink_code.strip()[:200],
                            vuln_type=vuln_type,
                            severity=severity,
                            confidence=confidence,
                            flow_path=flow_path,
                        ))
        return flows

    def _find_var_in_sinks(
        self, var_name: str, code: str, file_path: str
    ) -> List[Tuple[int, str, str, str]]:
        """Return list of (line, code_snippet, vuln_type, severity) where
        *var_name* appears inside a dangerous sink call."""
        results: List[Tuple[int, str, str, str]] = []
        # Escape the dollar sign for regex
        var_pattern = re.escape(var_name)

        for lineno, line in enumerate(code.splitlines(), 1):
            sink_m = self._SINK_CALL_RE.search(line)
            if not sink_m:
                continue
            func_name = sink_m.group(1).lower()
            # Check if our tainted variable appears in the argument area
            # (everything after the opening parenthesis on the same line)
            after_paren = line[sink_m.end() - 1:]  # include the '('
            if re.search(var_pattern, after_paren):
                vuln_type, severity = DEFAULT_SINKS.get(
                    func_name, ("Unknown", "MEDIUM"))
                results.append((lineno, line, vuln_type, severity))

        return results

    def _files_that_include(
        self, source_file: str,
        forward: Dict[str, Set[str]],
        reverse: Dict[str, Set[str]],
    ) -> Set[str]:
        """Return every file that has *source_file* in its transitive
        include closure -- i.e. files that directly or indirectly include
        *source_file* and therefore can see its global variables.

        Also includes files that *source_file* itself includes (a global
        set in config.php is visible in any file that requires config.php).
        """
        reachable: Set[str] = set()
        # BFS over reverse edges (who includes source_file?)
        queue: deque[str] = deque([source_file])
        visited: Set[str] = {source_file}
        while queue:
            current = queue.popleft()
            for parent in reverse.get(current, set()):
                if parent not in visited:
                    visited.add(parent)
                    reachable.add(parent)
                    queue.append(parent)

        # Also BFS forward: files included *by* source_file can have
        # their variables overwritten, but more importantly the including
        # file can use them in sinks.
        queue = deque([source_file])
        fwd_visited: Set[str] = {source_file}
        while queue:
            current = queue.popleft()
            for child in forward.get(current, set()):
                if child not in fwd_visited:
                    fwd_visited.add(child)
                    reachable.add(child)
                    queue.append(child)

        return reachable

    def _build_flow_path(
        self, source_file: str, sink_file: str,
        forward: Dict[str, Set[str]],
    ) -> List[str]:
        """BFS to find the shortest include-chain from *source_file* to
        *sink_file*.  Returns the path as a list of file paths (including
        both endpoints)."""
        if source_file == sink_file:
            return [source_file]

        # Try forward direction first
        path = self._bfs_path(source_file, sink_file, forward)
        if path:
            return path

        # Try reverse (sink includes source)
        reverse_adj: Dict[str, Set[str]] = defaultdict(set)
        for k, vs in forward.items():
            for v in vs:
                reverse_adj[v].add(k)
        path = self._bfs_path(source_file, sink_file, reverse_adj)
        return path or [source_file, "...", sink_file]

    @staticmethod
    def _bfs_path(start: str, goal: str,
                  adj: Dict[str, Set[str]]) -> List[str]:
        queue: deque[List[str]] = deque([[start]])
        visited: Set[str] = {start}
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == goal:
                return path
            for neighbour in adj.get(node, set()):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(path + [neighbour])
        return []

    @staticmethod
    def _compute_confidence(
        src_info: GlobalVarInfo,
        sink_file: str,
        flow_path: List[str],
        ctx: CrossFileContext,
    ) -> float:
        """Heuristic confidence score for a cross-file flow (0.0 -- 1.0)."""
        score = 0.70

        # Higher confidence if taint source is a primary superglobal
        if src_info.taint_source in ("$_GET", "$_POST", "$_REQUEST"):
            score += 0.15
        elif src_info.taint_source in ("$_COOKIE", "$_FILES"):
            score += 0.10

        # Shorter include chains are more credible
        if len(flow_path) <= 2:
            score += 0.10
        elif len(flow_path) <= 4:
            score += 0.05

        # Penalise if the include edge is unresolved
        unresolved_in_path = any(
            not e.is_resolved
            for e in ctx.include_edges
            if e.from_file in flow_path and e.to_file in flow_path
        )
        if unresolved_in_path:
            score -= 0.20

        return round(max(0.10, min(1.0, score)), 2)

    # ------------------------------------------------------------------ #
    #  Utilities                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _discover_php_files(root: str) -> List[str]:
        """Recursively find all .php files under *root*, skipping
        vendor / node_modules directories."""
        skip = {"vendor", "node_modules", ".git", "__pycache__"}
        php_files: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if fn.endswith(".php"):
                    php_files.append(
                        os.path.normpath(os.path.join(dirpath, fn)))
        return php_files
