#!/usr/bin/env python3
"""
APEX String Domain Analysis Module

Tracks string construction through assignments and concatenation to reduce
false positives in taint analysis of dynamic queries. Works alongside the
abstract interpreter (core.abstract_interp) by providing fine-grained
positional taint information within constructed strings.

Instead of treating an entire concatenated string as tainted when any part
is tainted, this module tracks exactly which fragments are literal and which
carry taint. This enables context-aware sink checking -- for example,
distinguishing between a tainted value in a SQL WHERE clause (dangerous)
versus a tainted value used as a table name prefix (less dangerous).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re

from .ts_adapter import TSNode
from .rule_engine import get_rule_engine, RuleEngine


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class StringFragment:
    """
    A single fragment within a composite string value.

    Attributes:
        value:       The literal text content of this fragment, or None if
                     the concrete value is unknown (e.g. user input).
        tainted:     Whether this fragment carries taint.
        taint_types: Set of vulnerability categories this taint applies to
                     (e.g. {'SQL', 'XSS', 'COMMAND'}).
        source:      Identifier for the taint source (e.g. '$_GET["id"]'),
                     or None for untainted / unknown fragments.
    """
    value: Optional[str] = None
    tainted: bool = False
    taint_types: Set[str] = field(default_factory=set)
    source: Optional[str] = None

    def copy(self) -> "StringFragment":
        return StringFragment(
            value=self.value,
            tainted=self.tainted,
            taint_types=set(self.taint_types),
            source=self.source,
        )


# ---------------------------------------------------------------------------
# StringValue -- ordered sequence of fragments
# ---------------------------------------------------------------------------

class StringValue:
    """
    Represents a string that may be built from a mix of literal text and
    tainted (or unknown) segments.  The ordering of fragments reflects the
    left-to-right construction of the string via concatenation or
    interpolation.
    """

    def __init__(self, fragments: Optional[List[StringFragment]] = None):
        self.fragments: List[StringFragment] = fragments if fragments is not None else []

    # -- Query helpers -------------------------------------------------------

    def is_fully_literal(self) -> bool:
        """Return True if every fragment has a known literal value and none
        is tainted.  A fully-literal string poses no injection risk."""
        if not self.fragments:
            return True
        return all(f.value is not None and not f.tainted for f in self.fragments)

    def has_tainted_fragment(self) -> bool:
        """Return True if at least one fragment is tainted."""
        return any(f.tainted for f in self.fragments)

    def get_tainted_positions(self) -> List[int]:
        """Return the indices of all tainted fragments."""
        return [i for i, f in enumerate(self.fragments) if f.tainted]

    def get_literal_text(self) -> str:
        """Best-effort reconstruction of the literal portions of the string.
        Unknown fragments are replaced with a placeholder."""
        parts: List[str] = []
        for frag in self.fragments:
            if frag.value is not None:
                parts.append(frag.value)
            else:
                parts.append("{?}")
        return "".join(parts)

    def get_all_taint_types(self) -> Set[str]:
        """Collect taint types across every tainted fragment."""
        types: Set[str] = set()
        for frag in self.fragments:
            if frag.tainted:
                types |= frag.taint_types
        return types

    def get_all_sources(self) -> Set[str]:
        """Collect source identifiers from all tainted fragments."""
        sources: Set[str] = set()
        for frag in self.fragments:
            if frag.tainted and frag.source:
                sources.add(frag.source)
        return sources

    # -- Composition ---------------------------------------------------------

    def concat(self, other: "StringValue") -> "StringValue":
        """Return a new StringValue that is the concatenation of *self*
        followed by *other*.  Adjacent literal fragments are merged for
        compactness."""
        merged: List[StringFragment] = []
        for frag in self.fragments + other.fragments:
            # Merge consecutive untainted literals to keep the list compact.
            if (merged
                    and not merged[-1].tainted
                    and not frag.tainted
                    and merged[-1].value is not None
                    and frag.value is not None):
                merged[-1] = StringFragment(
                    value=merged[-1].value + frag.value,
                    tainted=False,
                    taint_types=set(),
                    source=None,
                )
            else:
                merged.append(frag.copy())
        return StringValue(merged)

    def interpolate(self, var_map: Dict[str, "StringValue"]) -> "StringValue":
        """Resolve PHP double-quoted string interpolation.

        Scans each literal fragment for ``$varname`` references.  When a
        variable is found in *var_map*, its StringValue replaces the
        reference.  Unknown variables produce a single tainted fragment
        with ``None`` value (conservative assumption).

        Args:
            var_map: Mapping of PHP variable names (including the ``$``
                     prefix) to their current StringValue.

        Returns:
            A new StringValue with interpolations resolved.
        """
        # Pattern to match simple PHP variable interpolation: $var or ${var}
        var_pattern = re.compile(r'\$\{?([a-zA-Z_]\w*)\}?')
        result_fragments: List[StringFragment] = []

        for frag in self.fragments:
            # Only process literal, untainted fragments for interpolation.
            if frag.value is None or frag.tainted:
                result_fragments.append(frag.copy())
                continue

            text = frag.value
            last_end = 0

            for match in var_pattern.finditer(text):
                var_name = "$" + match.group(1)
                start, end = match.start(), match.end()

                # Emit any literal text before this variable reference.
                if start > last_end:
                    result_fragments.append(StringFragment(
                        value=text[last_end:start],
                        tainted=False,
                    ))

                # Substitute the variable's StringValue if known.
                if var_name in var_map:
                    for sub_frag in var_map[var_name].fragments:
                        result_fragments.append(sub_frag.copy())
                else:
                    # Unknown variable -- treat conservatively as tainted.
                    result_fragments.append(StringFragment(
                        value=None,
                        tainted=True,
                        taint_types=set(),
                        source=var_name,
                    ))

                last_end = end

            # Remaining literal text after the last variable reference.
            if last_end < len(text):
                result_fragments.append(StringFragment(
                    value=text[last_end:],
                    tainted=False,
                ))
            elif last_end == 0:
                # No interpolation found -- keep the original fragment.
                result_fragments.append(frag.copy())

        return StringValue(result_fragments)

    def copy(self) -> "StringValue":
        return StringValue([f.copy() for f in self.fragments])

    def __repr__(self) -> str:
        parts = []
        for f in self.fragments:
            if f.tainted:
                parts.append(f"<TAINT:{f.source or '?'}>")
            elif f.value is not None:
                display = f.value if len(f.value) <= 30 else f.value[:27] + "..."
                parts.append(repr(display))
            else:
                parts.append("<unknown>")
        return f"StringValue([{', '.join(parts)}])"


# ---------------------------------------------------------------------------
# StringAnalyzer -- evaluates AST expressions into StringValue
# ---------------------------------------------------------------------------

# SQL clause keywords used to locate tainted positions within queries.
_SQL_DANGEROUS_CLAUSES = re.compile(
    r'\b(WHERE|VALUES|SET|HAVING|ORDER\s+BY|GROUP\s+BY|LIMIT|UNION)\b',
    re.IGNORECASE,
)
_SQL_TABLE_POSITION = re.compile(
    r'\b(FROM|INTO|UPDATE|JOIN)\s+$',
    re.IGNORECASE,
)


class StringAnalyzer:
    """
    Evaluates PHP AST expression nodes into :class:`StringValue` objects and
    performs context-aware sink checking to reduce false positives.

    The analyzer bridges the gap between the abstract interpreter's per-variable
    :class:`~core.abstract_interp.TaintInfo` and the finer-grained positional
    taint tracked by StringValue.

    Args:
        rule_engine: A :class:`~core.rule_engine.RuleEngine` instance used to
                     look up sink definitions and vulnerability types.
    """

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or get_rule_engine()

    # -- Expression evaluation -----------------------------------------------

    def analyze_string_expr(
        self,
        node: TSNode,
        env: Dict[str, StringValue],
    ) -> StringValue:
        """Evaluate a PHP expression AST node into a :class:`StringValue`.

        Handles literals, variables, concatenation (binary ``.``), and
        double-quoted string interpolation.  Falls back to an unknown tainted
        fragment when the node type is unrecognised.

        Args:
            node: A tree-sitter AST node (wrapped by :class:`TSNode`).
            env:  Current mapping of PHP variable names to their StringValue.

        Returns:
            The resulting StringValue for the expression.
        """
        if node is None:
            return StringValue()

        node_type = node.type

        # -- String literal (single-quoted, no interpolation) ----------------
        if node_type == "string" and not node.named_children:
            raw = node.text
            # Strip surrounding quotes.
            if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
                raw = raw[1:-1]
            return StringValue([StringFragment(value=raw, tainted=False)])

        # -- Encapsed (double-quoted) string with interpolation --------------
        if node_type in ("encapsed_string", "heredoc"):
            return self._analyze_encapsed(node, env)

        # -- Integer / float / null / boolean literals -----------------------
        if node_type in ("integer", "float", "null", "boolean"):
            return StringValue([StringFragment(value=node.text, tainted=False)])

        # -- Variable reference ----------------------------------------------
        if node_type == "variable_name":
            var_name = node.text
            if var_name in env:
                return env[var_name].copy()
            # Variable not in env -- return unknown untainted fragment.
            return StringValue([StringFragment(value=None, tainted=False, source=var_name)])

        # -- Subscript expression ($arr['key']) ------------------------------
        if node_type == "subscript_expression":
            return self._analyze_subscript(node, env)

        # -- Binary expression (concatenation with '.') ---------------------
        if node_type == "binary_expression":
            return self._analyze_binary(node, env)

        # -- Parenthesized expression ----------------------------------------
        if node_type == "parenthesized_expression":
            children = node.named_children
            if children:
                return self.analyze_string_expr(children[0], env)
            return StringValue()

        # -- Function / method call ------------------------------------------
        if node_type in ("function_call_expression", "member_call_expression"):
            return self._analyze_call(node, env)

        # -- Assignment expression -------------------------------------------
        if node_type == "assignment_expression":
            return self._analyze_assignment(node, env)

        # -- Cast expression -------------------------------------------------
        if node_type == "cast_expression":
            cast_type_node = node.child_by_field("type")
            if cast_type_node and cast_type_node.text in (
                "int", "integer", "float", "double", "bool", "boolean",
            ):
                return StringValue([StringFragment(value=None, tainted=False)])
            children = node.named_children
            if children:
                return self.analyze_string_expr(children[-1], env)

        # -- Fallback: unknown expression ------------------------------------
        return StringValue([StringFragment(value=None, tainted=False)])

    # -- Private expression handlers -----------------------------------------

    def _analyze_encapsed(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        """Handle double-quoted strings with embedded variables."""
        fragments: List[StringFragment] = []
        for child in node.children:
            if child.type == "string_content":
                fragments.append(StringFragment(value=child.text, tainted=False))
            elif child.type == "variable_name":
                var_name = child.text
                if var_name in env:
                    fragments.extend(f.copy() for f in env[var_name].fragments)
                else:
                    fragments.append(StringFragment(
                        value=None, tainted=False, source=var_name,
                    ))
            elif child.type in ("\"", "'", "<<<"):
                # Quote delimiters -- skip.
                continue
            else:
                # Nested expression inside the string.
                sub_val = self.analyze_string_expr(child, env)
                fragments.extend(sub_val.fragments)
        return StringValue(fragments)

    def _analyze_subscript(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        """Handle ``$arr['key']`` or ``$_GET['param']``."""
        full_text = node.text
        # Check if base is a superglobal source.
        children = node.named_children
        if children:
            base_text = children[0].text if children[0].type == "variable_name" else ""
            if base_text in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"):
                return StringValue([StringFragment(
                    value=None,
                    tainted=True,
                    taint_types={"SQL", "XSS", "COMMAND", "CODE"},
                    source=full_text,
                )])
            if base_text == "$_SERVER":
                return StringValue([StringFragment(
                    value=None,
                    tainted=True,
                    taint_types={"SQL", "XSS", "COMMAND"},
                    source=full_text,
                )])
        # Check the env for the full subscript text.
        if full_text in env:
            return env[full_text].copy()
        return StringValue([StringFragment(value=None, tainted=False, source=full_text)])

    def _analyze_binary(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        """Handle binary expressions -- only concatenation (``'.'``) produces
        a meaningful StringValue; other operators return unknown."""
        left_node = node.child_by_field("left")
        right_node = node.child_by_field("right")
        # Determine the operator by examining children for the '.' token.
        is_concat = False
        for child in node.children:
            if child.type == "." or (not child.type.isalpha() and child.text == "."):
                is_concat = True
                break

        left_val = self.analyze_string_expr(left_node, env) if left_node else StringValue()
        right_val = self.analyze_string_expr(right_node, env) if right_node else StringValue()

        if is_concat:
            return left_val.concat(right_val)

        # Non-concatenation binary op -- the result is not a meaningful string.
        return StringValue([StringFragment(value=None, tainted=False)])

    def _analyze_call(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        """Handle function and method calls.

        If the call is a known sanitizer, the result is untainted.  Otherwise,
        taint propagates from the arguments.
        """
        func_name = node.get_function_name()
        if not func_name:
            return StringValue([StringFragment(value=None, tainted=False)])

        # Check if the function is a known sanitizer.
        if self.rule_engine and self.rule_engine.is_sanitizer(func_name):
            return StringValue([StringFragment(value=None, tainted=False)])

        # Propagate taint from arguments.
        args = node.get_arguments()
        merged = StringValue()
        for arg in args:
            arg_val = self.analyze_string_expr(arg, env)
            if arg_val.has_tainted_fragment():
                merged = merged.concat(arg_val)

        if merged.fragments:
            return merged
        return StringValue([StringFragment(value=None, tainted=False)])

    def _analyze_assignment(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        """Handle ``$var = expr``, updating *env* and returning the value."""
        left = node.child_by_field("left")
        right = node.child_by_field("right")
        if not left or not right:
            return StringValue()

        rhs_val = self.analyze_string_expr(right, env)

        var_name = left.text if left.type == "variable_name" else None
        if var_name:
            env[var_name] = rhs_val.copy()

        return rhs_val

    # -- Context-aware sink checking -----------------------------------------

    def check_sink_context(
        self,
        sink_name: str,
        string_val: StringValue,
    ) -> Dict:
        """Perform context-aware analysis of a tainted StringValue reaching a
        sink, returning a risk assessment dictionary.

        The result dict always contains:
            - ``dangerous`` (bool): Whether the tainted position is considered
              high-risk for the given sink type.
            - ``risk_level`` (str): ``'high'``, ``'medium'``, or ``'low'``.
            - ``context`` (str): Human-readable description of why the risk
              level was assigned.
            - ``tainted_positions`` (List[int]): Indices of tainted fragments.

        Sink-type heuristics:
            **SQL** -- tainted data in a WHERE/VALUES/SET clause is dangerous;
            tainted data adjacent to FROM/INTO (table-name position) is less so.

            **XSS** -- tainted data inside an HTML attribute context is
            dangerous; tainted data inside an HTML comment is considered safe.

            **COMMAND** -- tainted data that constitutes the command itself
            (first position) is critical; tainted data in argument positions
            is still dangerous but slightly less so.

        Args:
            sink_name: Name of the sink function (e.g. ``'mysqli_query'``).
            string_val: The StringValue reaching the sink.

        Returns:
            A dict with risk assessment fields.
        """
        if not string_val.has_tainted_fragment():
            return {
                "dangerous": False,
                "risk_level": "low",
                "context": "No tainted fragments in string value.",
                "tainted_positions": [],
            }

        vuln_type = self._resolve_vuln_type(sink_name)
        tainted_positions = string_val.get_tainted_positions()
        literal_text = string_val.get_literal_text()

        if vuln_type == "SQL":
            return self._check_sql_context(string_val, tainted_positions, literal_text)
        elif vuln_type == "XSS":
            return self._check_xss_context(string_val, tainted_positions, literal_text)
        elif vuln_type in ("COMMAND", "CMD"):
            return self._check_cmd_context(string_val, tainted_positions, literal_text)

        # Generic fallback -- any tainted data at a sink is suspicious.
        return {
            "dangerous": True,
            "risk_level": "high",
            "context": f"Tainted data reaches sink '{sink_name}' (type: {vuln_type}).",
            "tainted_positions": tainted_positions,
        }

    # -- Sink-specific context helpers ---------------------------------------

    def _check_sql_context(
        self,
        string_val: StringValue,
        tainted_positions: List[int],
        literal_text: str,
    ) -> Dict:
        """Assess SQL injection risk based on where tainted data appears."""
        # Build the literal prefix up to the first tainted fragment.
        first_tainted = tainted_positions[0] if tainted_positions else 0
        prefix_parts = []
        for i, frag in enumerate(string_val.fragments):
            if i >= first_tainted:
                break
            if frag.value is not None:
                prefix_parts.append(frag.value)
        prefix = "".join(prefix_parts)

        # Is the tainted fragment inside a dangerous SQL clause?
        if _SQL_DANGEROUS_CLAUSES.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data in SQL clause (WHERE/VALUES/SET/HAVING/ORDER BY).",
                "tainted_positions": tainted_positions,
            }

        # Is the tainted fragment in a table-name position?
        if _SQL_TABLE_POSITION.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "medium",
                "context": "Tainted data in SQL table-name position (FROM/INTO/UPDATE/JOIN).",
                "tainted_positions": tainted_positions,
            }

        # Tainted data in other SQL positions (e.g. column alias) -- still risky
        # but less clear-cut.
        return {
            "dangerous": True,
            "risk_level": "medium",
            "context": "Tainted data in SQL query at an unclassified position.",
            "tainted_positions": tainted_positions,
        }

    def _check_xss_context(
        self,
        string_val: StringValue,
        tainted_positions: List[int],
        literal_text: str,
    ) -> Dict:
        """Assess XSS risk based on the surrounding HTML context."""
        first_tainted = tainted_positions[0] if tainted_positions else 0
        prefix_parts = []
        for i, frag in enumerate(string_val.fragments):
            if i >= first_tainted:
                break
            if frag.value is not None:
                prefix_parts.append(frag.value)
        prefix = "".join(prefix_parts)

        # Inside an HTML comment?  Generally safe.
        if "<!--" in prefix and "-->" not in prefix:
            return {
                "dangerous": False,
                "risk_level": "low",
                "context": "Tainted data inside an HTML comment (generally safe).",
                "tainted_positions": tainted_positions,
            }

        # Inside an HTML attribute value?  Dangerous.
        # Heuristic: look for an unclosed attribute quote in the prefix.
        attr_pattern = re.compile(r'=\s*["\'][^"\']*$')
        if attr_pattern.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data inside an HTML attribute value.",
                "tainted_positions": tainted_positions,
            }

        # Inside a <script> block?  Very dangerous.
        if re.search(r'<script[^>]*>[^<]*$', prefix, re.IGNORECASE):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data inside a <script> block.",
                "tainted_positions": tainted_positions,
            }

        # Generic HTML body context.
        return {
            "dangerous": True,
            "risk_level": "medium",
            "context": "Tainted data in HTML body context.",
            "tainted_positions": tainted_positions,
        }

    def _check_cmd_context(
        self,
        string_val: StringValue,
        tainted_positions: List[int],
        literal_text: str,
    ) -> Dict:
        """Assess command injection risk based on tainted-data position."""
        if not tainted_positions:
            return {
                "dangerous": False,
                "risk_level": "low",
                "context": "No tainted fragments in command string.",
                "tainted_positions": [],
            }

        first_tainted = tainted_positions[0]

        # If the very first fragment is tainted, the user controls the command
        # binary itself -- critical.
        if first_tainted == 0:
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data controls the command executable itself.",
                "tainted_positions": tainted_positions,
            }

        # Check whether the literal prefix up to the tainted fragment contains
        # a space, indicating the tainted data is an argument.
        prefix_parts = []
        for i, frag in enumerate(string_val.fragments):
            if i >= first_tainted:
                break
            if frag.value is not None:
                prefix_parts.append(frag.value)
        prefix = "".join(prefix_parts)

        if " " in prefix:
            return {
                "dangerous": True,
                "risk_level": "medium",
                "context": "Tainted data used as a command argument.",
                "tainted_positions": tainted_positions,
            }

        # Tainted data immediately after the command name with no separator --
        # could be part of the command name or a flag.
        return {
            "dangerous": True,
            "risk_level": "high",
            "context": "Tainted data adjacent to command name without clear separator.",
            "tainted_positions": tainted_positions,
        }

    # -- Utility -------------------------------------------------------------

    def _resolve_vuln_type(self, sink_name: str) -> str:
        """Map a sink name to its vulnerability type using the rule engine.
        Falls back to keyword-based heuristics when no rule is found."""
        if self.rule_engine:
            vuln_type = self.rule_engine.get_sink_vuln_type(sink_name)
            if vuln_type:
                return vuln_type.upper()

        # Heuristic fallback based on common sink names.
        name_lower = sink_name.lower()
        sql_keywords = ("query", "mysql", "mysqli", "pg_query", "sqlite", "pdo")
        xss_keywords = ("echo", "print", "printf", "vprintf", "die")
        cmd_keywords = ("exec", "system", "passthru", "shell_exec", "popen", "proc_open")

        if any(kw in name_lower for kw in sql_keywords):
            return "SQL"
        if any(kw in name_lower for kw in xss_keywords):
            return "XSS"
        if any(kw in name_lower for kw in cmd_keywords):
            return "COMMAND"
        return "UNKNOWN"
