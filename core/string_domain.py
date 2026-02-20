#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re

from .ts_adapter import TSNode
from .rule_engine import get_rule_engine, RuleEngine


@dataclass
class StringFragment:
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


class StringValue:

    def __init__(self, fragments: Optional[List[StringFragment]] = None):
        self.fragments: List[StringFragment] = fragments if fragments is not None else []


    def is_fully_literal(self) -> bool:
        if not self.fragments:
            return True
        return all(f.value is not None and not f.tainted for f in self.fragments)

    def has_tainted_fragment(self) -> bool:
        return any(f.tainted for f in self.fragments)

    def get_tainted_positions(self) -> List[int]:
        return [i for i, f in enumerate(self.fragments) if f.tainted]

    def get_literal_text(self) -> str:
        parts: List[str] = []
        for frag in self.fragments:
            if frag.value is not None:
                parts.append(frag.value)
            else:
                parts.append("{?}")
        return "".join(parts)

    def get_all_taint_types(self) -> Set[str]:
        types: Set[str] = set()
        for frag in self.fragments:
            if frag.tainted:
                types |= frag.taint_types
        return types

    def get_all_sources(self) -> Set[str]:
        sources: Set[str] = set()
        for frag in self.fragments:
            if frag.tainted and frag.source:
                sources.add(frag.source)
        return sources


    def concat(self, other: "StringValue") -> "StringValue":
        merged: List[StringFragment] = []
        for frag in self.fragments + other.fragments:
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
        var_pattern = re.compile(r'\$\{?([a-zA-Z_]\w*)\}?')
        result_fragments: List[StringFragment] = []

        for frag in self.fragments:
            if frag.value is None or frag.tainted:
                result_fragments.append(frag.copy())
                continue

            text = frag.value
            last_end = 0

            for match in var_pattern.finditer(text):
                var_name = "$" + match.group(1)
                start, end = match.start(), match.end()

                if start > last_end:
                    result_fragments.append(StringFragment(
                        value=text[last_end:start],
                        tainted=False,
                    ))

                if var_name in var_map:
                    for sub_frag in var_map[var_name].fragments:
                        result_fragments.append(sub_frag.copy())
                else:
                    result_fragments.append(StringFragment(
                        value=None,
                        tainted=True,
                        taint_types=set(),
                        source=var_name,
                    ))

                last_end = end

            if last_end < len(text):
                result_fragments.append(StringFragment(
                    value=text[last_end:],
                    tainted=False,
                ))
            elif last_end == 0:
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


_SQL_DANGEROUS_CLAUSES = re.compile(
    r'\b(WHERE|VALUES|SET|HAVING|ORDER\s+BY|GROUP\s+BY|LIMIT|UNION)\b',
    re.IGNORECASE,
)
_SQL_TABLE_POSITION = re.compile(
    r'\b(FROM|INTO|UPDATE|JOIN)\s+$',
    re.IGNORECASE,
)


# tracks tainted fragments in string concatenation/interpolation
class StringAnalyzer:

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or get_rule_engine()


    def analyze_string_expr(
        self,
        node: TSNode,
        env: Dict[str, StringValue],
    ) -> StringValue:
        if node is None:
            return StringValue()

        node_type = node.type

        if node_type == "string" and not node.named_children:
            raw = node.text
            if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
                raw = raw[1:-1]
            return StringValue([StringFragment(value=raw, tainted=False)])

        if node_type in ("encapsed_string", "heredoc"):
            return self._analyze_encapsed(node, env)

        if node_type in ("integer", "float", "null", "boolean"):
            return StringValue([StringFragment(value=node.text, tainted=False)])

        if node_type == "variable_name":
            var_name = node.text
            if var_name in env:
                return env[var_name].copy()
            return StringValue([StringFragment(value=None, tainted=False, source=var_name)])

        if node_type == "subscript_expression":
            return self._analyze_subscript(node, env)

        if node_type == "binary_expression":
            return self._analyze_binary(node, env)

        if node_type == "parenthesized_expression":
            children = node.named_children
            if children:
                return self.analyze_string_expr(children[0], env)
            return StringValue()

        if node_type in ("function_call_expression", "member_call_expression"):
            return self._analyze_call(node, env)

        if node_type == "assignment_expression":
            return self._analyze_assignment(node, env)

        if node_type == "cast_expression":
            cast_type_node = node.child_by_field("type")
            if cast_type_node and cast_type_node.text in (
                "int", "integer", "float", "double", "bool", "boolean",
            ):
                return StringValue([StringFragment(value=None, tainted=False)])
            children = node.named_children
            if children:
                return self.analyze_string_expr(children[-1], env)

        return StringValue([StringFragment(value=None, tainted=False)])


    def _analyze_encapsed(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
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
                continue
            else:
                sub_val = self.analyze_string_expr(child, env)
                fragments.extend(sub_val.fragments)
        return StringValue(fragments)

    def _analyze_subscript(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        full_text = node.text
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
        if full_text in env:
            return env[full_text].copy()
        return StringValue([StringFragment(value=None, tainted=False, source=full_text)])

    def _analyze_binary(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        left_node = node.child_by_field("left")
        right_node = node.child_by_field("right")
        is_concat = False
        for child in node.children:
            if child.type == "." or (not child.type.isalpha() and child.text == "."):
                is_concat = True
                break

        left_val = self.analyze_string_expr(left_node, env) if left_node else StringValue()
        right_val = self.analyze_string_expr(right_node, env) if right_node else StringValue()

        if is_concat:
            return left_val.concat(right_val)

        return StringValue([StringFragment(value=None, tainted=False)])

    def _analyze_call(self, node: TSNode, env: Dict[str, StringValue]) -> StringValue:
        func_name = node.get_function_name()
        if not func_name:
            return StringValue([StringFragment(value=None, tainted=False)])

        if self.rule_engine and self.rule_engine.is_sanitizer(func_name):
            return StringValue([StringFragment(value=None, tainted=False)])

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
        left = node.child_by_field("left")
        right = node.child_by_field("right")
        if not left or not right:
            return StringValue()

        rhs_val = self.analyze_string_expr(right, env)

        var_name = left.text if left.type == "variable_name" else None
        if var_name:
            env[var_name] = rhs_val.copy()

        return rhs_val


    def check_sink_context(
        self,
        sink_name: str,
        string_val: StringValue,
    ) -> Dict:
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

        return {
            "dangerous": True,
            "risk_level": "high",
            "context": f"Tainted data reaches sink '{sink_name}' (type: {vuln_type}).",
            "tainted_positions": tainted_positions,
        }


    def _check_sql_context(
        self,
        string_val: StringValue,
        tainted_positions: List[int],
        literal_text: str,
    ) -> Dict:
        first_tainted = tainted_positions[0] if tainted_positions else 0
        prefix_parts = []
        for i, frag in enumerate(string_val.fragments):
            if i >= first_tainted:
                break
            if frag.value is not None:
                prefix_parts.append(frag.value)
        prefix = "".join(prefix_parts)

        if _SQL_DANGEROUS_CLAUSES.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data in SQL clause (WHERE/VALUES/SET/HAVING/ORDER BY).",
                "tainted_positions": tainted_positions,
            }

        if _SQL_TABLE_POSITION.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "medium",
                "context": "Tainted data in SQL table-name position (FROM/INTO/UPDATE/JOIN).",
                "tainted_positions": tainted_positions,
            }

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
        first_tainted = tainted_positions[0] if tainted_positions else 0
        prefix_parts = []
        for i, frag in enumerate(string_val.fragments):
            if i >= first_tainted:
                break
            if frag.value is not None:
                prefix_parts.append(frag.value)
        prefix = "".join(prefix_parts)

        if "<!--" in prefix and "-->" not in prefix:
            return {
                "dangerous": False,
                "risk_level": "low",
                "context": "Tainted data inside an HTML comment (generally safe).",
                "tainted_positions": tainted_positions,
            }

        attr_pattern = re.compile(r'=\s*["\'][^"\']*$')
        if attr_pattern.search(prefix):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data inside an HTML attribute value.",
                "tainted_positions": tainted_positions,
            }

        if re.search(r'<script[^>]*>[^<]*$', prefix, re.IGNORECASE):
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data inside a <script> block.",
                "tainted_positions": tainted_positions,
            }

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
        if not tainted_positions:
            return {
                "dangerous": False,
                "risk_level": "low",
                "context": "No tainted fragments in command string.",
                "tainted_positions": [],
            }

        first_tainted = tainted_positions[0]

        if first_tainted == 0:
            return {
                "dangerous": True,
                "risk_level": "high",
                "context": "Tainted data controls the command executable itself.",
                "tainted_positions": tainted_positions,
            }

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

        return {
            "dangerous": True,
            "risk_level": "high",
            "context": "Tainted data adjacent to command name without clear separator.",
            "tainted_positions": tainted_positions,
        }


    def _resolve_vuln_type(self, sink_name: str) -> str:
        if self.rule_engine:
            vuln_type = self.rule_engine.get_sink_vuln_type(sink_name)
            if vuln_type:
                return vuln_type.upper()

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
