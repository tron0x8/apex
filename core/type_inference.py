#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Set, Optional, Tuple

from .cfg import CFGBlock
from .ts_adapter import TSNode
from .rule_engine import RuleEngine


class PHPType(Enum):

    BOTTOM    = auto()
    NULL      = auto()
    BOOL      = auto()
    INT       = auto()
    FLOAT     = auto()
    STRING    = auto()
    ARRAY     = auto()
    OBJECT    = auto()
    RESOURCE  = auto()
    CALLABLE  = auto()
    MIXED     = auto()

    def is_numeric(self) -> bool:
        return self in (PHPType.INT, PHPType.FLOAT)

    def is_scalar(self) -> bool:
        return self in (PHPType.BOOL, PHPType.INT, PHPType.FLOAT, PHPType.STRING)


BOTTOM   = PHPType.BOTTOM
NULL     = PHPType.NULL
BOOL     = PHPType.BOOL
INT      = PHPType.INT
FLOAT    = PHPType.FLOAT
STRING   = PHPType.STRING
ARRAY    = PHPType.ARRAY
OBJECT   = PHPType.OBJECT
RESOURCE = PHPType.RESOURCE
CALLABLE = PHPType.CALLABLE
MIXED    = PHPType.MIXED


_ALL_CONCRETE: Set[PHPType] = {
    NULL, BOOL, INT, FLOAT, STRING, ARRAY, OBJECT, RESOURCE, CALLABLE,
}


class TypeState:

    def __init__(self, mapping: Optional[Dict[str, Set[PHPType]]] = None) -> None:
        self._map: Dict[str, Set[PHPType]] = mapping if mapping is not None else {}

    def get(self, var: str) -> Set[PHPType]:
        return self._map.get(var, {MIXED})

    def set(self, var: str, types: Set[PHPType]) -> None:
        self._map[var] = types

    def copy(self) -> TypeState:
        return TypeState({k: set(v) for k, v in self._map.items()})

    def join(self, other: TypeState) -> TypeState:
        all_vars = set(self._map.keys()) | set(other._map.keys())
        merged: Dict[str, Set[PHPType]] = {}
        for var in all_vars:
            merged[var] = self.get(var) | other.get(var)
        return TypeState(merged)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeState):
            return NotImplemented
        return self._map == other._map

    def as_dict(self) -> Dict[str, Set[PHPType]]:
        return dict(self._map)

    def __repr__(self) -> str:
        parts = []
        for var in sorted(self._map):
            types_str = "|".join(t.name for t in sorted(self._map[var], key=lambda t: t.value))
            parts.append(f"{var}: {types_str}")
        return "TypeState({" + ", ".join(parts) + "})"


_FUNC_RETURN_TYPE: Dict[str, Set[PHPType]] = {
    "intval":     {INT},
    "floatval":   {FLOAT},
    "doubleval":  {FLOAT},
    "strval":     {STRING},
    "boolval":    {BOOL},
    "settype":    {BOOL},
    "abs":        {INT, FLOAT},
    "ceil":       {FLOAT},
    "floor":      {FLOAT},
    "round":      {FLOAT},
    "strlen":     {INT},
    "count":      {INT},
    "sizeof":     {INT},
    "ord":        {INT},
    "chr":        {STRING},
    "strtolower": {STRING},
    "strtoupper": {STRING},
    "trim":       {STRING},
    "ltrim":      {STRING},
    "rtrim":      {STRING},
    "substr":     {STRING},
    "str_replace":{STRING},
    "implode":    {STRING},
    "join":       {STRING},
    "explode":    {ARRAY},
    "array_keys": {ARRAY},
    "array_values": {ARRAY},
    "array_merge": {ARRAY},
    "array_map":  {ARRAY},
    "json_encode": {STRING},
    "json_decode": {MIXED},
    "is_null":    {BOOL},
    "is_int":     {BOOL},
    "is_integer": {BOOL},
    "is_long":    {BOOL},
    "is_float":   {BOOL},
    "is_double":  {BOOL},
    "is_string":  {BOOL},
    "is_bool":    {BOOL},
    "is_array":   {BOOL},
    "is_object":  {BOOL},
    "is_numeric": {BOOL},
    "isset":      {BOOL},
    "empty":      {BOOL},
}

_CAST_TYPE: Dict[str, Set[PHPType]] = {
    "int":      {INT},
    "integer":  {INT},
    "float":    {FLOAT},
    "double":   {FLOAT},
    "real":     {FLOAT},
    "string":   {STRING},
    "binary":   {STRING},
    "bool":     {BOOL},
    "boolean":  {BOOL},
    "array":    {ARRAY},
    "object":   {OBJECT},
    "unset":    {NULL},
}

_TYPE_CHECK_FUNC: Dict[str, Set[PHPType]] = {
    "is_int":     {INT},
    "is_integer": {INT},
    "is_long":    {INT},
    "is_float":   {FLOAT},
    "is_double":  {FLOAT},
    "is_numeric": {INT, FLOAT},
    "is_string":  {STRING},
    "is_bool":    {BOOL},
    "is_array":   {ARRAY},
    "is_object":  {OBJECT},
    "is_null":    {NULL},
    "is_resource": {RESOURCE},
    "is_callable": {CALLABLE},
}

_NUMERIC_SAFE_VULNS: Set[str] = {
    "sqli", "sql_injection", "xss", "cross_site_scripting",
    "path_traversal", "command_injection", "ldap_injection",
    "header_injection", "xpath_injection",
}

_BOOL_SAFE_VULNS: Set[str] = {
    "sqli", "sql_injection", "xss", "cross_site_scripting",
    "path_traversal", "command_injection", "header_injection",
    "ldap_injection", "xpath_injection", "ssrf",
}


class TypeInference:

    MAX_ITERATIONS = 80

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._rule_engine = rule_engine


    def infer(self, cfg_blocks: List[CFGBlock]) -> Dict[str, Set[PHPType]]:
        if not cfg_blocks:
            return {}

        block_map: Dict[int, CFGBlock] = {b.id: b for b in cfg_blocks}

        in_state:  Dict[int, TypeState] = {b.id: TypeState() for b in cfg_blocks}
        out_state: Dict[int, TypeState] = {b.id: TypeState() for b in cfg_blocks}

        worklist: List[int] = [b.id for b in cfg_blocks if b.is_entry]
        if not worklist:
            worklist = [cfg_blocks[0].id]

        visited: Set[int] = set()

        for _ in range(self.MAX_ITERATIONS):
            if not worklist:
                break

            next_worklist: List[int] = []

            for block_id in worklist:
                block = block_map.get(block_id)
                if block is None:
                    continue

                if block.predecessors:
                    joined = TypeState()
                    for pred_id in block.predecessors:
                        joined = joined.join(out_state.get(pred_id, TypeState()))
                    in_state[block_id] = joined

                current = in_state[block_id].copy()
                for stmt in block.statements:
                    current = self._transfer(stmt, current)

                old_out = out_state[block_id]
                out_state[block_id] = current

                if current != old_out or block_id not in visited:
                    visited.add(block_id)
                    for succ_id in block.successors:
                        if succ_id not in next_worklist:
                            next_worklist.append(succ_id)

            worklist = next_worklist

        result: Dict[str, Set[PHPType]] = {}
        for state in out_state.values():
            for var, types in state.as_dict().items():
                if var in result:
                    result[var] = result[var] | types
                else:
                    result[var] = set(types)

        return result

    def type_sanitizes(self, var: str, vuln_type: str,
                       types: Dict[str, Set[PHPType]]) -> bool:
        var_types = types.get(var, {MIXED})
        if not var_types or MIXED in var_types:
            return False

        vuln_lower = vuln_type.lower()

        for t in var_types:
            if t == BOTTOM:
                continue
            if t in (INT, FLOAT) and vuln_lower in _NUMERIC_SAFE_VULNS:
                continue
            if t == BOOL and vuln_lower in _BOOL_SAFE_VULNS:
                continue
            if t == NULL:
                continue
            return False

        return True


    def _transfer(self, node: TSNode, state: TypeState) -> TypeState:
        if node.type == "expression_statement":
            for child in node.named_children:
                state = self._transfer(child, state)
            return state

        if node.type == "assignment_expression":
            return self._transfer_assignment_node(node, state)

        if node.type == "augmented_assignment_expression":
            return self._transfer_augmented_assignment(node, state)

        if node.type in ("parenthesized_expression", "unary_op_expression"):
            pass

        return state

    def _transfer_assignment_node(self, node: TSNode, state: TypeState) -> TypeState:
        lhs = node.child_by_field("left")
        rhs = node.child_by_field("right")
        if lhs is None or rhs is None:
            return state

        target = lhs.text if lhs.type == "variable_name" else None
        if target is None:
            return state

        inferred = self._infer_expr_type(rhs, state)
        state.set(target, inferred)
        return state

    def _transfer_augmented_assignment(self, node: TSNode, state: TypeState) -> TypeState:
        lhs = node.child_by_field("left")
        if lhs is None:
            return state

        target = lhs.text if lhs.type == "variable_name" else None
        if target is None:
            return state

        op_text = node.text
        if ".=" in op_text:
            state.set(target, {STRING})
        elif "+=" in op_text or "-=" in op_text or "*=" in op_text:
            existing = state.get(target)
            if existing <= {INT}:
                state.set(target, {INT})
            elif existing <= {FLOAT}:
                state.set(target, {FLOAT})
            else:
                state.set(target, {INT, FLOAT})
        else:
            pass

        return state

    def _transfer_assignment(self, target: str, expr: TSNode,
                             types: TypeState) -> TypeState:
        inferred = self._infer_expr_type(expr, types)
        types.set(target, inferred)
        return types


    def _infer_expr_type(self, node: TSNode, state: TypeState) -> Set[PHPType]:
        ntype = node.type

        if ntype == "integer":
            return {INT}
        if ntype == "float":
            return {FLOAT}
        if ntype in ("string", "encapsed_string", "heredoc", "nowdoc",
                      "shell_command_expression"):
            return {STRING}
        if ntype in ("boolean", "true", "false"):
            return {BOOL}
        if ntype == "null":
            return {NULL}
        if ntype == "array_creation_expression":
            return {ARRAY}

        if ntype == "variable_name":
            return set(state.get(node.text))

        if ntype == "cast_expression":
            cast_type_node = node.child_by_field("type")
            if cast_type_node:
                cast_text = cast_type_node.text.strip("() ").lower()
                if cast_text in _CAST_TYPE:
                    return set(_CAST_TYPE[cast_text])
            text = node.text.lower()
            for cast_kw, cast_types in _CAST_TYPE.items():
                if f"({cast_kw})" in text:
                    return set(cast_types)
            return {MIXED}

        if ntype == "function_call_expression":
            func_name = node.get_function_name().lower()
            if func_name in _FUNC_RETURN_TYPE:
                return set(_FUNC_RETURN_TYPE[func_name])
            return {MIXED}

        if ntype == "object_creation_expression":
            return {OBJECT}

        if ntype == "binary_expression":
            return self._infer_binary_type(node, state)

        if ntype == "unary_op_expression":
            op = node.text[0] if node.text else ""
            if op == "!":
                return {BOOL}
            if op in ("-", "+", "~"):
                return {INT, FLOAT}

        if ntype in ("conditional_expression", "coalesce_expression"):
            children = node.named_children
            if len(children) >= 2:
                t1 = self._infer_expr_type(children[-2], state)
                t2 = self._infer_expr_type(children[-1], state)
                return t1 | t2

        if ntype in ("member_access_expression", "member_call_expression",
                      "scoped_call_expression"):
            return {MIXED}

        if ntype == "subscript_expression":
            return {MIXED}

        return {MIXED}

    def _infer_binary_type(self, node: TSNode, state: TypeState) -> Set[PHPType]:
        text = node.text
        for op in ("===", "!==", "==", "!=", "<>", "<=", ">=", "<", ">",
                    "&&", "||", "and", "or", "xor", "instanceof"):
            if op in text:
                return {BOOL}
        if "." in text and ".." not in text and ".=" not in text:
            for child in node.children:
                if child.type == "." or (hasattr(child, 'text') and child.text == "."):
                    return {STRING}
        for op in ("+", "-", "*", "/", "%", "**"):
            if op in text:
                return {INT, FLOAT}
        for op in ("&", "|", "^", "<<", ">>"):
            if op in text:
                return {INT}

        return {MIXED}


    def narrow_from_condition(self, cond: TSNode,
                              types: TypeState) -> Tuple[TypeState, TypeState]:
        true_state = types.copy()
        false_state = types.copy()

        inner = cond
        if inner.type == "parenthesized_expression":
            children = inner.named_children
            if children:
                inner = children[0]

        negated = False
        if inner.type == "unary_op_expression" and inner.text.startswith("!"):
            negated = True
            children = inner.named_children
            if children:
                inner = children[0]

        if inner.type == "function_call_expression":
            func_name = inner.get_function_name().lower()
            if func_name in _TYPE_CHECK_FUNC:
                args = inner.get_arguments()
                if args:
                    arg_var = self._find_var_in_node(args[0])
                    if arg_var:
                        asserted_types = _TYPE_CHECK_FUNC[func_name]
                        complement = _ALL_CONCRETE - asserted_types

                        t_state = true_state
                        f_state = false_state
                        if negated:
                            t_state, f_state = f_state, t_state

                        current = t_state.get(arg_var)
                        if MIXED in current:
                            t_state.set(arg_var, set(asserted_types))
                        else:
                            narrowed = current & asserted_types
                            t_state.set(arg_var, narrowed if narrowed else set(asserted_types))

                        current_f = f_state.get(arg_var)
                        if MIXED in current_f:
                            f_state.set(arg_var, set(complement))
                        else:
                            excluded = current_f - asserted_types
                            f_state.set(arg_var, excluded if excluded else {MIXED})

            if func_name == "isset":
                args = inner.get_arguments()
                if args:
                    arg_var = self._find_var_in_node(args[0])
                    if arg_var:
                        t_s = true_state if not negated else false_state
                        f_s = false_state if not negated else true_state
                        cur = t_s.get(arg_var)
                        t_s.set(arg_var, cur - {NULL} if cur - {NULL} else cur)
                        f_cur = f_s.get(arg_var)
                        f_s.set(arg_var, f_cur | {NULL})

        if inner.type == "binary_expression" and "instanceof" in inner.text:
            children = inner.named_children
            if len(children) >= 2:
                var_node = children[0]
                var_name = var_node.text if var_node.type == "variable_name" else None
                if var_name:
                    t_s = true_state if not negated else false_state
                    t_s.set(var_name, {OBJECT})

        return true_state, false_state


    @staticmethod
    def _find_var_in_node(node: TSNode) -> Optional[str]:
        if node.type == "variable_name":
            return node.text
        for child in node.named_children:
            if child.type == "variable_name":
                return child.text
        for desc in node.walk_descendants():
            if desc.type == "variable_name":
                return desc.text
        return None
