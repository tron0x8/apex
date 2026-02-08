#!/usr/bin/env python3
"""
PHP type inference for the APEX security scanner.

Performs forward dataflow analysis over the CFG to infer variable types.
Type information is used to improve taint precision -- for example, a
variable known to be INT is safe against SQL injection and XSS even if
it originated from user input (because intval() or (int) cast strips
any payload).

Supports:
    - Literal type inference (42 -> INT, "hello" -> STRING, etc.)
    - Cast expressions ((int)$x -> INT, (string)$x -> STRING)
    - Type-coercing function calls (intval -> INT, floatval -> FLOAT)
    - Condition-based type narrowing (is_int($x) -> INT in true branch)
    - instanceof narrowing ($x instanceof Foo -> OBJECT:Foo in true branch)
    - Type-based sanitization checks (INT is safe for SQLi and XSS)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Set, Optional, Tuple

from .cfg import CFGBlock
from .ts_adapter import TSNode
from .rule_engine import RuleEngine


# ---------------------------------------------------------------------------
# PHP type lattice
# ---------------------------------------------------------------------------

class PHPType(Enum):
    """Abstract PHP types arranged in a flat lattice.

    BOTTOM is the uninhabited type (no value has this type).
    MIXED (TOP) represents an unknown or unconstrained type.
    The concrete types sit between BOTTOM and MIXED.
    """

    BOTTOM    = auto()   # No possible type (unreachable code)
    NULL      = auto()
    BOOL      = auto()
    INT       = auto()
    FLOAT     = auto()
    STRING    = auto()
    ARRAY     = auto()
    OBJECT    = auto()
    RESOURCE  = auto()
    CALLABLE  = auto()
    MIXED     = auto()   # TOP -- could be anything

    def is_numeric(self) -> bool:
        """Return True if this type is a numeric scalar."""
        return self in (PHPType.INT, PHPType.FLOAT)

    def is_scalar(self) -> bool:
        """Return True if this type is a scalar (bool, int, float, string)."""
        return self in (PHPType.BOOL, PHPType.INT, PHPType.FLOAT, PHPType.STRING)


# Convenient constant aliases at module level
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


# The full set of concrete (non-bottom, non-top) types
_ALL_CONCRETE: Set[PHPType] = {
    NULL, BOOL, INT, FLOAT, STRING, ARRAY, OBJECT, RESOURCE, CALLABLE,
}


# ---------------------------------------------------------------------------
# Type state: maps variable names to their possible types
# ---------------------------------------------------------------------------

class TypeState:
    """Mapping from variable names to their inferred type sets.

    A variable mapped to an empty set is BOTTOM (unreachable).
    A variable mapped to _ALL_CONCRETE (or containing MIXED) is unconstrained.
    """

    def __init__(self, mapping: Optional[Dict[str, Set[PHPType]]] = None) -> None:
        self._map: Dict[str, Set[PHPType]] = mapping if mapping is not None else {}

    def get(self, var: str) -> Set[PHPType]:
        """Return the type set for *var*, defaulting to {MIXED}."""
        return self._map.get(var, {MIXED})

    def set(self, var: str, types: Set[PHPType]) -> None:
        """Set the type set for *var*."""
        self._map[var] = types

    def copy(self) -> TypeState:
        """Return a deep copy of this state."""
        return TypeState({k: set(v) for k, v in self._map.items()})

    def join(self, other: TypeState) -> TypeState:
        """Compute the join (union) of two type states.

        The result maps every variable to the union of its type sets
        from both states. Variables present in only one state are
        joined with {MIXED} (the default for absent variables).
        """
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
        """Return the underlying mapping (shallow copy)."""
        return dict(self._map)

    def __repr__(self) -> str:
        parts = []
        for var in sorted(self._map):
            types_str = "|".join(t.name for t in sorted(self._map[var], key=lambda t: t.value))
            parts.append(f"{var}: {types_str}")
        return "TypeState({" + ", ".join(parts) + "})"


# ---------------------------------------------------------------------------
# Function / cast -> type mappings
# ---------------------------------------------------------------------------

# Functions that coerce their return value to a known type
_FUNC_RETURN_TYPE: Dict[str, Set[PHPType]] = {
    "intval":     {INT},
    "floatval":   {FLOAT},
    "doubleval":  {FLOAT},
    "strval":     {STRING},
    "boolval":    {BOOL},
    "settype":    {BOOL},       # returns bool, but mutates arg
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

# PHP cast expressions to target types
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

# Type-check functions -> the type they assert in the true branch
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

# Vulnerability types for which numeric types provide implicit sanitization
_NUMERIC_SAFE_VULNS: Set[str] = {
    "sqli", "sql_injection", "xss", "cross_site_scripting",
    "path_traversal", "command_injection", "ldap_injection",
    "header_injection", "xpath_injection",
}

# Vulnerability types for which BOOL is safe
_BOOL_SAFE_VULNS: Set[str] = {
    "sqli", "sql_injection", "xss", "cross_site_scripting",
    "path_traversal", "command_injection", "header_injection",
    "ldap_injection", "xpath_injection", "ssrf",
}


# ---------------------------------------------------------------------------
# Main type inference engine
# ---------------------------------------------------------------------------

class TypeInference:
    """Forward dataflow type inference over PHP CFG blocks.

    Usage::

        engine = TypeInference(rule_engine)
        type_map = engine.infer(cfg_blocks)
        # type_map: Dict[str, Set[PHPType]]

        if engine.type_sanitizes('$id', 'sqli', type_map):
            # $id is INT, safe for SQL injection
            ...
    """

    MAX_ITERATIONS = 80

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._rule_engine = rule_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def infer(self, cfg_blocks: List[CFGBlock]) -> Dict[str, Set[PHPType]]:
        """Run forward dataflow analysis and return final type mappings.

        Args:
            cfg_blocks: list of CFGBlock objects from the CFG builder.

        Returns:
            Dictionary mapping variable name -> set of possible PHPTypes.
        """
        if not cfg_blocks:
            return {}

        # Build block lookup
        block_map: Dict[int, CFGBlock] = {b.id: b for b in cfg_blocks}

        # Initialize per-block input/output states
        in_state:  Dict[int, TypeState] = {b.id: TypeState() for b in cfg_blocks}
        out_state: Dict[int, TypeState] = {b.id: TypeState() for b in cfg_blocks}

        # Worklist-based iteration
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

                # Compute input state as join of all predecessor outputs
                if block.predecessors:
                    joined = TypeState()
                    for pred_id in block.predecessors:
                        joined = joined.join(out_state.get(pred_id, TypeState()))
                    in_state[block_id] = joined
                # Entry blocks keep their initial (empty) state

                # Apply transfer functions for each statement
                current = in_state[block_id].copy()
                for stmt in block.statements:
                    current = self._transfer(stmt, current)

                old_out = out_state[block_id]
                out_state[block_id] = current

                # If output changed, schedule successors
                if current != old_out or block_id not in visited:
                    visited.add(block_id)
                    for succ_id in block.successors:
                        if succ_id not in next_worklist:
                            next_worklist.append(succ_id)

            worklist = next_worklist

        # Merge all output states into a single result
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
        """Check whether a variable's inferred type makes it safe for a
        given vulnerability type.

        For example, if $id is known to be INT, it is safe against SQL
        injection because an integer cannot contain SQL metacharacters.

        Args:
            var:       variable name (e.g. '$id').
            vuln_type: vulnerability type string (e.g. 'sqli', 'xss').
            types:     the type map produced by :meth:`infer`.

        Returns:
            True if the variable's types are all safe for *vuln_type*.
        """
        var_types = types.get(var, {MIXED})
        if not var_types or MIXED in var_types:
            return False

        vuln_lower = vuln_type.lower()

        for t in var_types:
            if t == BOTTOM:
                # Unreachable code -- trivially safe
                continue
            if t in (INT, FLOAT) and vuln_lower in _NUMERIC_SAFE_VULNS:
                continue
            if t == BOOL and vuln_lower in _BOOL_SAFE_VULNS:
                continue
            if t == NULL:
                # NULL is safe for most injection types (becomes empty string)
                continue
            # This type is NOT safe for the vulnerability
            return False

        return True

    # ------------------------------------------------------------------
    # Transfer functions
    # ------------------------------------------------------------------

    def _transfer(self, node: TSNode, state: TypeState) -> TypeState:
        """Apply the transfer function for a single AST statement.

        Dispatches based on node type to the appropriate handler.
        """
        if node.type == "expression_statement":
            for child in node.named_children:
                state = self._transfer(child, state)
            return state

        if node.type == "assignment_expression":
            return self._transfer_assignment_node(node, state)

        if node.type == "augmented_assignment_expression":
            return self._transfer_augmented_assignment(node, state)

        # Conditions (from if-statement condition nodes pushed into blocks)
        if node.type in ("parenthesized_expression", "unary_op_expression"):
            # We do not narrow here; narrowing happens when the CFG builder
            # splits true/false branches. We handle it via the public
            # narrow_from_condition method if needed.
            pass

        return state

    def _transfer_assignment_node(self, node: TSNode, state: TypeState) -> TypeState:
        """Handle  $target = expr  assignment."""
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
        """Handle  $a .= expr, $a += expr, etc."""
        lhs = node.child_by_field("left")
        if lhs is None:
            return state

        target = lhs.text if lhs.type == "variable_name" else None
        if target is None:
            return state

        # Determine result type from operator
        op_text = node.text
        if ".=" in op_text:
            state.set(target, {STRING})
        elif "+=" in op_text or "-=" in op_text or "*=" in op_text:
            # Arithmetic -- result is numeric
            existing = state.get(target)
            if existing <= {INT}:
                state.set(target, {INT})
            elif existing <= {FLOAT}:
                state.set(target, {FLOAT})
            else:
                state.set(target, {INT, FLOAT})
        else:
            # Other operators -- keep existing type
            pass

        return state

    def _transfer_assignment(self, target: str, expr: TSNode,
                             types: TypeState) -> TypeState:
        """Infer type from the RHS expression and update the state.

        This is the core assignment transfer function used by the
        public-facing analysis.

        Args:
            target: variable name being assigned to.
            expr:   the RHS AST node.
            types:  current type state.

        Returns:
            Updated TypeState with the target's type refined.
        """
        inferred = self._infer_expr_type(expr, types)
        types.set(target, inferred)
        return types

    # ------------------------------------------------------------------
    # Expression type inference
    # ------------------------------------------------------------------

    def _infer_expr_type(self, node: TSNode, state: TypeState) -> Set[PHPType]:
        """Infer the possible types of an expression node."""
        ntype = node.type

        # Literals
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

        # Variable reference -- return current known types
        if ntype == "variable_name":
            return set(state.get(node.text))

        # Cast expression: (int)$x, (string)$x, etc.
        if ntype == "cast_expression":
            cast_type_node = node.child_by_field("type")
            if cast_type_node:
                cast_text = cast_type_node.text.strip("() ").lower()
                if cast_text in _CAST_TYPE:
                    return set(_CAST_TYPE[cast_text])
            # Fallback: check text for cast pattern
            text = node.text.lower()
            for cast_kw, cast_types in _CAST_TYPE.items():
                if f"({cast_kw})" in text:
                    return set(cast_types)
            return {MIXED}

        # Function calls
        if ntype == "function_call_expression":
            func_name = node.get_function_name().lower()
            if func_name in _FUNC_RETURN_TYPE:
                return set(_FUNC_RETURN_TYPE[func_name])
            # Check if the rule engine knows about this function
            return {MIXED}

        # Object creation
        if ntype == "object_creation_expression":
            return {OBJECT}

        # Binary expressions
        if ntype == "binary_expression":
            return self._infer_binary_type(node, state)

        # Unary expressions
        if ntype == "unary_op_expression":
            op = node.text[0] if node.text else ""
            if op == "!":
                return {BOOL}
            if op in ("-", "+", "~"):
                return {INT, FLOAT}

        # Ternary / null coalesce
        if ntype in ("conditional_expression", "coalesce_expression"):
            # Join the types of both branches
            children = node.named_children
            if len(children) >= 2:
                t1 = self._infer_expr_type(children[-2], state)
                t2 = self._infer_expr_type(children[-1], state)
                return t1 | t2

        # Member access -- we cannot track object types precisely here
        if ntype in ("member_access_expression", "member_call_expression",
                      "scoped_call_expression"):
            return {MIXED}

        # Subscript (array access)
        if ntype == "subscript_expression":
            return {MIXED}

        return {MIXED}

    def _infer_binary_type(self, node: TSNode, state: TypeState) -> Set[PHPType]:
        """Infer the result type of a binary expression."""
        text = node.text
        # Comparison / logical operators always return bool
        for op in ("===", "!==", "==", "!=", "<>", "<=", ">=", "<", ">",
                    "&&", "||", "and", "or", "xor", "instanceof"):
            if op in text:
                return {BOOL}
        # String concatenation
        if "." in text and ".." not in text and ".=" not in text:
            # Could be concatenation operator or decimal point in a number.
            # Look for the actual '.' operator among children.
            for child in node.children:
                if child.type == "." or (hasattr(child, 'text') and child.text == "."):
                    return {STRING}
        # Arithmetic operators
        for op in ("+", "-", "*", "/", "%", "**"):
            if op in text:
                return {INT, FLOAT}
        # Bitwise operators
        for op in ("&", "|", "^", "<<", ">>"):
            if op in text:
                return {INT}

        return {MIXED}

    # ------------------------------------------------------------------
    # Condition-based type narrowing
    # ------------------------------------------------------------------

    def narrow_from_condition(self, cond: TSNode,
                              types: TypeState) -> Tuple[TypeState, TypeState]:
        """Narrow types based on a branch condition.

        Returns (true_state, false_state) representing what is known
        in each branch after the condition is evaluated.

        Handles patterns like:
            - is_int($x)         -> true: {INT}, false: everything except INT
            - is_numeric($x)     -> true: {INT, FLOAT}, false: no numeric
            - $x instanceof Foo  -> true: {OBJECT}, false: unchanged
            - isset($x)          -> true: remove NULL, false: add NULL

        Args:
            cond:  the condition AST node.
            types: current type state before the branch.

        Returns:
            Tuple of (true_branch_state, false_branch_state).
        """
        true_state = types.copy()
        false_state = types.copy()

        # Unwrap parentheses
        inner = cond
        if inner.type == "parenthesized_expression":
            children = inner.named_children
            if children:
                inner = children[0]

        # Handle negation:  !is_int($x)  swaps true/false
        negated = False
        if inner.type == "unary_op_expression" and inner.text.startswith("!"):
            negated = True
            children = inner.named_children
            if children:
                inner = children[0]

        # is_int($x), is_string($x), etc.
        if inner.type == "function_call_expression":
            func_name = inner.get_function_name().lower()
            if func_name in _TYPE_CHECK_FUNC:
                args = inner.get_arguments()
                if args:
                    # The first argument's first variable child
                    arg_var = self._find_var_in_node(args[0])
                    if arg_var:
                        asserted_types = _TYPE_CHECK_FUNC[func_name]
                        complement = _ALL_CONCRETE - asserted_types

                        t_state = true_state
                        f_state = false_state
                        if negated:
                            t_state, f_state = f_state, t_state

                        # True branch: narrow to asserted type(s)
                        current = t_state.get(arg_var)
                        if MIXED in current:
                            t_state.set(arg_var, set(asserted_types))
                        else:
                            narrowed = current & asserted_types
                            t_state.set(arg_var, narrowed if narrowed else set(asserted_types))

                        # False branch: exclude asserted type(s)
                        current_f = f_state.get(arg_var)
                        if MIXED in current_f:
                            f_state.set(arg_var, set(complement))
                        else:
                            excluded = current_f - asserted_types
                            f_state.set(arg_var, excluded if excluded else {MIXED})

            # isset($x) -> true: remove NULL
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

        # $x instanceof ClassName
        if inner.type == "binary_expression" and "instanceof" in inner.text:
            children = inner.named_children
            if len(children) >= 2:
                var_node = children[0]
                var_name = var_node.text if var_node.type == "variable_name" else None
                if var_name:
                    t_s = true_state if not negated else false_state
                    t_s.set(var_name, {OBJECT})

        return true_state, false_state

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_var_in_node(node: TSNode) -> Optional[str]:
        """Find the first variable_name text within a node subtree."""
        if node.type == "variable_name":
            return node.text
        for child in node.named_children:
            if child.type == "variable_name":
                return child.text
        # Deeper search
        for desc in node.walk_descendants():
            if desc.type == "variable_name":
                return desc.text
        return None
