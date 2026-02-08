#!/usr/bin/env python3
"""
Tree-sitter adapter for APEX taint engine.
Wraps tree-sitter nodes with a clean interface for taint analysis.
"""

import tree_sitter_php as tsphp
from tree_sitter import Language, Parser
from typing import Optional, List


# Module-level parser (initialized once)
_language = Language(tsphp.language_php())
_parser = Parser(_language)

# Punctuation types to skip when iterating children
_PUNCTUATION = frozenset({
    '(', ')', '{', '}', '[', ']', ';', ',', ':', '=', '=>',
    '->', '::', '.', '?', '!', '&&', '||', '??', '...', '@',
    'php_tag', 'text_interpolation',
})


class TSNode:
    """Lightweight wrapper around a tree-sitter node."""

    __slots__ = ('_node', '_code')

    def __init__(self, ts_node, code_bytes: bytes):
        self._node = ts_node
        self._code = code_bytes

    @property
    def type(self) -> str:
        return self._node.type

    @property
    def text(self) -> str:
        return self._code[self._node.start_byte:self._node.end_byte].decode('utf8', errors='replace')

    @property
    def line(self) -> int:
        """1-based line number."""
        return self._node.start_point[0] + 1

    @property
    def children(self) -> List['TSNode']:
        """All children, including punctuation."""
        return [TSNode(c, self._code) for c in self._node.children]

    @property
    def named_children(self) -> List['TSNode']:
        """Named children only (skip punctuation/anonymous tokens)."""
        return [TSNode(c, self._code) for c in self._node.children if c.is_named]

    @property
    def child_count(self) -> int:
        return self._node.child_count

    def child_by_field(self, name: str) -> Optional['TSNode']:
        """Get child by tree-sitter field name."""
        c = self._node.child_by_field_name(name)
        if c is not None:
            return TSNode(c, self._code)
        return None

    def get_variable_name(self) -> str:
        """
        Extract the full variable name like '$_GET' or '$x' from a variable_name node.
        variable_name has children: '$' + name
        """
        if self.type == 'variable_name':
            return self.text
        return ''

    def get_function_name(self) -> str:
        """Extract function name from a function_call_expression node."""
        if self.type == 'function_call_expression':
            func = self.child_by_field('function')
            if func:
                return func.text
        elif self.type == 'member_call_expression':
            name = self.child_by_field('name')
            if name:
                return name.text
        elif self.type == 'scoped_call_expression':
            name = self.child_by_field('name')
            if name:
                return name.text
        return ''

    def get_arguments(self) -> List['TSNode']:
        """Get argument nodes from a call expression."""
        args_node = self.child_by_field('arguments')
        if args_node is None:
            return []
        return [TSNode(c, self._code) for c in args_node._node.children
                if c.is_named and c.type == 'argument']

    def walk_descendants(self):
        """Yield all descendant nodes (depth-first)."""
        stack = list(reversed(self.children))
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    def __repr__(self):
        text = self.text
        if len(text) > 40:
            text = text[:40] + '...'
        return f'TSNode({self.type}, line={self.line}, {repr(text)})'


def parse_php_ts(code: str) -> TSNode:
    """Parse PHP code with tree-sitter, return wrapped root node."""
    if not code.strip().startswith('<?'):
        code = '<?php\n' + code
    code_bytes = code.encode('utf8')
    tree = _parser.parse(code_bytes)
    return TSNode(tree.root_node, code_bytes)
