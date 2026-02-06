#!/usr/bin/env python3

import re
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, Iterator
from collections import deque


class TokenType(Enum):
    T_STRING = auto()
    T_VARIABLE = auto()
    T_LNUMBER = auto()
    T_DNUMBER = auto()
    T_CONSTANT_ENCAPSED_STRING = auto()
    T_ENCAPSED_AND_WHITESPACE = auto()
    T_IF = auto()
    T_ELSE = auto()
    T_ELSEIF = auto()
    T_WHILE = auto()
    T_FOR = auto()
    T_FOREACH = auto()
    T_SWITCH = auto()
    T_CASE = auto()
    T_DEFAULT = auto()
    T_BREAK = auto()
    T_CONTINUE = auto()
    T_RETURN = auto()
    T_FUNCTION = auto()
    T_CLASS = auto()
    T_INTERFACE = auto()
    T_TRAIT = auto()
    T_EXTENDS = auto()
    T_IMPLEMENTS = auto()
    T_PUBLIC = auto()
    T_PRIVATE = auto()
    T_PROTECTED = auto()
    T_STATIC = auto()
    T_FINAL = auto()
    T_ABSTRACT = auto()
    T_CONST = auto()
    T_NEW = auto()
    T_INSTANCEOF = auto()
    T_TRY = auto()
    T_CATCH = auto()
    T_FINALLY = auto()
    T_THROW = auto()
    T_ECHO = auto()
    T_PRINT = auto()
    T_INCLUDE = auto()
    T_INCLUDE_ONCE = auto()
    T_REQUIRE = auto()
    T_REQUIRE_ONCE = auto()
    T_GLOBAL = auto()
    T_ARRAY = auto()
    T_LIST = auto()
    T_EVAL = auto()
    T_ISSET = auto()
    T_UNSET = auto()
    T_EMPTY = auto()
    T_EXIT = auto()
    T_DIE = auto()
    T_NAMESPACE = auto()
    T_USE = auto()
    T_AS = auto()
    T_PLUS = auto()
    T_MINUS = auto()
    T_MUL = auto()
    T_DIV = auto()
    T_MOD = auto()
    T_POW = auto()
    T_CONCAT = auto()
    T_ASSIGN = auto()
    T_PLUS_EQUAL = auto()
    T_MINUS_EQUAL = auto()
    T_MUL_EQUAL = auto()
    T_DIV_EQUAL = auto()
    T_CONCAT_EQUAL = auto()
    T_AND = auto()
    T_OR = auto()
    T_XOR = auto()
    T_NOT = auto()
    T_BITWISE_AND = auto()
    T_BITWISE_OR = auto()
    T_BITWISE_XOR = auto()
    T_BITWISE_NOT = auto()
    T_SL = auto()
    T_SR = auto()
    T_IS_EQUAL = auto()
    T_IS_NOT_EQUAL = auto()
    T_IS_IDENTICAL = auto()
    T_IS_NOT_IDENTICAL = auto()
    T_IS_SMALLER = auto()
    T_IS_GREATER = auto()
    T_IS_SMALLER_OR_EQUAL = auto()
    T_IS_GREATER_OR_EQUAL = auto()
    T_SPACESHIP = auto()
    T_COALESCE = auto()
    T_QUESTION = auto()
    T_COLON = auto()
    T_DOUBLE_COLON = auto()
    T_OBJECT_OPERATOR = auto()
    T_DOUBLE_ARROW = auto()
    T_INC = auto()
    T_DEC = auto()
    T_LPAREN = auto()
    T_RPAREN = auto()
    T_LBRACE = auto()
    T_RBRACE = auto()
    T_LBRACKET = auto()
    T_RBRACKET = auto()
    T_SEMICOLON = auto()
    T_COMMA = auto()
    T_AT = auto()
    T_DOLLAR = auto()
    T_BACKTICK = auto()
    T_OPEN_TAG = auto()
    T_CLOSE_TAG = auto()
    T_INLINE_HTML = auto()
    T_COMMENT = auto()
    T_DOC_COMMENT = auto()
    T_WHITESPACE = auto()
    T_EOF = auto()
    T_UNKNOWN = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int


class PHPLexer:
    KEYWORDS = {
        'if': TokenType.T_IF, 'else': TokenType.T_ELSE, 'elseif': TokenType.T_ELSEIF,
        'while': TokenType.T_WHILE, 'for': TokenType.T_FOR, 'foreach': TokenType.T_FOREACH,
        'switch': TokenType.T_SWITCH, 'case': TokenType.T_CASE, 'default': TokenType.T_DEFAULT,
        'break': TokenType.T_BREAK, 'continue': TokenType.T_CONTINUE, 'return': TokenType.T_RETURN,
        'function': TokenType.T_FUNCTION, 'class': TokenType.T_CLASS, 'interface': TokenType.T_INTERFACE,
        'trait': TokenType.T_TRAIT, 'extends': TokenType.T_EXTENDS, 'implements': TokenType.T_IMPLEMENTS,
        'public': TokenType.T_PUBLIC, 'private': TokenType.T_PRIVATE, 'protected': TokenType.T_PROTECTED,
        'static': TokenType.T_STATIC, 'final': TokenType.T_FINAL, 'abstract': TokenType.T_ABSTRACT,
        'const': TokenType.T_CONST, 'new': TokenType.T_NEW, 'instanceof': TokenType.T_INSTANCEOF,
        'try': TokenType.T_TRY, 'catch': TokenType.T_CATCH, 'finally': TokenType.T_FINALLY,
        'throw': TokenType.T_THROW, 'echo': TokenType.T_ECHO, 'print': TokenType.T_PRINT,
        'include': TokenType.T_INCLUDE, 'include_once': TokenType.T_INCLUDE_ONCE,
        'require': TokenType.T_REQUIRE, 'require_once': TokenType.T_REQUIRE_ONCE,
        'global': TokenType.T_GLOBAL, 'array': TokenType.T_ARRAY, 'list': TokenType.T_LIST,
        'eval': TokenType.T_EVAL, 'isset': TokenType.T_ISSET, 'unset': TokenType.T_UNSET,
        'empty': TokenType.T_EMPTY, 'exit': TokenType.T_EXIT, 'die': TokenType.T_DIE,
        'namespace': TokenType.T_NAMESPACE, 'use': TokenType.T_USE, 'as': TokenType.T_AS,
        'and': TokenType.T_AND, 'or': TokenType.T_OR, 'xor': TokenType.T_XOR,
    }

    def __init__(self, code: str):
        self.code = code
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
        self.in_php = False

    def peek(self, offset: int = 0) -> str:
        pos = self.pos + offset
        return self.code[pos] if pos < len(self.code) else ''

    def peek_str(self, length: int) -> str:
        return self.code[self.pos:self.pos + length]

    def advance(self, count: int = 1) -> str:
        result = self.code[self.pos:self.pos + count]
        for c in result:
            if c == '\n':
                self.line += 1
                self.column = 1
            else:
                self.column += 1
        self.pos += count
        return result

    def skip_whitespace(self) -> Optional[Token]:
        start_line, start_col = self.line, self.column
        ws = ''
        while self.pos < len(self.code) and self.peek() in ' \t\n\r':
            ws += self.advance()
        return Token(TokenType.T_WHITESPACE, ws, start_line, start_col) if ws else None

    def read_string(self, quote: str) -> Token:
        start_line, start_col = self.line, self.column
        self.advance()
        value = ''
        while self.pos < len(self.code):
            c = self.peek()
            if c == '\\' and self.peek(1) in (quote, '\\', 'n', 'r', 't', '$'):
                value += self.advance(2)
            elif c == quote:
                self.advance()
                break
            else:
                value += self.advance()
        return Token(TokenType.T_CONSTANT_ENCAPSED_STRING, quote + value + quote, start_line, start_col)

    def read_number(self) -> Token:
        start_line, start_col = self.line, self.column
        value = ''
        is_float = False
        if self.peek() == '0' and self.peek(1) in 'xX':
            value = self.advance(2)
            while self.peek() in '0123456789abcdefABCDEF':
                value += self.advance()
            return Token(TokenType.T_LNUMBER, value, start_line, start_col)
        while self.peek() in '0123456789':
            value += self.advance()
        if self.peek() == '.' and self.peek(1) in '0123456789':
            is_float = True
            value += self.advance()
            while self.peek() in '0123456789':
                value += self.advance()
        if self.peek() in 'eE':
            is_float = True
            value += self.advance()
            if self.peek() in '+-':
                value += self.advance()
            while self.peek() in '0123456789':
                value += self.advance()
        return Token(TokenType.T_DNUMBER if is_float else TokenType.T_LNUMBER, value, start_line, start_col)

    def read_identifier(self) -> Token:
        start_line, start_col = self.line, self.column
        value = ''
        while self.peek() and (self.peek().isalnum() or self.peek() == '_'):
            value += self.advance()
        lower = value.lower()
        return Token(self.KEYWORDS.get(lower, TokenType.T_STRING), value, start_line, start_col)

    def read_variable(self) -> Token:
        start_line, start_col = self.line, self.column
        self.advance()
        if self.peek() == '{':
            self.advance()
            value = '${'
            brace_count = 1
            while self.pos < len(self.code) and brace_count > 0:
                c = self.advance()
                value += c
                if c == '{': brace_count += 1
                elif c == '}': brace_count -= 1
            return Token(TokenType.T_VARIABLE, value, start_line, start_col)
        value = '$'
        while self.peek() and (self.peek().isalnum() or self.peek() == '_'):
            value += self.advance()
        return Token(TokenType.T_VARIABLE, value, start_line, start_col)

    def read_comment(self) -> Token:
        start_line, start_col = self.line, self.column
        if self.peek_str(2) == '//':
            value = self.advance(2)
            while self.pos < len(self.code) and self.peek() != '\n':
                value += self.advance()
            return Token(TokenType.T_COMMENT, value, start_line, start_col)
        elif self.peek_str(2) == '/*':
            is_doc = self.peek_str(3) == '/**'
            value = self.advance(2)
            while self.pos < len(self.code) and self.peek_str(2) != '*/':
                value += self.advance()
            if self.peek_str(2) == '*/':
                value += self.advance(2)
            return Token(TokenType.T_DOC_COMMENT if is_doc else TokenType.T_COMMENT, value, start_line, start_col)
        elif self.peek() == '#':
            value = self.advance()
            while self.pos < len(self.code) and self.peek() != '\n':
                value += self.advance()
            return Token(TokenType.T_COMMENT, value, start_line, start_col)
        return None

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.code):
            start_line, start_col = self.line, self.column
            if not self.in_php:
                if self.peek_str(5) == '<?php':
                    self.tokens.append(Token(TokenType.T_OPEN_TAG, self.advance(5), start_line, start_col))
                    self.in_php = True
                elif self.peek_str(2) == '<?':
                    self.tokens.append(Token(TokenType.T_OPEN_TAG, self.advance(2), start_line, start_col))
                    self.in_php = True
                else:
                    html = ''
                    while self.pos < len(self.code) and self.peek_str(2) != '<?':
                        html += self.advance()
                    if html:
                        self.tokens.append(Token(TokenType.T_INLINE_HTML, html, start_line, start_col))
                continue
            if self.peek_str(2) == '?>':
                self.tokens.append(Token(TokenType.T_CLOSE_TAG, self.advance(2), start_line, start_col))
                self.in_php = False
                continue
            if self.skip_whitespace():
                continue
            if self.peek_str(2) in ('//', '/*') or self.peek() == '#':
                if self.read_comment():
                    continue
            c = self.peek()
            if c in '"\'':
                self.tokens.append(self.read_string(c))
                continue
            if c == '`':
                self.tokens.append(Token(TokenType.T_BACKTICK, self.advance(), start_line, start_col))
                continue
            if c.isdigit() or (c == '.' and self.peek(1).isdigit()):
                self.tokens.append(self.read_number())
                continue
            if c == '$':
                self.tokens.append(self.read_variable())
                continue
            if c.isalpha() or c == '_':
                self.tokens.append(self.read_identifier())
                continue
            two, three = self.peek_str(2), self.peek_str(3)
            if three == '===':
                self.tokens.append(Token(TokenType.T_IS_IDENTICAL, self.advance(3), start_line, start_col))
                continue
            if three == '!==':
                self.tokens.append(Token(TokenType.T_IS_NOT_IDENTICAL, self.advance(3), start_line, start_col))
                continue
            if three == '<=>':
                self.tokens.append(Token(TokenType.T_SPACESHIP, self.advance(3), start_line, start_col))
                continue
            ops2 = {'==': TokenType.T_IS_EQUAL, '!=': TokenType.T_IS_NOT_EQUAL, '<=': TokenType.T_IS_SMALLER_OR_EQUAL,
                    '>=': TokenType.T_IS_GREATER_OR_EQUAL, '&&': TokenType.T_AND, '||': TokenType.T_OR,
                    '??': TokenType.T_COALESCE, '++': TokenType.T_INC, '--': TokenType.T_DEC,
                    '->': TokenType.T_OBJECT_OPERATOR, '=>': TokenType.T_DOUBLE_ARROW, '::': TokenType.T_DOUBLE_COLON,
                    '<<': TokenType.T_SL, '>>': TokenType.T_SR, '**': TokenType.T_POW,
                    '+=': TokenType.T_PLUS_EQUAL, '-=': TokenType.T_MINUS_EQUAL, '*=': TokenType.T_MUL_EQUAL,
                    '/=': TokenType.T_DIV_EQUAL, '.=': TokenType.T_CONCAT_EQUAL}
            if two in ops2:
                self.tokens.append(Token(ops2[two], self.advance(2), start_line, start_col))
                continue
            ops1 = {'+': TokenType.T_PLUS, '-': TokenType.T_MINUS, '*': TokenType.T_MUL, '/': TokenType.T_DIV,
                    '%': TokenType.T_MOD, '.': TokenType.T_CONCAT, '=': TokenType.T_ASSIGN,
                    '<': TokenType.T_IS_SMALLER, '>': TokenType.T_IS_GREATER, '!': TokenType.T_NOT,
                    '&': TokenType.T_BITWISE_AND, '|': TokenType.T_BITWISE_OR, '^': TokenType.T_BITWISE_XOR,
                    '~': TokenType.T_BITWISE_NOT, '?': TokenType.T_QUESTION, ':': TokenType.T_COLON,
                    '(': TokenType.T_LPAREN, ')': TokenType.T_RPAREN, '{': TokenType.T_LBRACE,
                    '}': TokenType.T_RBRACE, '[': TokenType.T_LBRACKET, ']': TokenType.T_RBRACKET,
                    ';': TokenType.T_SEMICOLON, ',': TokenType.T_COMMA, '@': TokenType.T_AT}
            if c in ops1:
                self.tokens.append(Token(ops1[c], self.advance(), start_line, start_col))
                continue
            self.tokens.append(Token(TokenType.T_UNKNOWN, self.advance(), start_line, start_col))
        self.tokens.append(Token(TokenType.T_EOF, '', self.line, self.column))
        return self.tokens


class NodeType(Enum):
    PROGRAM = auto()
    FUNCTION_DECL = auto()
    CLASS_DECL = auto()
    METHOD_DECL = auto()
    PROPERTY_DECL = auto()
    PARAMETER = auto()
    STMT_EXPR = auto()
    STMT_IF = auto()
    STMT_WHILE = auto()
    STMT_FOR = auto()
    STMT_FOREACH = auto()
    STMT_SWITCH = auto()
    STMT_CASE = auto()
    STMT_RETURN = auto()
    STMT_ECHO = auto()
    STMT_PRINT = auto()
    STMT_TRY = auto()
    STMT_CATCH = auto()
    STMT_THROW = auto()
    STMT_GLOBAL = auto()
    STMT_BLOCK = auto()
    EXPR_ASSIGN = auto()
    EXPR_BINARY = auto()
    EXPR_UNARY = auto()
    EXPR_TERNARY = auto()
    EXPR_CALL = auto()
    EXPR_METHOD_CALL = auto()
    EXPR_STATIC_CALL = auto()
    EXPR_NEW = auto()
    EXPR_ARRAY = auto()
    EXPR_ARRAY_ACCESS = auto()
    EXPR_PROPERTY_ACCESS = auto()
    EXPR_STATIC_PROPERTY = auto()
    EXPR_VARIABLE = auto()
    EXPR_LITERAL = auto()
    EXPR_INCLUDE = auto()
    EXPR_EVAL = auto()
    EXPR_ISSET = auto()
    EXPR_EMPTY = auto()
    EXPR_EXIT = auto()
    EXPR_CAST = auto()
    EXPR_INSTANCEOF = auto()
    EXPR_CLOSURE = auto()


@dataclass
class ASTNode:
    type: NodeType
    value: Any = None
    children: List['ASTNode'] = field(default_factory=list)
    line: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def add_child(self, node: 'ASTNode'):
        self.children.append(node)
        return self

    def find_all(self, node_type: NodeType) -> Iterator['ASTNode']:
        if self.type == node_type:
            yield self
        for child in self.children:
            yield from child.find_all(node_type)


class PHPParser:
    def __init__(self, tokens: List[Token]):
        self.tokens = [t for t in tokens if t.type not in (TokenType.T_WHITESPACE, TokenType.T_COMMENT)]
        self.pos = 0

    def current(self) -> Token:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else Token(TokenType.T_EOF, '', 0, 0)

    def peek(self, offset: int = 0) -> Token:
        pos = self.pos + offset
        return self.tokens[pos] if pos < len(self.tokens) else Token(TokenType.T_EOF, '', 0, 0)

    def advance(self) -> Token:
        token = self.current()
        self.pos += 1
        return token

    def expect(self, token_type: TokenType) -> Token:
        if self.current().type != token_type:
            raise SyntaxError(f"Expected {token_type.name}, got {self.current().type.name}")
        return self.advance()

    def match(self, *types: TokenType) -> bool:
        return self.current().type in types

    def parse(self) -> ASTNode:
        program = ASTNode(NodeType.PROGRAM)
        while not self.match(TokenType.T_EOF):
            if self.match(TokenType.T_OPEN_TAG, TokenType.T_CLOSE_TAG, TokenType.T_INLINE_HTML):
                self.advance()
                continue
            stmt = self.parse_statement()
            if stmt:
                program.add_child(stmt)
        return program

    def parse_statement(self) -> Optional[ASTNode]:
        if self.match(TokenType.T_FUNCTION): return self.parse_function()
        if self.match(TokenType.T_CLASS): return self.parse_class()
        if self.match(TokenType.T_IF): return self.parse_if()
        if self.match(TokenType.T_WHILE): return self.parse_while()
        if self.match(TokenType.T_FOR): return self.parse_for()
        if self.match(TokenType.T_FOREACH): return self.parse_foreach()
        if self.match(TokenType.T_SWITCH): return self.parse_switch()
        if self.match(TokenType.T_RETURN): return self.parse_return()
        if self.match(TokenType.T_ECHO): return self.parse_echo()
        if self.match(TokenType.T_PRINT): return self.parse_print()
        if self.match(TokenType.T_TRY): return self.parse_try()
        if self.match(TokenType.T_THROW): return self.parse_throw()
        if self.match(TokenType.T_GLOBAL): return self.parse_global()
        if self.match(TokenType.T_LBRACE): return self.parse_block()
        if self.match(TokenType.T_SEMICOLON):
            self.advance()
            return None
        return self.parse_expression_statement()

    def parse_function(self) -> ASTNode:
        self.expect(TokenType.T_FUNCTION)
        name = self.expect(TokenType.T_STRING)
        node = ASTNode(NodeType.FUNCTION_DECL, name.value, line=name.line)
        self.expect(TokenType.T_LPAREN)
        while not self.match(TokenType.T_RPAREN):
            node.add_child(self.parse_parameter())
            if self.match(TokenType.T_COMMA): self.advance()
        self.expect(TokenType.T_RPAREN)
        node.add_child(self.parse_block())
        return node

    def parse_parameter(self) -> ASTNode:
        node = ASTNode(NodeType.PARAMETER)
        if self.match(TokenType.T_STRING):
            node.attributes['type'] = self.advance().value
        if self.match(TokenType.T_VARIABLE):
            node.value = self.advance().value
        if self.match(TokenType.T_ASSIGN):
            self.advance()
            node.add_child(self.parse_expression())
        return node

    def parse_class(self) -> ASTNode:
        self.expect(TokenType.T_CLASS)
        name = self.expect(TokenType.T_STRING)
        node = ASTNode(NodeType.CLASS_DECL, name.value, line=name.line)
        if self.match(TokenType.T_EXTENDS):
            self.advance()
            node.attributes['extends'] = self.expect(TokenType.T_STRING).value
        if self.match(TokenType.T_IMPLEMENTS):
            self.advance()
            interfaces = [self.expect(TokenType.T_STRING).value]
            while self.match(TokenType.T_COMMA):
                self.advance()
                interfaces.append(self.expect(TokenType.T_STRING).value)
            node.attributes['implements'] = interfaces
        self.expect(TokenType.T_LBRACE)
        while not self.match(TokenType.T_RBRACE, TokenType.T_EOF):
            member = self.parse_class_member()
            if member: node.add_child(member)
        self.expect(TokenType.T_RBRACE)
        return node

    def parse_class_member(self) -> Optional[ASTNode]:
        visibility, is_static = None, False
        while self.match(TokenType.T_PUBLIC, TokenType.T_PRIVATE, TokenType.T_PROTECTED, TokenType.T_STATIC):
            if self.match(TokenType.T_STATIC): is_static = True
            else: visibility = self.current().type.name.lower().replace('t_', '')
            self.advance()
        if self.match(TokenType.T_FUNCTION):
            method = self.parse_function()
            method.type = NodeType.METHOD_DECL
            method.attributes['visibility'] = visibility or 'public'
            method.attributes['static'] = is_static
            return method
        if self.match(TokenType.T_VARIABLE):
            prop = ASTNode(NodeType.PROPERTY_DECL, self.advance().value)
            prop.attributes['visibility'] = visibility or 'public'
            prop.attributes['static'] = is_static
            if self.match(TokenType.T_ASSIGN):
                self.advance()
                prop.add_child(self.parse_expression())
            self.expect(TokenType.T_SEMICOLON)
            return prop
        return None

    def parse_block(self) -> ASTNode:
        self.expect(TokenType.T_LBRACE)
        node = ASTNode(NodeType.STMT_BLOCK)
        while not self.match(TokenType.T_RBRACE, TokenType.T_EOF):
            stmt = self.parse_statement()
            if stmt: node.add_child(stmt)
        self.expect(TokenType.T_RBRACE)
        return node

    def parse_if(self) -> ASTNode:
        token = self.expect(TokenType.T_IF)
        node = ASTNode(NodeType.STMT_IF, line=token.line)
        self.expect(TokenType.T_LPAREN)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        node.add_child(self.parse_block() if self.match(TokenType.T_LBRACE) else self.parse_statement())
        if self.match(TokenType.T_ELSE):
            self.advance()
            if self.match(TokenType.T_IF): node.add_child(self.parse_if())
            else: node.add_child(self.parse_block() if self.match(TokenType.T_LBRACE) else self.parse_statement())
        return node

    def parse_while(self) -> ASTNode:
        token = self.expect(TokenType.T_WHILE)
        node = ASTNode(NodeType.STMT_WHILE, line=token.line)
        self.expect(TokenType.T_LPAREN)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        node.add_child(self.parse_block() if self.match(TokenType.T_LBRACE) else self.parse_statement())
        return node

    def parse_for(self) -> ASTNode:
        token = self.expect(TokenType.T_FOR)
        node = ASTNode(NodeType.STMT_FOR, line=token.line)
        self.expect(TokenType.T_LPAREN)
        if not self.match(TokenType.T_SEMICOLON): node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        if not self.match(TokenType.T_SEMICOLON): node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        if not self.match(TokenType.T_RPAREN): node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        node.add_child(self.parse_block() if self.match(TokenType.T_LBRACE) else self.parse_statement())
        return node

    def parse_foreach(self) -> ASTNode:
        token = self.expect(TokenType.T_FOREACH)
        node = ASTNode(NodeType.STMT_FOREACH, line=token.line)
        self.expect(TokenType.T_LPAREN)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_AS)
        first = self.parse_expression()
        if self.match(TokenType.T_DOUBLE_ARROW):
            self.advance()
            node.attributes['key'] = first
            node.add_child(self.parse_expression())
        else:
            node.add_child(first)
        self.expect(TokenType.T_RPAREN)
        node.add_child(self.parse_block() if self.match(TokenType.T_LBRACE) else self.parse_statement())
        return node

    def parse_switch(self) -> ASTNode:
        token = self.expect(TokenType.T_SWITCH)
        node = ASTNode(NodeType.STMT_SWITCH, line=token.line)
        self.expect(TokenType.T_LPAREN)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        self.expect(TokenType.T_LBRACE)
        while not self.match(TokenType.T_RBRACE, TokenType.T_EOF):
            if self.match(TokenType.T_CASE):
                self.advance()
                case = ASTNode(NodeType.STMT_CASE)
                case.add_child(self.parse_expression())
                self.expect(TokenType.T_COLON)
                while not self.match(TokenType.T_CASE, TokenType.T_DEFAULT, TokenType.T_RBRACE, TokenType.T_EOF):
                    stmt = self.parse_statement()
                    if stmt: case.add_child(stmt)
                node.add_child(case)
            elif self.match(TokenType.T_DEFAULT):
                self.advance()
                self.expect(TokenType.T_COLON)
                default = ASTNode(NodeType.STMT_CASE)
                default.attributes['default'] = True
                while not self.match(TokenType.T_CASE, TokenType.T_RBRACE, TokenType.T_EOF):
                    stmt = self.parse_statement()
                    if stmt: default.add_child(stmt)
                node.add_child(default)
            else: break
        self.expect(TokenType.T_RBRACE)
        return node

    def parse_return(self) -> ASTNode:
        token = self.expect(TokenType.T_RETURN)
        node = ASTNode(NodeType.STMT_RETURN, line=token.line)
        if not self.match(TokenType.T_SEMICOLON): node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        return node

    def parse_echo(self) -> ASTNode:
        token = self.expect(TokenType.T_ECHO)
        node = ASTNode(NodeType.STMT_ECHO, line=token.line)
        node.add_child(self.parse_expression())
        while self.match(TokenType.T_COMMA):
            self.advance()
            node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        return node

    def parse_print(self) -> ASTNode:
        token = self.expect(TokenType.T_PRINT)
        node = ASTNode(NodeType.STMT_PRINT, line=token.line)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        return node

    def parse_try(self) -> ASTNode:
        token = self.expect(TokenType.T_TRY)
        node = ASTNode(NodeType.STMT_TRY, line=token.line)
        node.add_child(self.parse_block())
        while self.match(TokenType.T_CATCH):
            self.advance()
            catch = ASTNode(NodeType.STMT_CATCH)
            self.expect(TokenType.T_LPAREN)
            if self.match(TokenType.T_STRING): catch.attributes['type'] = self.advance().value
            if self.match(TokenType.T_VARIABLE): catch.value = self.advance().value
            self.expect(TokenType.T_RPAREN)
            catch.add_child(self.parse_block())
            node.add_child(catch)
        return node

    def parse_throw(self) -> ASTNode:
        token = self.expect(TokenType.T_THROW)
        node = ASTNode(NodeType.STMT_THROW, line=token.line)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        return node

    def parse_global(self) -> ASTNode:
        token = self.expect(TokenType.T_GLOBAL)
        node = ASTNode(NodeType.STMT_GLOBAL, line=token.line)
        node.add_child(self.parse_expression())
        while self.match(TokenType.T_COMMA):
            self.advance()
            node.add_child(self.parse_expression())
        self.expect(TokenType.T_SEMICOLON)
        return node

    def parse_expression_statement(self) -> Optional[ASTNode]:
        expr = self.parse_expression()
        if expr:
            node = ASTNode(NodeType.STMT_EXPR, line=expr.line)
            node.add_child(expr)
            if self.match(TokenType.T_SEMICOLON): self.advance()
            return node
        return None

    def parse_expression(self) -> ASTNode:
        return self.parse_assignment()

    def parse_assignment(self) -> ASTNode:
        left = self.parse_ternary()
        if self.match(TokenType.T_ASSIGN, TokenType.T_PLUS_EQUAL, TokenType.T_MINUS_EQUAL,
                      TokenType.T_MUL_EQUAL, TokenType.T_DIV_EQUAL, TokenType.T_CONCAT_EQUAL):
            op = self.advance()
            right = self.parse_assignment()
            node = ASTNode(NodeType.EXPR_ASSIGN, op.value, line=op.line)
            node.add_child(left)
            node.add_child(right)
            return node
        return left

    def parse_ternary(self) -> ASTNode:
        cond = self.parse_or()
        if self.match(TokenType.T_QUESTION):
            self.advance()
            then = self.parse_expression()
            self.expect(TokenType.T_COLON)
            els = self.parse_ternary()
            node = ASTNode(NodeType.EXPR_TERNARY, line=cond.line)
            node.add_child(cond)
            node.add_child(then)
            node.add_child(els)
            return node
        if self.match(TokenType.T_COALESCE):
            self.advance()
            right = self.parse_ternary()
            node = ASTNode(NodeType.EXPR_BINARY, '??', line=cond.line)
            node.add_child(cond)
            node.add_child(right)
            return node
        return cond

    def parse_or(self) -> ASTNode:
        left = self.parse_and()
        while self.match(TokenType.T_OR):
            op = self.advance()
            right = self.parse_and()
            node = ASTNode(NodeType.EXPR_BINARY, '||', line=op.line)
            node.add_child(left)
            node.add_child(right)
            left = node
        return left

    def parse_and(self) -> ASTNode:
        left = self.parse_comparison()
        while self.match(TokenType.T_AND):
            op = self.advance()
            right = self.parse_comparison()
            node = ASTNode(NodeType.EXPR_BINARY, '&&', line=op.line)
            node.add_child(left)
            node.add_child(right)
            left = node
        return left

    def parse_comparison(self) -> ASTNode:
        left = self.parse_additive()
        while self.match(TokenType.T_IS_EQUAL, TokenType.T_IS_NOT_EQUAL, TokenType.T_IS_IDENTICAL,
                        TokenType.T_IS_NOT_IDENTICAL, TokenType.T_IS_SMALLER, TokenType.T_IS_GREATER,
                        TokenType.T_IS_SMALLER_OR_EQUAL, TokenType.T_IS_GREATER_OR_EQUAL):
            op = self.advance()
            right = self.parse_additive()
            node = ASTNode(NodeType.EXPR_BINARY, op.value, line=op.line)
            node.add_child(left)
            node.add_child(right)
            left = node
        return left

    def parse_additive(self) -> ASTNode:
        left = self.parse_multiplicative()
        while self.match(TokenType.T_PLUS, TokenType.T_MINUS, TokenType.T_CONCAT):
            op = self.advance()
            right = self.parse_multiplicative()
            node = ASTNode(NodeType.EXPR_BINARY, op.value, line=op.line)
            node.add_child(left)
            node.add_child(right)
            left = node
        return left

    def parse_multiplicative(self) -> ASTNode:
        left = self.parse_unary()
        while self.match(TokenType.T_MUL, TokenType.T_DIV, TokenType.T_MOD):
            op = self.advance()
            right = self.parse_unary()
            node = ASTNode(NodeType.EXPR_BINARY, op.value, line=op.line)
            node.add_child(left)
            node.add_child(right)
            left = node
        return left

    def parse_unary(self) -> ASTNode:
        if self.match(TokenType.T_NOT, TokenType.T_MINUS, TokenType.T_PLUS, TokenType.T_INC, TokenType.T_DEC, TokenType.T_AT):
            op = self.advance()
            operand = self.parse_unary()
            node = ASTNode(NodeType.EXPR_UNARY, op.value, line=op.line)
            node.add_child(operand)
            return node
        return self.parse_postfix()

    def parse_postfix(self) -> ASTNode:
        left = self.parse_primary()
        while True:
            if self.match(TokenType.T_LPAREN):
                self.advance()
                node = ASTNode(NodeType.EXPR_CALL, left.value if left.type == NodeType.EXPR_VARIABLE else None, line=left.line)
                node.add_child(left)
                while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
                    node.add_child(self.parse_expression())
                    if self.match(TokenType.T_COMMA): self.advance()
                self.expect(TokenType.T_RPAREN)
                left = node
            elif self.match(TokenType.T_LBRACKET):
                self.advance()
                node = ASTNode(NodeType.EXPR_ARRAY_ACCESS, line=left.line)
                node.add_child(left)
                if not self.match(TokenType.T_RBRACKET): node.add_child(self.parse_expression())
                self.expect(TokenType.T_RBRACKET)
                left = node
            elif self.match(TokenType.T_OBJECT_OPERATOR):
                self.advance()
                member = self.advance()
                if self.match(TokenType.T_LPAREN):
                    self.advance()
                    node = ASTNode(NodeType.EXPR_METHOD_CALL, member.value, line=left.line)
                    node.add_child(left)
                    while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
                        node.add_child(self.parse_expression())
                        if self.match(TokenType.T_COMMA): self.advance()
                    self.expect(TokenType.T_RPAREN)
                else:
                    node = ASTNode(NodeType.EXPR_PROPERTY_ACCESS, member.value, line=left.line)
                    node.add_child(left)
                left = node
            elif self.match(TokenType.T_DOUBLE_COLON):
                self.advance()
                member = self.advance()
                if self.match(TokenType.T_LPAREN):
                    self.advance()
                    node = ASTNode(NodeType.EXPR_STATIC_CALL, member.value, line=left.line)
                    node.add_child(left)
                    while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
                        node.add_child(self.parse_expression())
                        if self.match(TokenType.T_COMMA): self.advance()
                    self.expect(TokenType.T_RPAREN)
                else:
                    node = ASTNode(NodeType.EXPR_STATIC_PROPERTY, member.value, line=left.line)
                    node.add_child(left)
                left = node
            elif self.match(TokenType.T_INC, TokenType.T_DEC):
                op = self.advance()
                node = ASTNode(NodeType.EXPR_UNARY, op.value + '_post', line=left.line)
                node.add_child(left)
                left = node
            else:
                break
        return left

    def parse_primary(self) -> ASTNode:
        if self.match(TokenType.T_VARIABLE):
            t = self.advance()
            return ASTNode(NodeType.EXPR_VARIABLE, t.value, line=t.line)
        if self.match(TokenType.T_LNUMBER, TokenType.T_DNUMBER):
            t = self.advance()
            return ASTNode(NodeType.EXPR_LITERAL, t.value, line=t.line, attributes={'type': 'number'})
        if self.match(TokenType.T_CONSTANT_ENCAPSED_STRING):
            t = self.advance()
            return ASTNode(NodeType.EXPR_LITERAL, t.value, line=t.line, attributes={'type': 'string'})
        if self.match(TokenType.T_STRING):
            t = self.advance()
            return ASTNode(NodeType.EXPR_LITERAL, t.value, line=t.line, attributes={'type': 'identifier'})
        if self.match(TokenType.T_ARRAY): return self.parse_array()
        if self.match(TokenType.T_LBRACKET): return self.parse_short_array()
        if self.match(TokenType.T_NEW): return self.parse_new()
        if self.match(TokenType.T_EVAL): return self.parse_eval()
        if self.match(TokenType.T_INCLUDE, TokenType.T_INCLUDE_ONCE, TokenType.T_REQUIRE, TokenType.T_REQUIRE_ONCE):
            return self.parse_include()
        if self.match(TokenType.T_ISSET): return self.parse_isset()
        if self.match(TokenType.T_EMPTY): return self.parse_empty()
        if self.match(TokenType.T_EXIT, TokenType.T_DIE): return self.parse_exit()
        if self.match(TokenType.T_LPAREN):
            self.advance()
            expr = self.parse_expression()
            self.expect(TokenType.T_RPAREN)
            return expr
        t = self.advance()
        return ASTNode(NodeType.EXPR_LITERAL, t.value, line=t.line)

    def parse_array(self) -> ASTNode:
        t = self.expect(TokenType.T_ARRAY)
        self.expect(TokenType.T_LPAREN)
        node = ASTNode(NodeType.EXPR_ARRAY, line=t.line)
        while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
            item = self.parse_expression()
            if self.match(TokenType.T_DOUBLE_ARROW):
                self.advance()
                value = self.parse_expression()
                item.attributes['key'] = item.value
                item = value
            node.add_child(item)
            if self.match(TokenType.T_COMMA): self.advance()
        self.expect(TokenType.T_RPAREN)
        return node

    def parse_short_array(self) -> ASTNode:
        t = self.expect(TokenType.T_LBRACKET)
        node = ASTNode(NodeType.EXPR_ARRAY, line=t.line)
        while not self.match(TokenType.T_RBRACKET, TokenType.T_EOF):
            item = self.parse_expression()
            if self.match(TokenType.T_DOUBLE_ARROW):
                self.advance()
                value = self.parse_expression()
                item.attributes['key'] = item.value
                item = value
            node.add_child(item)
            if self.match(TokenType.T_COMMA): self.advance()
        self.expect(TokenType.T_RBRACKET)
        return node

    def parse_new(self) -> ASTNode:
        t = self.expect(TokenType.T_NEW)
        cls = self.advance()
        node = ASTNode(NodeType.EXPR_NEW, cls.value, line=t.line)
        if self.match(TokenType.T_LPAREN):
            self.advance()
            while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
                node.add_child(self.parse_expression())
                if self.match(TokenType.T_COMMA): self.advance()
            self.expect(TokenType.T_RPAREN)
        return node

    def parse_eval(self) -> ASTNode:
        t = self.expect(TokenType.T_EVAL)
        self.expect(TokenType.T_LPAREN)
        node = ASTNode(NodeType.EXPR_EVAL, line=t.line)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        return node

    def parse_include(self) -> ASTNode:
        t = self.advance()
        node = ASTNode(NodeType.EXPR_INCLUDE, t.value, line=t.line)
        if self.match(TokenType.T_LPAREN):
            self.advance()
            node.add_child(self.parse_expression())
            self.expect(TokenType.T_RPAREN)
        else:
            node.add_child(self.parse_expression())
        return node

    def parse_isset(self) -> ASTNode:
        t = self.expect(TokenType.T_ISSET)
        self.expect(TokenType.T_LPAREN)
        node = ASTNode(NodeType.EXPR_ISSET, line=t.line)
        while not self.match(TokenType.T_RPAREN, TokenType.T_EOF):
            node.add_child(self.parse_expression())
            if self.match(TokenType.T_COMMA): self.advance()
        self.expect(TokenType.T_RPAREN)
        return node

    def parse_empty(self) -> ASTNode:
        t = self.expect(TokenType.T_EMPTY)
        self.expect(TokenType.T_LPAREN)
        node = ASTNode(NodeType.EXPR_EMPTY, line=t.line)
        node.add_child(self.parse_expression())
        self.expect(TokenType.T_RPAREN)
        return node

    def parse_exit(self) -> ASTNode:
        t = self.advance()
        node = ASTNode(NodeType.EXPR_EXIT, t.value, line=t.line)
        if self.match(TokenType.T_LPAREN):
            self.advance()
            if not self.match(TokenType.T_RPAREN): node.add_child(self.parse_expression())
            self.expect(TokenType.T_RPAREN)
        return node


def parse_php(code: str) -> ASTNode:
    lexer = PHPLexer(code)
    tokens = lexer.tokenize()
    parser = PHPParser(tokens)
    return parser.parse()
