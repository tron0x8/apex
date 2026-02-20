#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from .ts_adapter import TSNode


@dataclass
class CFGBlock:
    id: int
    statements: List[TSNode] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


# builds cfg from tree-sitter ast - handles if/else/for/while/switch/try
class CFGBuilder:

    def __init__(self):
        self._counter = 0
        self._blocks: Dict[int, CFGBlock] = {}

    def _new_block(self, **kwargs) -> CFGBlock:
        block = CFGBlock(id=self._counter, **kwargs)
        self._blocks[block.id] = block
        self._counter += 1
        return block

    def _link(self, src: CFGBlock, dst: CFGBlock):
        if dst.id not in src.successors:
            src.successors.append(dst.id)
        if src.id not in dst.predecessors:
            dst.predecessors.append(src.id)

    def build(self, body_node: TSNode) -> List[CFGBlock]:
        self._counter = 0
        self._blocks = {}

        entry = self._new_block(is_entry=True)
        exit_block = self._new_block(is_exit=True)

        last = self._process_block(body_node, entry, exit_block)
        if last and last.id != exit_block.id:
            self._link(last, exit_block)

        return list(self._blocks.values())

    def _process_block(self, node: TSNode, current: CFGBlock,
                       exit_block: CFGBlock) -> Optional[CFGBlock]:
        for child in node.named_children:
            if child.type == 'if_statement':
                current = self._handle_if(child, current, exit_block)
                if current is None:
                    return None
            elif child.type in ('while_statement', 'for_statement'):
                current = self._handle_loop(child, current, exit_block)
                if current is None:
                    return None
            elif child.type == 'foreach_statement':
                current = self._handle_loop(child, current, exit_block)
                if current is None:
                    return None
            elif child.type == 'try_statement':
                current = self._handle_try(child, current, exit_block)
                if current is None:
                    return None
            elif child.type == 'switch_statement':
                current = self._handle_switch(child, current, exit_block)
                if current is None:
                    return None
            elif child.type == 'return_statement':
                current.statements.append(child)
                self._link(current, exit_block)
                return None
            elif child.type == 'throw_expression':
                current.statements.append(child)
                self._link(current, exit_block)
                return None
            else:
                current.statements.append(child)

        return current

    def _handle_if(self, node: TSNode, current: CFGBlock,
                   exit_block: CFGBlock) -> Optional[CFGBlock]:
        cond = node.child_by_field('condition')
        if cond:
            current.statements.append(cond)

        then_block = self._new_block()
        self._link(current, then_block)

        join_block = self._new_block()

        body = node.child_by_field('body')
        if body:
            then_end = self._process_block(body, then_block, exit_block)
            if then_end:
                self._link(then_end, join_block)
        else:
            self._link(then_block, join_block)

        alt = node.child_by_field('alternative')
        if alt:
            else_block = self._new_block()
            self._link(current, else_block)
            else_end = self._process_block(alt, else_block, exit_block)
            if else_end:
                self._link(else_end, join_block)
        else:
            self._link(current, join_block)

        return join_block

    def _handle_loop(self, node: TSNode, current: CFGBlock,
                     exit_block: CFGBlock) -> Optional[CFGBlock]:
        header = self._new_block()
        self._link(current, header)

        cond = node.child_by_field('condition')
        if cond:
            header.statements.append(cond)

        body_block = self._new_block()
        self._link(header, body_block)

        post_loop = self._new_block()
        self._link(header, post_loop)

        body = node.child_by_field('body')
        if body is None:
            named = node.named_children
            for n in named:
                if n.type == 'compound_statement':
                    body = n
                    break

        if body:
            body_end = self._process_block(body, body_block, exit_block)
            if body_end:
                self._link(body_end, header)
        else:
            self._link(body_block, header)

        return post_loop

    def _handle_try(self, node: TSNode, current: CFGBlock,
                    exit_block: CFGBlock) -> Optional[CFGBlock]:
        try_block = self._new_block()
        self._link(current, try_block)

        join_block = self._new_block()

        named = node.named_children
        try_body = None
        catch_clauses = []
        finally_clause = None

        for child in named:
            if child.type == 'compound_statement' and try_body is None:
                try_body = child
            elif child.type == 'catch_clause':
                catch_clauses.append(child)
            elif child.type == 'finally_clause':
                finally_clause = child

        if try_body:
            try_end = self._process_block(try_body, try_block, exit_block)
            if try_end:
                self._link(try_end, join_block)

        for catch in catch_clauses:
            catch_block = self._new_block()
            self._link(try_block, catch_block)
            catch_body = None
            for c in catch.named_children:
                if c.type == 'compound_statement':
                    catch_body = c
                    break
            if catch_body:
                catch_end = self._process_block(catch_body, catch_block, exit_block)
                if catch_end:
                    self._link(catch_end, join_block)
            else:
                self._link(catch_block, join_block)

        if finally_clause:
            finally_block = self._new_block()
            self._link(join_block, finally_block)
            for c in finally_clause.named_children:
                if c.type == 'compound_statement':
                    fin_end = self._process_block(c, finally_block, exit_block)
                    if fin_end:
                        new_join = self._new_block()
                        self._link(fin_end, new_join)
                        return new_join
            return finally_block

        return join_block

    def _handle_switch(self, node: TSNode, current: CFGBlock,
                       exit_block: CFGBlock) -> Optional[CFGBlock]:
        cond = node.child_by_field('condition')
        if cond:
            current.statements.append(cond)

        post_switch = self._new_block()

        switch_body = None
        for child in node.named_children:
            if child.type == 'switch_block':
                switch_body = child
                break

        if not switch_body:
            self._link(current, post_switch)
            return post_switch

        prev_case_block = None
        for case in switch_body.named_children:
            if case.type in ('case_statement', 'default_statement'):
                case_block = self._new_block()
                self._link(current, case_block)

                if prev_case_block:
                    self._link(prev_case_block, case_block)

                for stmt in case.named_children:
                    if stmt.type == 'break_statement':
                        self._link(case_block, post_switch)
                        prev_case_block = None
                        break
                    else:
                        case_block.statements.append(stmt)
                else:
                    prev_case_block = case_block

        if prev_case_block:
            self._link(prev_case_block, post_switch)

        return post_switch
