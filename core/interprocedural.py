#!/usr/bin/env python3
"""APEX Inter-procedural Analysis - Tracks taint flow across function calls"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    params: List[str] = field(default_factory=list)
    returns_tainted: bool = False
    tainted_params: Set[int] = field(default_factory=set)
    calls: List[str] = field(default_factory=list)
    body: str = ""

@dataclass  
class TaintFlow:
    source_func: str
    source_file: str
    sink_func: str
    sink_file: str
    flow_path: List[str]
    vuln_type: str
    confidence: float

class InterproceduralAnalyzer:
    FUNC_PATTERN = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)\s*\{', re.I)
    CALL_PATTERN = re.compile(r'\b(\w+)\s*\(', re.I)
    RETURN_PATTERN = re.compile(r'return\s+(.+?);', re.I)
    
    SOURCES = {r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_FILES'}
    
    SINKS = {
        'SQL': [r'mysql_query', r'mysqli_query', r'->query'],
        'XSS': [r'\becho\b', r'\bprint\b'],
        'CMD': [r'\bexec\b', r'\bsystem\b', r'shell_exec'],
        'FILE': [r'\binclude\b', r'\brequire\b'],
    }
    
    SANITIZERS = {
        'SQL': [r'intval', r'\(int\)', r'escape_string', r'->prepare'],
        'XSS': [r'htmlspecialchars', r'htmlentities'],
        'CMD': [r'escapeshellarg'],
        'FILE': [r'basename'],
    }

    def __init__(self):
        self.functions = {}
        self.call_graph = {}
        self.reverse_graph = {}
        self.file_functions = {}

    def analyze_file(self, filepath, content):
        functions = []
        for m in self.FUNC_PATTERN.finditer(content):
            fn, ps = m.group(1), m.group(2)
            body = self._extract_body(content, m.end())
            params = [p.group(1) for p in re.finditer(r'\$(\w+)', ps)]
            line = content[:m.start()].count('\n') + 1
            fi = FunctionInfo(fn, filepath, line, params, body=body)
            self._analyze_function(fi)
            functions.append(fi)
            self.functions[fn] = fi
        self.file_functions[filepath] = [f.name for f in functions]
        return functions

    def _extract_body(self, content, start):
        bc, ep = 1, start
        while bc > 0 and ep < len(content):
            if content[ep] == '{': bc += 1
            elif content[ep] == '}': bc -= 1
            ep += 1
        return content[start:ep-1]

    def _analyze_function(self, func):
        body = func.body
        for i, p in enumerate(func.params):
            if re.search(rf'\${p}\b', body):
                for s in self.SOURCES:
                    if re.search(s, body, re.I):
                        func.tainted_params.add(i)
                        break
        for rm in self.RETURN_PATTERN.finditer(body):
            for s in self.SOURCES:
                if re.search(s, rm.group(1), re.I):
                    func.returns_tainted = True
        skip = {'if','while','for','foreach','switch','array','isset','empty'}
        for cm in self.CALL_PATTERN.finditer(body):
            c = cm.group(1)
            if c.lower() not in skip: func.calls.append(c)

    def build_call_graph(self):
        for fn, fi in self.functions.items():
            self.call_graph[fn] = fi.calls
            for c in fi.calls:
                self.reverse_graph.setdefault(c, []).append(fn)

    def find_taint_flows(self):
        flows = []
        for fn, fi in self.functions.items():
            for vt, sinks in self.SINKS.items():
                for sp in sinks:
                    if re.search(sp, fi.body, re.I):
                        flow = self._trace(fi, vt)
                        if flow: flows.append(flow)
        return flows

    def _trace(self, sink_func, vt):
        visited = set()
        def trace(fn, path):
            if fn in visited: return None
            visited.add(fn)
            if fn not in self.functions: return None
            f = self.functions[fn]
            for src in self.SOURCES:
                if re.search(src, f.body, re.I):
                    sans = self.SANITIZERS.get(vt, [])
                    if not any(re.search(s, f.body, re.I) for s in sans):
                        return path + [fn]
            for caller in self.reverse_graph.get(fn, []):
                r = trace(caller, path + [fn])
                if r: return r
            return None
        path = trace(sink_func.name, [])
        if path and len(path) > 1:
            sf = self.functions.get(path[-1])
            if sf:
                return TaintFlow(path[-1], sf.file, sink_func.name, sink_func.file,
                    list(reversed(path)), vt, 0.7 + 0.1*min(len(path),3))
        return None

    def analyze_project(self, project_dir):
        ppath = Path(project_dir)
        php_files = list(ppath.rglob('*.php'))
        print(f"[*] Analyzing {len(php_files)} PHP files...")
        for pf in php_files:
            try:
                content = pf.read_text(encoding='utf-8', errors='ignore')
                self.analyze_file(str(pf), content)
            except: pass
        print(f"[*] Found {len(self.functions)} functions")
        self.build_call_graph()
        flows = self.find_taint_flows()
        print(f"[*] Found {len(flows)} inter-procedural flows")
        return flows

    def get_summary(self):
        return {
            'total_functions': len(self.functions),
            'total_files': len(self.file_functions),
            'tainted_params': sum(1 for f in self.functions.values() if f.tainted_params),
            'tainted_returns': sum(1 for f in self.functions.values() if f.returns_tainted),
        }

def analyze_interprocedural(project_dir):
    analyzer = InterproceduralAnalyzer()
    flows = analyzer.analyze_project(project_dir)
    return flows, analyzer.get_summary()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python interprocedural.py <project_dir>")
        sys.exit(1)
    flows, summary = analyze_interprocedural(sys.argv[1])
    print(f"\nSummary: {summary}")
    for f in flows:
        print(f"\n[{f.vuln_type}] {f.confidence:.0%}: {' -> '.join(f.flow_path)}")
