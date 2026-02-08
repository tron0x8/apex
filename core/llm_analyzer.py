#!/usr/bin/env python3
"""
APEX LLM-Powered Security Analyzer

Three-layer analysis:
  Layer 1: Rule-based scan (existing - fast, free)
  Layer 2: LLM verification of findings (FP elimination)
  Layer 3: LLM deep hunt (finds what rules can't)
"""

import os
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path


@dataclass
class LLMFinding:
    """A vulnerability found or verified by LLM analysis."""
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file: str
    line: int
    code: str
    description: str
    attack_scenario: str = ""
    confidence: float = 0.0
    cwe: str = ""
    fix_suggestion: str = ""
    layer: str = ""  # "verify", "deep_hunt", "auth_gap", "cross_file"


@dataclass
class VerifyResult:
    """Result of LLM verification of a rule-based finding."""
    is_true_positive: bool
    confidence: float
    reasoning: str
    adjusted_severity: str
    exploitability: str  # "direct", "conditional", "theoretical"


class LLMAnalyzer:
    """LLM-powered PHP security analyzer. Supports Ollama (local/free) and Anthropic API."""

    # Backend auto-detection order
    BACKENDS = ["ollama", "anthropic"]

    def __init__(self, backend: Optional[str] = None,
                 model: Optional[str] = None,
                 api_key: Optional[str] = None,
                 ollama_url: str = "http://localhost:11434",
                 fast_mode: bool = False):
        """
        Args:
            backend: "ollama" or "anthropic". Auto-detected if None.
            model: Model name. Defaults based on backend.
            api_key: Anthropic API key (only for anthropic backend).
            ollama_url: Ollama server URL (default: localhost:11434).
            fast_mode: CPU-optimized mode with shorter prompts and smaller context.
        """
        self.ollama_url = ollama_url
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None
        self.fast_mode = fast_mode
        self.stats = {
            "api_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "findings_verified": 0,
            "fps_eliminated": 0,
            "new_findings": 0,
        }

        # Auto-detect backend
        if backend:
            self.backend = backend
        else:
            self.backend = self._detect_backend()

        # Set default model based on backend
        if model:
            self.model = model
        elif self.backend == "ollama":
            if fast_mode:
                self.model = "qwen2.5-coder:7b"  # Best speed/quality for CPU
            else:
                self.model = "qwen2.5-coder:7b"
        else:
            self.model = "claude-sonnet-4-5-20250929"

        # Tuning params based on mode
        if self.fast_mode:
            self._code_limit = 2000       # Max code chars per prompt
            self._max_tokens_verify = 150  # Short verification responses
            self._max_tokens_hunt = 400    # Short hunt responses
            self._max_tokens_auth = 400
            self._verify_context_lines = 10  # Lines before/after finding
            self._ollama_timeout = 600     # 10 min per call (CPU needs time)
            self._batch_size = 2           # Small batches for CPU
            self._batch_context_chars = 200  # Short context per finding in batch
        else:
            self._code_limit = 12000
            self._max_tokens_verify = 512
            self._max_tokens_hunt = 3000
            self._max_tokens_auth = 3000
            self._verify_context_lines = 25
            self._ollama_timeout = 600     # 10 min per call
            self._batch_size = 5
            self._batch_context_chars = 500

    def _detect_backend(self) -> str:
        """Auto-detect available backend. Prefers Ollama (free)."""
        # Try Ollama first (free, local)
        try:
            import httpx
            resp = httpx.get(f"{self.ollama_url}/api/tags", timeout=3)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                if models:
                    return "ollama"
        except Exception:
            pass

        # Try urllib as fallback (no extra deps)
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.ollama_url}/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read())
                    if data.get("models"):
                        return "ollama"
        except Exception:
            pass

        # Fall back to Anthropic if API key exists
        if self.api_key:
            return "anthropic"

        raise RuntimeError(
            "No LLM backend available!\n"
            "  Option 1 (FREE): Install Ollama -> curl -fsSL https://ollama.com/install.sh | sh\n"
            "                    Pull model    -> ollama pull qwen2.5-coder:32b\n"
            "  Option 2 (PAID): Set ANTHROPIC_API_KEY environment variable"
        )

    @property
    def client(self):
        """Lazy-init Anthropic client (only for anthropic backend)."""
        if self._client is None and self.backend == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def warmup(self, verbose: bool = False) -> bool:
        """Pre-warm the LLM model (load into RAM). Important for Ollama on CPU."""
        if self.backend != "ollama":
            return True

        if verbose:
            print(f"[LLM] Warming up {self.model} (loading into RAM)...")

        try:
            import urllib.request
            payload = json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": "Say OK"}],
                "stream": False,
                "keep_alive": "1h",  # Keep model loaded for 1 hour
                "options": {"num_predict": 5, "temperature": 0.0},
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.ollama_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Long timeout for first load - model may need to be read from disk
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = json.loads(resp.read())
                content = data.get("message", {}).get("content", "")
                duration = data.get("total_duration", 0) / 1e9

            if verbose:
                print(f"[LLM] Model ready ({duration:.1f}s): {content[:50]}")
            return True
        except Exception as e:
            if verbose:
                print(f"[LLM] Warmup failed: {e}")
            return False

    def _call_llm(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        """Make an LLM call via the configured backend."""
        self.stats["api_calls"] += 1

        if self.backend == "ollama":
            return self._call_ollama(system, prompt, max_tokens)
        else:
            return self._call_anthropic(system, prompt, max_tokens)

    def _call_ollama(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        """Call Ollama local API."""
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.0,  # Deterministic for security analysis
            },
        }).encode("utf-8")

        import urllib.request
        req = urllib.request.Request(
            f"{self.ollama_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        timeout = self._ollama_timeout
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            raise RuntimeError(f"Ollama call failed (timeout={timeout}s): {e}")

        # Track token usage
        self.stats["input_tokens"] += data.get("prompt_eval_count", 0)
        self.stats["output_tokens"] += data.get("eval_count", 0)

        return data.get("message", {}).get("content", "")

    def _call_anthropic(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        """Call Anthropic Claude API."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        self.stats["input_tokens"] += response.usage.input_tokens
        self.stats["output_tokens"] += response.usage.output_tokens
        return response.content[0].text

    def _parse_json_response(self, text: str) -> dict:
        """Extract JSON from LLM response, handling markdown code blocks."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # skip ```json
            end = next((i for i, l in enumerate(lines) if l.strip() == "```"), len(lines))
            text = "\n".join(lines[:end])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return {}

    # =========================================================================
    # Layer 2: Finding Verification (FP Elimination)
    # =========================================================================

    def verify_finding(self, finding_dict: dict, code_context: str,
                       full_code: str) -> VerifyResult:
        """Verify a rule-based finding using LLM analysis."""
        if self.fast_mode:
            system = "PHP security expert. Reply ONLY JSON."
            vuln_type = finding_dict.get("type", "Unknown")
            code_line = finding_dict.get("code", "")[:100]
            prompt = (
                f"Is this a real {vuln_type} vulnerability or false positive?\n"
                f"Code: {code_line}\n"
                f"Context:\n{code_context[:self._code_limit]}\n\n"
                f'Reply JSON: {{"tp":true/false,"sev":"CRITICAL/HIGH/MEDIUM/LOW","why":"brief"}}'
            )
        else:
            system = (
                "You are a PHP security expert. Analyze vulnerability findings from a "
                "static analysis tool. Determine if each finding is a true positive or "
                "false positive. Be precise - security scanners often over-report.\n"
                "Respond ONLY with a JSON object, no other text."
            )

            vuln_type = finding_dict.get("type", "Unknown")
            line = finding_dict.get("line", 0)
            code_line = finding_dict.get("code", "")

            prompt = f"""Analyze this PHP security finding:

**Vulnerability Type:** {vuln_type}
**File:** {finding_dict.get('file', 'unknown')}
**Line:** {line}
**Code at line:** {code_line}
**Confidence from scanner:** {finding_dict.get('confidence', 'N/A')}

**Surrounding code (50 lines):**
```php
{code_context}
```

Determine:
1. Is this a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE?
2. Is there effective sanitization/validation nearby?
3. How exploitable is it? (direct / conditional / theoretical)
4. What should the severity be? (CRITICAL / HIGH / MEDIUM / LOW)

Respond as JSON:
{{
    "is_true_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation",
    "adjusted_severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "exploitability": "direct/conditional/theoretical"
}}"""

        try:
            resp = self._call_llm(system, prompt, max_tokens=self._max_tokens_verify)
            data = self._parse_json_response(resp)

            self.stats["findings_verified"] += 1

            # Handle fast mode short keys
            is_tp = data.get("is_true_positive", data.get("tp", True))
            confidence = float(data.get("confidence", data.get("conf", 0.5)))
            reasoning = data.get("reasoning", data.get("why", ""))
            severity = data.get("adjusted_severity", data.get("sev", "MEDIUM"))
            exploit = data.get("exploitability", "theoretical")

            if not is_tp:
                self.stats["fps_eliminated"] += 1

            return VerifyResult(
                is_true_positive=is_tp,
                confidence=confidence,
                reasoning=reasoning,
                adjusted_severity=severity,
                exploitability=exploit,
            )
        except Exception as e:
            return VerifyResult(
                is_true_positive=True,
                confidence=0.5,
                reasoning=f"LLM verification failed: {e}",
                adjusted_severity=finding_dict.get("severity", "MEDIUM"),
                exploitability="unknown",
            )

    def verify_findings_batch(self, findings: list, file_codes: Dict[str, str]) -> list:
        """Verify multiple findings, return filtered list with LLM verdicts."""
        verified = []

        # In fast mode, batch multiple findings into one call
        if self.fast_mode and len(findings) > 1:
            return self._verify_batch_fast(findings, file_codes)

        for f in findings:
            fdict = f.to_dict() if hasattr(f, "to_dict") else f
            filepath = fdict.get("file", "")
            code = file_codes.get(filepath, "")

            line_num = fdict.get("line", 0)
            lines = code.split("\n")
            ctx_lines = self._verify_context_lines
            start = max(0, line_num - ctx_lines)
            end = min(len(lines), line_num + ctx_lines)
            context = "\n".join(
                f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start=start)
            )

            result = self.verify_finding(fdict, context, code)
            fdict["llm_verified"] = result.is_true_positive
            fdict["llm_confidence"] = result.confidence
            fdict["llm_reasoning"] = result.reasoning
            fdict["llm_severity"] = result.adjusted_severity
            fdict["llm_exploitability"] = result.exploitability

            if result.is_true_positive:
                verified.append(fdict)

        return verified

    def _verify_batch_fast(self, findings: list, file_codes: Dict[str, str]) -> list:
        """Fast-mode: batch verify findings in small LLM calls."""
        verified = []
        batch_size = self._batch_size
        ctx_chars = self._batch_context_chars
        total_batches = (len(findings) + batch_size - 1) // batch_size

        for batch_idx, batch_start in enumerate(range(0, len(findings), batch_size)):
            batch = findings[batch_start:batch_start + batch_size]
            items = []
            fdicts = []

            print(f"[LLM]   Batch {batch_idx+1}/{total_batches} "
                  f"({len(batch)} findings)...", end="", flush=True)

            for idx, f in enumerate(batch):
                fdict = f.to_dict() if hasattr(f, "to_dict") else f
                fdicts.append(fdict)
                filepath = fdict.get("file", "")
                code = file_codes.get(filepath, "")
                line_num = fdict.get("line", 0)
                lines = code.split("\n")
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 3)
                ctx = "\n".join(lines[start:end])[:ctx_chars]
                items.append(
                    f"{idx+1}. {fdict.get('type','?')} L{line_num}: "
                    f"{fdict.get('code','')[:60]}\n{ctx}"
                )

            prompt = (
                "Real or false positive?\n\n"
                + "\n\n".join(items) + "\n\n"
                '[{"id":1,"tp":true/false,"sev":"HIGH","why":"brief"}, ...]'
            )

            t0 = time.time()
            try:
                resp = self._call_llm("PHP security expert. Reply ONLY JSON.", prompt,
                                       max_tokens=self._max_tokens_verify)
                elapsed = time.time() - t0
                data = self._parse_json_response(resp)

                # Handle both array and object response
                results_list = data if isinstance(data, list) else data.get("results", [data])
                if not isinstance(results_list, list):
                    results_list = [results_list]

                fps = 0
                for idx, fdict in enumerate(fdicts):
                    r = results_list[idx] if idx < len(results_list) else {}
                    is_tp = r.get("tp", r.get("is_true_positive", True))
                    self.stats["findings_verified"] += 1
                    if not is_tp:
                        self.stats["fps_eliminated"] += 1
                        fps += 1
                    else:
                        fdict["llm_verified"] = True
                        fdict["llm_severity"] = r.get("sev", fdict.get("severity", "MEDIUM"))
                        fdict["llm_reasoning"] = r.get("why", "")
                        verified.append(fdict)
                print(f" OK ({elapsed:.0f}s, {fps} FP)")
            except Exception as e:
                elapsed = time.time() - t0
                # On failure, keep all findings (fail-open)
                print(f" FAIL ({elapsed:.0f}s): {e}")
                for fdict in fdicts:
                    fdict["llm_verified"] = True
                    fdict["llm_reasoning"] = f"batch verify failed: {e}"
                    verified.append(fdict)

        return verified

    # =========================================================================
    # Layer 3: Deep Hunt (Finds what rules can't)
    # =========================================================================

    def deep_hunt_file(self, filepath: str, code: str,
                       project_context: str = "") -> List[LLMFinding]:
        """Perform deep security analysis of a single PHP file."""
        # Skip very small or very large files
        if len(code) < 50 or len(code) > 100_000:
            return []

        code_display = code[:self._code_limit]

        if self.fast_mode:
            system = "PHP security auditor. Find vulnerabilities. Reply ONLY JSON."
            prompt = (
                f"File: {os.path.basename(filepath)}\n"
                f"```php\n{code_display}\n```\n\n"
                "Find: SQLi, XSS, CMDi, file upload, missing auth, unserialize, LFI/RFI.\n"
                'Reply JSON: {"findings":[{"vuln_type":"X","sev":"HIGH","line":1,'
                '"code":"snippet","desc":"what"}]} or {"findings":[]}'
            )
        else:
            system = (
                "You are an elite PHP security researcher performing a thorough code "
                "audit. Find vulnerabilities that automated scanners typically miss. "
                "Focus on logic flaws, missing auth, indirect taint flows, and dangerous "
                "patterns. Only report REAL vulnerabilities with HIGH confidence.\n"
                "Respond ONLY with a JSON object, no other text."
            )

            prompt = f"""Perform a deep security audit of this PHP file:

**File:** {filepath}

```php
{code_display}
```

{f"**Project context:** {project_context}" if project_context else ""}

Search specifically for:
1. **MISSING AUTHENTICATION/AUTHORIZATION** - Endpoints/AJAX handlers that perform sensitive operations without checking if user is logged in or has permission
2. **ARBITRARY FILE READ/WRITE** - file_put_contents, fwrite, file_get_contents, fopen where path comes from user input (even indirectly through base64_decode, json_decode, etc.)
3. **INDIRECT TAINT FLOWS** - User input flowing through base64_decode(), json_decode(), unserialize(), str_replace(), explode() to dangerous sinks
4. **INSECURE FILE ROUTING** - Dynamic require/include based on URL parameters or decoded values
5. **BROKEN ACCESS CONTROL** - Admin functions accessible without proper role checks
6. **OBJECT INJECTION** - unserialize() of user-controlled data
7. **SQL INJECTION** - Including through ORM/query builder misuse, string interpolation in queries
8. **COMMAND INJECTION** - Including through backticks, proc_open, etc.
9. **RACE CONDITIONS** - TOCTOU (time-of-check-time-of-use)
10. **INSECURE CRYPTOGRAPHY** - Weak hashing, predictable tokens, timing attacks

For each vulnerability found, provide:
- Exact line number(s)
- The vulnerable code
- A concrete attack scenario
- CWE identifier

Respond as JSON:
{{
    "findings": [
        {{
            "vuln_type": "type name",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "line": 123,
            "code": "vulnerable code snippet",
            "description": "what the vulnerability is",
            "attack_scenario": "step by step how to exploit",
            "cwe": "CWE-XXX",
            "fix": "how to fix it"
        }}
    ]
}}

If NO vulnerabilities found, return: {{"findings": []}}
Important: Only report findings you are confident about. No speculative findings."""

        try:
            resp = self._call_llm(system, prompt, max_tokens=self._max_tokens_hunt)
            data = self._parse_json_response(resp)

            results = []
            for f in data.get("findings", []):
                finding = LLMFinding(
                    vuln_type=f.get("vuln_type", "Unknown"),
                    severity=f.get("severity", f.get("sev", "MEDIUM")),
                    file=filepath,
                    line=f.get("line", 0),
                    code=f.get("code", "")[:200],
                    description=f.get("description", f.get("desc", "")),
                    attack_scenario=f.get("attack_scenario", ""),
                    confidence=0.85,
                    cwe=f.get("cwe", ""),
                    fix_suggestion=f.get("fix", ""),
                    layer="deep_hunt",
                )
                results.append(finding)
                self.stats["new_findings"] += 1

            return results
        except Exception as e:
            print(f"[LLM] WARNING: deep hunt failed for {os.path.basename(filepath)}: {e}")
            return []

    # =========================================================================
    # Layer 3b: Authentication Gap Analysis
    # =========================================================================

    def analyze_auth_gaps(self, endpoints: List[Dict[str, str]],
                          routing_code: str = "") -> List[LLMFinding]:
        """Analyze endpoints for missing authentication/authorization."""
        if not endpoints:
            return []

        code_lim = self._code_limit

        if self.fast_mode:
            system = "PHP security expert. Find missing auth. Reply ONLY JSON."
            endpoints_text = ""
            for ep in endpoints[:10]:  # Fewer in fast mode
                endpoints_text += f"\n--- {os.path.basename(ep['file'])} ---\n"
                endpoints_text += ep.get("code", "")[:1000] + "\n"

            prompt = (
                "Which endpoints lack authentication/authorization?\n\n"
                + endpoints_text + "\n"
                + '{"findings":[{"vuln_type":"Missing Auth","sev":"HIGH",'
                  '"file":"name","line":1,"desc":"what"}]} or {"findings":[]}'
            )
        else:
            system = (
                "You are a PHP security expert analyzing web application endpoints for "
                "authentication and authorization vulnerabilities. Identify endpoints that "
                "perform sensitive operations without proper access control.\n"
                "Respond ONLY with a JSON object, no other text."
            )

            endpoints_text = ""
            for ep in endpoints[:30]:
                endpoints_text += f"\n--- {ep['file']} ---\n"
                code = ep.get("code", "")[:3000]
                endpoints_text += code + "\n"

            prompt = f"""Analyze these PHP endpoints for authentication/authorization gaps:

{endpoints_text}

{f"**Routing mechanism:**\n```php\n{routing_code[:3000]}\n```" if routing_code else ""}

For each endpoint, determine:
1. Does it check if user is authenticated (session, token, login check)?
2. Does it verify authorization (role/permission check)?
3. Does it have CSRF protection?
4. What sensitive operations does it perform (file write, DB modify, user admin)?

Report endpoints that lack proper auth for their sensitivity level.

Respond as JSON:
{{
    "findings": [
        {{
            "vuln_type": "Missing Authentication/Authorization",
            "severity": "CRITICAL/HIGH",
            "file": "filename",
            "line": 1,
            "code": "relevant code",
            "description": "what auth check is missing",
            "attack_scenario": "how to exploit",
            "cwe": "CWE-862"
        }}
    ]
}}"""

        try:
            resp = self._call_llm(system, prompt, max_tokens=self._max_tokens_auth)
            data = self._parse_json_response(resp)

            results = []
            for f in data.get("findings", []):
                finding = LLMFinding(
                    vuln_type=f.get("vuln_type", "Missing Authentication"),
                    severity=f.get("severity", "HIGH"),
                    file=f.get("file", ""),
                    line=f.get("line", 0),
                    code=f.get("code", "")[:200],
                    description=f.get("description", ""),
                    attack_scenario=f.get("attack_scenario", ""),
                    confidence=0.80,
                    cwe=f.get("cwe", "CWE-862"),
                    fix_suggestion=f.get("fix", ""),
                    layer="auth_gap",
                )
                results.append(finding)
                self.stats["new_findings"] += 1

            return results
        except Exception:
            return []

    # =========================================================================
    # Layer 3c: Cross-File Flow Analysis
    # =========================================================================

    def analyze_cross_file_flow(self, file_chain: List[Dict[str, str]]) -> List[LLMFinding]:
        """Analyze taint flows that cross file boundaries via include/require."""
        if not file_chain:
            return []

        system = (
            "You are a PHP security expert analyzing data flows across multiple files "
            "connected by include/require statements. Trace user input from entry "
            "points through file includes to dangerous sinks.\n"
            "Respond ONLY with a JSON object, no other text."
        )

        chain_text = ""
        for entry in file_chain[:10]:
            chain_text += f"\n=== {entry['file']} ===\n"
            code = entry.get("code", "")[:5000]
            chain_text += f"```php\n{code}\n```\n"

        prompt = f"""Analyze the data flow across these connected PHP files:

{chain_text}

Trace how user input ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES, $_SERVER)
flows through include/require boundaries to reach dangerous sinks.

Look for:
1. Router files that include other files based on user input
2. AJAX handlers included without authentication
3. Data passed through shared variables or globals across includes
4. File write/read operations in included files that use data from parent scope

Respond as JSON:
{{
    "findings": [
        {{
            "vuln_type": "Cross-File Taint Flow",
            "severity": "CRITICAL/HIGH",
            "file": "sink_file.php",
            "line": 123,
            "code": "dangerous sink code",
            "description": "User input from source_file flows to sink via include",
            "attack_scenario": "step by step exploitation",
            "flow_path": ["entry.php", "router.php", "handler.php"],
            "cwe": "CWE-XXX"
        }}
    ]
}}"""

        try:
            resp = self._call_llm(system, prompt, max_tokens=3000)
            data = self._parse_json_response(resp)

            results = []
            for f in data.get("findings", []):
                finding = LLMFinding(
                    vuln_type=f.get("vuln_type", "Cross-File Taint Flow"),
                    severity=f.get("severity", "HIGH"),
                    file=f.get("file", ""),
                    line=f.get("line", 0),
                    code=f.get("code", "")[:200],
                    description=f.get("description", ""),
                    attack_scenario=f.get("attack_scenario", ""),
                    confidence=0.80,
                    cwe=f.get("cwe", ""),
                    fix_suggestion=f.get("fix", ""),
                    layer="cross_file",
                )
                results.append(finding)
                self.stats["new_findings"] += 1

            return results
        except Exception:
            return []

    # =========================================================================
    # Auto-Discovery: Generic Entry Point & Pattern Detection
    # =========================================================================

    def _auto_discover(self, file_codes: Dict[str, str],
                        project_dir: str, verbose: bool = False) -> Dict:
        """
        Automatically discover project structure, entry points, routing,
        AJAX handlers, and include chains. Works on ANY PHP project.
        """
        import re
        discovery = {
            "entry_points": [],      # Files directly accessible via web
            "routing_files": [],     # Files that route/dispatch requests
            "ajax_handlers": [],     # AJAX/API endpoints
            "admin_files": [],       # Admin panel files
            "auth_files": [],        # Authentication related
            "file_ops_files": [],    # Files with file read/write operations
            "dangerous_files": [],   # Files with eval/exec/unserialize
            "include_chains": [],    # Dynamic include chains
            "db_files": [],          # Direct database interaction
            "upload_handlers": [],   # File upload handlers
        }

        # Patterns that indicate different file roles (generic, not CMS-specific)
        routing_patterns = [
            r'(?:require|include)(?:_once)?\s*\(\s*.*?base64_decode',
            r'(?:require|include)(?:_once)?\s*\(\s*\$\w+\s*\)',
            r'(?:require|include)(?:_once)?\s*\(\s*.*?\$.*?\..*?\$',
            r'switch\s*\(\s*\$_(GET|POST|REQUEST)',
            r'if\s*\(\s*\$_(GET|POST|REQUEST).*?===?\s*[\'"]',
            r'->dispatch\s*\(|->route\s*\(|->handle\s*\(',
            r'\$_SERVER\s*\[\s*[\'"]REQUEST_URI[\'"]\s*\]',
            r'\$_SERVER\s*\[\s*[\'"]PATH_INFO[\'"]\s*\]',
        ]

        entry_point_patterns = [
            r'<\?php\s+(?:/\*.*?\*/\s+)?(?:define|require|include|session_start)',
        ]

        auth_patterns = [
            r'session_start|session_destroy|session_regenerate',
            r'\$_SESSION\s*\[.*?(user|login|auth|admin|token)',
            r'password_verify|password_hash|md5\s*\(\s*.*?pass',
            r'function\s+(?:check_auth|is_logged|verify_user|check_login|authenticate)',
            r'(?:login|logout|signin|signout|register)\s*\(',
        ]

        file_ops_patterns = [
            r'file_put_contents\s*\(',
            r'fwrite\s*\(',
            r'fopen\s*\(.*?[\'"]w',
            r'move_uploaded_file\s*\(',
            r'copy\s*\(.*?\$',
            r'rename\s*\(.*?\$',
            r'unlink\s*\(.*?\$',
            r'mkdir\s*\(.*?\$',
            r'file_get_contents\s*\(.*?\$',
            r'readfile\s*\(.*?\$',
        ]

        dangerous_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bsystem\s*\(',
            r'\bpassthru\s*\(',
            r'\bshell_exec\s*\(',
            r'\bpopen\s*\(',
            r'\bproc_open\s*\(',
            r'\bunserialize\s*\(.*?\$',
            r'\bcall_user_func\s*\(.*?\$',
            r'\bcreate_function\s*\(',
            r'\bassert\s*\(.*?\$',
            r'`.*?\$',
        ]

        upload_patterns = [
            r'\$_FILES\s*\[',
            r'move_uploaded_file',
            r'(?:type|tmp_name|name|size)\s*\]',
            r'upload|attachment|import',
        ]

        db_patterns = [
            r'(?:mysql|mysqli|pg|sqlite|oci)_query\s*\(',
            r'->query\s*\(',
            r'->exec\s*\(',
            r'->prepare\s*\(',
            r'->execute\s*\(',
            r'SELECT\s+.*?FROM\s+.*?WHERE\s+.*?\$',
            r'INSERT\s+INTO\s+.*?\$',
            r'UPDATE\s+.*?SET\s+.*?\$',
            r'DELETE\s+FROM\s+.*?\$',
        ]

        for filepath, code in file_codes.items():
            fname = os.path.basename(filepath).lower()
            fpath_lower = filepath.lower().replace("\\", "/")
            relpath = os.path.relpath(filepath, project_dir)

            info = {"file": filepath, "relpath": relpath, "code": code}

            # Check routing
            if any(re.search(p, code) for p in routing_patterns):
                discovery["routing_files"].append(info)

            # Check admin
            if ("admin" in fpath_lower or "manage" in fname or
                "cpanel" in fname or "dashboard" in fname or "backend" in fpath_lower):
                discovery["admin_files"].append(info)

            # Check AJAX/API (generic detection)
            is_ajax = (
                "ajax" in fname or "api" in fname or
                "json" in fname or "rpc" in fname or
                "endpoint" in fname or "action" in fname or
                "handler" in fname or "callback" in fname or
                "-ajax" in fname or "_ajax" in fname or
                "xmlhttp" in code.lower()[:500] or
                "X-Requested-With" in code[:500] or
                "application/json" in code[:1000] or
                re.search(r'header\s*\(\s*[\'"]Content-Type:\s*application/json', code)
            )
            if is_ajax:
                discovery["ajax_handlers"].append(info)

            # Check auth
            if any(re.search(p, code, re.IGNORECASE) for p in auth_patterns):
                discovery["auth_files"].append(info)

            # Check file operations
            if any(re.search(p, code) for p in file_ops_patterns):
                discovery["file_ops_files"].append(info)

            # Check dangerous functions
            if any(re.search(p, code) for p in dangerous_patterns):
                discovery["dangerous_files"].append(info)

            # Check uploads
            if sum(1 for p in upload_patterns if re.search(p, code, re.IGNORECASE)) >= 2:
                discovery["upload_handlers"].append(info)

            # Check direct DB
            if any(re.search(p, code, re.IGNORECASE) for p in db_patterns):
                discovery["db_files"].append(info)

            # Entry points: files that start sessions, define constants, etc.
            if any(re.search(p, code[:500]) for p in entry_point_patterns):
                discovery["entry_points"].append(info)

        # Build include chains from routing files
        for router in discovery["routing_files"]:
            chain = [router]
            code = router["code"]

            # Find all files this router might include
            static_includes = re.findall(
                r'(?:require|include)(?:_once)?\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                code,
            )
            b64_refs = re.findall(
                r'base64_encode\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                code,
            )

            for ref in set(static_includes + b64_refs):
                for other_path, other_code in file_codes.items():
                    if ref in other_path or other_path.endswith(ref):
                        chain.append({
                            "file": other_path,
                            "relpath": os.path.relpath(other_path, project_dir),
                            "code": other_code,
                        })
                        break

            if len(chain) > 1:
                discovery["include_chains"].append(chain)

        if verbose:
            print(f"[LLM] Auto-Discovery Results:")
            print(f"  Entry points:     {len(discovery['entry_points'])}")
            print(f"  Routing files:    {len(discovery['routing_files'])}")
            print(f"  AJAX/API:         {len(discovery['ajax_handlers'])}")
            print(f"  Admin files:      {len(discovery['admin_files'])}")
            print(f"  Auth files:       {len(discovery['auth_files'])}")
            print(f"  File operations:  {len(discovery['file_ops_files'])}")
            print(f"  Dangerous funcs:  {len(discovery['dangerous_files'])}")
            print(f"  Upload handlers:  {len(discovery['upload_handlers'])}")
            print(f"  DB interaction:   {len(discovery['db_files'])}")
            print(f"  Include chains:   {len(discovery['include_chains'])}")

        return discovery

    # =========================================================================
    # Full Project Scan (Orchestrator)
    # =========================================================================

    def scan_project(self, project_dir: str,
                     rule_findings: Optional[list] = None,
                     file_codes: Optional[Dict[str, str]] = None,
                     verbose: bool = False) -> Dict:
        """
        Full LLM-powered project scan.

        Args:
            project_dir: Path to PHP project
            rule_findings: Optional pre-computed rule-based findings
            file_codes: Optional dict of filepath -> code content
            verbose: Print progress
        """
        results = {
            "project": project_dir,
            "verified_findings": [],
            "new_findings": [],
            "stats": {},
        }

        # Load all PHP files if not provided
        if file_codes is None:
            file_codes = {}
            ppath = Path(project_dir)
            for php_file in ppath.rglob("*.php"):
                try:
                    file_codes[str(php_file)] = php_file.read_text(
                        encoding="utf-8", errors="ignore"
                    )
                except Exception:
                    pass

        if verbose:
            print(f"[LLM] {len(file_codes)} PHP files loaded")

        # Layer 2: Verify rule-based findings
        if rule_findings:
            if verbose:
                print(f"[LLM] Layer 2: Verifying {len(rule_findings)} findings...")
            verified = self.verify_findings_batch(rule_findings, file_codes)
            results["verified_findings"] = verified
            if verbose:
                eliminated = len(rule_findings) - len(verified)
                print(f"[LLM] Layer 2: {eliminated} FPs eliminated, "
                      f"{len(verified)} confirmed")

        # Auto-discover project structure (generic, works on any CMS)
        discovery = self._auto_discover(file_codes, project_dir, verbose=verbose)

        # Layer 3: Deep hunt on interesting files
        if verbose:
            print(f"[LLM] Layer 3: Deep hunting files...")

        # Build priority set from auto-discovery
        priority_set = set()
        for category in ["ajax_handlers", "admin_files", "routing_files",
                         "file_ops_files", "dangerous_files", "upload_handlers",
                         "auth_files"]:
            for info in discovery.get(category, []):
                priority_set.add(info["file"])

        priority_files = []
        normal_files = []
        for filepath, code in file_codes.items():
            if filepath in priority_set:
                priority_files.append((filepath, code))
            else:
                normal_files.append((filepath, code))

        if verbose:
            print(f"[LLM]   {len(priority_files)} priority + "
                  f"{len(normal_files)} normal files")

        # Build project context string
        file_tree = "\n".join(
            f"  {os.path.relpath(fp, project_dir)}"
            for fp in sorted(file_codes.keys())[:100]
        )
        project_context = f"Project files ({len(file_codes)} total):\n{file_tree}"

        all_new_findings = []

        # In fast mode, only scan priority files
        if self.fast_mode:
            scan_files = priority_files
            if verbose:
                print(f"[LLM]   Fast mode: scanning {len(scan_files)} priority files only")
        else:
            scan_files = priority_files + normal_files

        for i, (filepath, code) in enumerate(scan_files):
            if verbose:
                relpath = os.path.relpath(filepath, project_dir)
                tag = "[PRIORITY]" if i < len(priority_files) else "[normal]"
                print(f"[LLM]   {tag} ({i+1}/{len(scan_files)}) {relpath}")

            try:
                findings = self.deep_hunt_file(filepath, code, project_context)
                all_new_findings.extend(findings)
            except Exception as e:
                if verbose:
                    print(f"[LLM]   [SKIP] {relpath}: {e}")

        # Layer 3b: Auth gap analysis on discovered AJAX/API endpoints
        ajax_endpoints = [
            {"file": info["file"], "code": info["code"]}
            for info in discovery.get("ajax_handlers", [])
        ]
        # Also include admin files and file_ops files without auth
        auth_file_set = set(
            info["file"] for info in discovery.get("auth_files", [])
        )
        for info in discovery.get("admin_files", []):
            if info["file"] not in auth_file_set:
                ajax_endpoints.append({"file": info["file"], "code": info["code"]})
        for info in discovery.get("file_ops_files", []):
            if info["file"] not in auth_file_set:
                ajax_endpoints.append({"file": info["file"], "code": info["code"]})

        # Build routing code from discovered routing files
        routing_code = ""
        for info in discovery.get("routing_files", [])[:5]:
            routing_code += f"\n// {info['file']}\n{info['code'][:3000]}\n"

        # In fast mode, skip 3b/3c (too expensive for CPU)
        if not self.fast_mode:
            if ajax_endpoints:
                if verbose:
                    print(f"[LLM] Layer 3b: Analyzing {len(ajax_endpoints)} "
                          f"endpoints for auth gaps...")
                auth_findings = self.analyze_auth_gaps(ajax_endpoints, routing_code)
                all_new_findings.extend(auth_findings)

            # Layer 3c: Cross-file flow analysis using discovered chains
            include_chains = discovery.get("include_chains", [])
            if not include_chains:
                include_chains = self._find_include_chains(file_codes, project_dir)
            if include_chains:
                if verbose:
                    print(f"[LLM] Layer 3c: Analyzing {len(include_chains)} "
                          f"include chains...")
                for chain in include_chains[:5]:
                    flow_findings = self.analyze_cross_file_flow(chain)
                    all_new_findings.extend(flow_findings)
        elif verbose:
            print(f"[LLM] Fast mode: skipping Layer 3b/3c")

        results["new_findings"] = [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "code": f.code,
                "description": f.description,
                "attack_scenario": f.attack_scenario,
                "confidence": f.confidence,
                "cwe": f.cwe,
                "fix": f.fix_suggestion,
                "layer": f.layer,
            }
            for f in all_new_findings
        ]

        results["stats"] = dict(self.stats)
        return results

    def _find_include_chains(self, file_codes: Dict[str, str],
                              project_dir: str) -> List[List[Dict[str, str]]]:
        """Find chains of files connected by include/require."""
        import re
        chains = []

        # Find files that dynamically include others
        for filepath, code in file_codes.items():
            # Look for dynamic include patterns:
            #   require($var), include(base64_decode(...)), require($dir . $file)
            patterns = [
                r'(?:require|include)(?:_once)?\s*\(\s*\$\w+\s*\)',
                r'(?:require|include)(?:_once)?\s*\(\s*.*?base64_decode',
                r'(?:require|include)(?:_once)?\s*\(\s*.*?\$.*?\..*?\$',
            ]

            has_dynamic_include = any(re.search(p, code) for p in patterns)
            if not has_dynamic_include:
                continue

            # Find which files this file might include
            # Look for static includes to build a chain
            chain = [{"file": filepath, "code": code}]

            # Find referenced files
            static_includes = re.findall(
                r'(?:require|include)(?:_once)?\s*\(\s*[\'"]([^"\']+)[\'"]\s*\)',
                code,
            )
            # Also find base64 encoded paths
            b64_includes = re.findall(
                r'base64_encode\s*\(\s*[\'"]([^"\']+)[\'"]\s*\)',
                code,
            )

            referenced = set(static_includes + b64_includes)

            for ref in referenced:
                # Try to find the actual file
                for other_path, other_code in file_codes.items():
                    if ref in other_path or other_path.endswith(ref):
                        chain.append({"file": other_path, "code": other_code})
                        break

            if len(chain) > 1:
                chains.append(chain)

        return chains

    def get_cost_estimate(self) -> Dict:
        """Estimate API cost based on token usage."""
        if self.backend == "ollama":
            # Ollama is free (local)
            return {
                "input_tokens": self.stats["input_tokens"],
                "output_tokens": self.stats["output_tokens"],
                "api_calls": self.stats["api_calls"],
                "estimated_cost_usd": 0.0,
                "backend": "ollama (FREE)",
            }
        else:
            # Approximate pricing (Claude Sonnet 4.5)
            input_cost = self.stats["input_tokens"] * 3.0 / 1_000_000
            output_cost = self.stats["output_tokens"] * 15.0 / 1_000_000
            return {
                "input_tokens": self.stats["input_tokens"],
                "output_tokens": self.stats["output_tokens"],
                "api_calls": self.stats["api_calls"],
                "estimated_cost_usd": round(input_cost + output_cost, 4),
                "backend": "anthropic",
            }
