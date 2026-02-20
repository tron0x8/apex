#!/usr/bin/env python3
# apex/core - tron (@tron0x8)

from .rule_engine import RuleEngine, get_rule_engine
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
import re

try:
    from .abstract_interp import AbstractState
except ImportError:
    AbstractState = None

try:
    from .taint_engine import TypeState  # type: ignore[attr-defined]
except ImportError:
    try:
        from .taint_tracker import TypeState  # type: ignore[attr-defined]
    except ImportError:
        TypeState = None

try:
    from .interprocedural import FunctionSummary  # type: ignore[attr-defined]
except ImportError:
    FunctionSummary = None

try:
    from .symbolic_executor import StringValue  # type: ignore[attr-defined]
except ImportError:
    StringValue = None


@dataclass
class AnalysisContext:

    taint_state: Optional[Any] = None
    type_state: Optional[Any] = None
    framework: Optional[str] = None
    function_context: Optional[Any] = None
    string_value: Optional[Any] = None
    alias_info: Optional[Dict] = None
    file_path: str = ""
    code_lines: List[str] = field(default_factory=list)


class FPFilterV2:

    def __init__(self, rule_engine: RuleEngine) -> None:
        self._engine = rule_engine
        self._fp_rules = rule_engine.get_fp_rules()
        self._sanitizers = rule_engine.get_sanitizers()
        self._frameworks = rule_engine.frameworks

        self._compiled_sanitizers: List[tuple] = []
        for _name, san_def in self._sanitizers.items():
            if san_def.pattern:
                try:
                    compiled = re.compile(san_def.pattern, re.IGNORECASE)
                    self._compiled_sanitizers.append(
                        (compiled, san_def.protects_against, san_def.name)
                    )
                except re.error:
                    pass


    def filter(
        self,
        findings: List[Dict],
        context: AnalysisContext,
    ) -> List[Dict]:

        result: List[Dict] = []

        for finding in findings:
            reason = self._classify(finding, context)
            if reason is not None:
                finding["fp_filtered"] = True
                finding["fp_reason"] = reason
            else:
                result.append(finding)

        return result


    def _classify(self, finding: Dict, ctx: AnalysisContext) -> Optional[str]:

        vuln_type: str = finding.get("vuln_type", finding.get("type", ""))
        line_num: int = finding.get("line", 0)
        code_line: str = finding.get("code", "")

        surrounding = self._get_surrounding_code(line_num, ctx, window=5)

        reason = self._check_category(
            "comment_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason
        reason = self._check_category(
            "dead_code_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_sanitizer_presence(vuln_type, code_line, surrounding)
        if reason:
            return reason

        reason = self._check_category(
            "prepared_statement_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_category(
            "type_cast_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_framework_safe(vuln_type, code_line, surrounding, ctx)
        if reason:
            return reason

        reason = self._check_category(
            "validation_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_category(
            "auth_check_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_category(
            "orm_patterns", finding, code_line, surrounding
        )
        if reason:
            return reason

        reason = self._check_type_state(finding, ctx)
        if reason:
            return reason

        reason = self._check_analysis_context(finding, ctx)
        if reason:
            return reason

        return None


    def _check_category(
        self,
        category: str,
        finding: Dict,
        code_line: str,
        surrounding: str,
    ) -> Optional[str]:

        rules = self._fp_rules.get(category, [])
        for rule in rules:
            if self._check_rule(finding, rule, code_line, surrounding):
                return f"{category}: {rule.description or rule.name}"
        return None

    def _check_rule(
        self,
        finding: Dict,
        rule: Any,
        code_line: str,
        surrounding: str,
    ) -> bool:

        vuln_type: str = finding.get("vuln_type", finding.get("type", ""))

        if rule.applies_to and vuln_type not in rule.applies_to:
            return False

        if not rule.pattern:
            return False

        try:
            compiled = rule.compiled_pattern
        except (re.error, AttributeError):
            return False

        if compiled.search(code_line):
            return True

        if rule.category in (
            "prepared_stmt", "type_cast", "validation",
            "auth_check", "orm", "dead_code",
        ):
            if compiled.search(surrounding):
                return True

        return False


    def _check_sanitizer_presence(
        self,
        vuln_type: str,
        code_line: str,
        surrounding: str,
    ) -> Optional[str]:

        text = code_line + "\n" + surrounding
        for compiled, protects_against, name in self._compiled_sanitizers:
            if vuln_type in protects_against or any(
                vuln_type.upper().startswith(p.split("_")[0])
                for p in protects_against
            ):
                if compiled.search(text):
                    return f"sanitizer_present: {name} protects against {vuln_type}"
        return None


    def _check_framework_safe(
        self,
        vuln_type: str,
        code_line: str,
        surrounding: str,
        ctx: AnalysisContext,
    ) -> Optional[str]:

        fw_name = ctx.framework
        if not fw_name:
            return None

        fw_def = self._engine.get_framework(fw_name)
        if fw_def is None:
            return None

        text = code_line + "\n" + surrounding
        for pattern_str in fw_def.safe_patterns:
            try:
                if re.search(pattern_str, text, re.IGNORECASE):
                    return (
                        f"framework_safe: {fw_def.name} safe pattern "
                        f"'{pattern_str}' matched"
                    )
            except re.error:
                continue

        return None


    def _check_type_state(
        self, finding: Dict, ctx: AnalysisContext
    ) -> Optional[str]:

        if ctx.type_state is None:
            return None

        line_num: int = finding.get("line", 0)
        vuln_type: str = finding.get("vuln_type", finding.get("type", ""))

        safe_types = {"int", "integer", "float", "double", "bool", "boolean"}

        inferred: Optional[str] = None
        if hasattr(ctx.type_state, "get_type_at"):
            try:
                inferred = ctx.type_state.get_type_at(line_num)
            except Exception:
                pass
        elif hasattr(ctx.type_state, "types"):
            try:
                inferred = ctx.type_state.types.get(line_num)
            except Exception:
                pass

        if inferred and str(inferred).lower() in safe_types:
            return f"type_safe: variable typed as {inferred} at line {line_num}"

        return None


    def _check_analysis_context(
        self, finding: Dict, ctx: AnalysisContext
    ) -> Optional[str]:

        line_num: int = finding.get("line", 0)

        if ctx.taint_state is not None:
            if hasattr(ctx.taint_state, "is_clean_at"):
                try:
                    if ctx.taint_state.is_clean_at(line_num):
                        return (
                            f"taint_clean: abstract state shows clean "
                            f"value at line {line_num}"
                        )
                except Exception:
                    pass
            elif hasattr(ctx.taint_state, "is_tainted_at"):
                try:
                    if not ctx.taint_state.is_tainted_at(line_num):
                        return (
                            f"taint_clean: variable not tainted at "
                            f"line {line_num}"
                        )
                except Exception:
                    pass

        if ctx.string_value is not None:
            if hasattr(ctx.string_value, "is_constant"):
                try:
                    if ctx.string_value.is_constant():
                        return (
                            f"string_constant: value is a known constant "
                            f"at line {line_num}"
                        )
                except Exception:
                    pass
            if hasattr(ctx.string_value, "is_safe_for"):
                vuln_type: str = finding.get(
                    "vuln_type", finding.get("type", "")
                )
                try:
                    if ctx.string_value.is_safe_for(vuln_type):
                        return (
                            f"string_safe: string domain marks value "
                            f"safe for {vuln_type} at line {line_num}"
                        )
                except Exception:
                    pass

        return None


    @staticmethod
    def _get_surrounding_code(
        line_num: int,
        ctx: AnalysisContext,
        window: int = 5,
    ) -> str:

        if not ctx.code_lines:
            return ""

        total = len(ctx.code_lines)
        if line_num <= 0 or line_num > total:
            return ""

        start = max(0, line_num - 1 - window)
        end = min(total, line_num + window)
        return "\n".join(ctx.code_lines[start:end])
