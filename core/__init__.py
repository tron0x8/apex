from .ts_adapter import TSNode, parse_php_ts
from .taint_engine import TaintAnalyzer, TaintFinding, analyze_php_file, TaintType, TaintLevel
from .symbolic_executor import SymbolicExecutor, SymbolicValue, SymbolicType, symbolic_execute_file
from .interprocedural import InterproceduralAnalyzer, FunctionInfo, TaintFlow, analyze_interprocedural
from .apex_core import APEXCore, VulnerabilityReport
from .frameworks import Framework, FrameworkDetector, FrameworkAnalyzer, FRAMEWORKS, EXTENDED_CWE_MAP
from .patterns import PatternScanner, VulnPattern, VULN_PATTERNS, scan_with_patterns
from .fp_filter import ZeroFPFilter, ZeroFPFilter as FalsePositiveFilter, filter_false_positives, validate_data_flow
from .advanced_analysis import AdvancedAnalyzer, TaintTracker, analyze_php_advanced, SOURCES, SINKS, SANITIZERS
from .security_checks import SecurityChecker, SecurityCheck, SECURITY_CHECKS, run_security_checks


# Advanced Context Analysis
try:
    from .context_analyzer import (
        AdvancedContextAnalyzer, WhitelistDetector, CustomFunctionAnalyzer,
        InterFileTracker, AuthContextAnalyzer, analyze_context
    )
except ImportError:
    pass

# False Positive Pre-Filter
try:
    from .fp_prefilter import FPPreFilter, EnhancedVulnFilter, create_enhanced_filter
except ImportError:
    pass
