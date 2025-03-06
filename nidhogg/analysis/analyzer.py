# nidhogg/analysis/analyzer.py
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from crosshair.tracers import COMPOSITE_TRACER

from nidhogg.core.module_loader import load_module_from_file, analyze_module, enhanced_analyze_module
from nidhogg.core.simulator import SimulatedIO
from nidhogg.analysis.suspicious import SuspiciousFunctionTracer
from nidhogg.analysis.taint import TaintTrackingTracer
from nidhogg.utils.debug import debug

# Remove detect_malware_with_taint function as we're integrating taint analysis directly

def detect_malware(targets: List[str], verbose: bool = False, enable_coverage: bool = False) -> int:
    """
    Detect potentially malicious code and data exfiltration in the given targets
    
    Args:
        targets: List of file paths or directories to analyze
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
        
    Returns:
        Integer status code (0 for success, 1 if security issues found)
    """
    # Initialize tracers
    suspicious_tracer = SuspiciousFunctionTracer()
    taint_tracer = TaintTrackingTracer()
    any_suspicious = False
    sim_io = SimulatedIO()
    
    print(f"Nidhogg Security Analyzer running with{'out' if not enable_coverage else ''} enhanced coverage")
    
    with COMPOSITE_TRACER:
        # Push our tracers
        COMPOSITE_TRACER.push_module(suspicious_tracer)
        COMPOSITE_TRACER.push_module(taint_tracer)
        
        analyzed_files = 0
        
        for target_path in targets:
            path = Path(target_path)
            if not path.exists():
                print(f"Path does not exist: {path}")
                continue
            
            if path.is_file() and path.suffix == '.py':
                debug(f"\nAnalyzing file: {path}")
                try:
                    module, spec = load_module_from_file(path)
                    if enable_coverage:
                        enhanced_analyze_module(module, spec, sim_io, tracers=[suspicious_tracer, taint_tracer], enable_coverage=True)
                    else:
                        analyze_module(module, spec, sim_io, tracers=[suspicious_tracer, taint_tracer])
                    analyzed_files += 1
                except Exception as e:
                    debug(f"Error analyzing {path}: {e}")
            
            elif path.is_dir():
                for python_file in path.glob('**/*.py'):
                    debug(f"\nAnalyzing file: {python_file}")
                    try:
                        module, spec = load_module_from_file(python_file)
                        if enable_coverage:
                            enhanced_analyze_module(module, spec, sim_io, tracers=[suspicious_tracer, taint_tracer], enable_coverage=True)
                        else:
                            analyze_module(module, spec, sim_io, tracers=[suspicious_tracer, taint_tracer])
                        analyzed_files += 1
                    except Exception as e:
                        debug(f"Error analyzing {python_file}: {e}")
        
        # Clean up tracers
        COMPOSITE_TRACER.pop_config(taint_tracer)
        COMPOSITE_TRACER.pop_config(suspicious_tracer)
    
    print(f"\nAnalyzed {analyzed_files} Python file(s)")
    
    # Get analysis results
    findings = suspicious_tracer.get_findings()
    taint_report = taint_tracer.get_report()
    
    # Track if any security issues were found
    security_issues_found = len(findings) > 0 or taint_report['total_exfiltration_attempts'] > 0
    
    # Display suspicious functions findings
    if findings:
        print("\n=== SUSPICIOUS FUNCTIONS ===")
        any_suspicious = True
        
        for finding in findings:
            risk_color = {
                'high': '\033[91m',  # Red
                'medium': '\033[93m',  # Yellow
                'low': '\033[96m',  # Cyan
            }.get(finding['risk'], '')
            end_color = '\033[0m'
            
            print(f"{finding['filename']}:{finding['line']}: {risk_color}{finding['risk']} risk{end_color}: "
                f"{finding['description']} - Call to {finding['function']}")
            
            # Print argument info if available
            if finding['args'] and verbose:
                for arg_name, arg_value in finding['args'].items():
                    print(f"  - {arg_name}: {arg_value}")
    
    # Display taint analysis findings
    if taint_report['total_tainted_vars'] > 0:
        print("\n=== DATA FLOW ANALYSIS ===")
        print(f"Found {taint_report['total_tainted_vars']} tainted variables")
        
        if verbose:
            for var in taint_report["tainted_variables"]:
                print(f"  - {var['name']}: {', '.join(var['taints'])}")
    
    # Display exfiltration attempts
    if taint_report['total_exfiltration_attempts'] > 0:
        print("\n=== POTENTIAL DATA EXFILTRATION ===")
        print(f"Detected {taint_report['total_exfiltration_attempts']} potential data exfiltration attempts")
        
        for attempt in taint_report["exfiltration_attempts"]:
            print(f"  - {attempt['filename']}:{attempt['line']}: "
                f"Potential exfiltration via {attempt['sink']['module']}.{attempt['sink']['name']}")
            
            for data in attempt['tainted_data']:
                if 'position' in data:
                    print(f"    Arg {data['position']}: {data['value']}")
                elif 'keyword' in data:
                    print(f"    Keyword {data['keyword']}: {data['value']}")
                elif 'result' in data:
                    print(f"    Result: {data['value']}")
                
                print(f"    Tainted with: {', '.join(data['taints'])}")
    
    # Final summary
    if security_issues_found:
        risk_level = "HIGH" if any(f['risk'] == 'high' for f in findings) or taint_report['total_exfiltration_attempts'] > 0 else "MEDIUM"
        print(f"\n=== SECURITY ANALYSIS SUMMARY ===")
        print(f"Security Risk: \033[91m{risk_level}\033[0m")
        print(f"- Suspicious function calls: {len(findings)}")
        print(f"- Tainted variables: {taint_report['total_tainted_vars']}")
        print(f"- Potential data exfiltration: {taint_report['total_exfiltration_attempts']}")
    else:
        print("\nNo suspicious patterns or data flow issues detected.")
    
    return 1 if security_issues_found else 0