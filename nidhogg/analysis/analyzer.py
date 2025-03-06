# nidhogg/analysis/analyzer.py
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from crosshair.tracers import COMPOSITE_TRACER

from nidhogg.core.module_loader import load_module_from_file, analyze_module, enhanced_analyze_module
from nidhogg.core.simulator import SimulatedIO
from nidhogg.core.network_interceptor import NetworkInterceptor
from nidhogg.analysis.suspicious import SuspiciousFunctionTracer
from nidhogg.utils.debug import debug

def detect_malware(targets: List[str], verbose: bool = False, enable_coverage: bool = False) -> int:
    """
    Detect potentially malicious code in the given targets
    
    Args:
        targets: List of file paths or directories to analyze
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
        
    Returns:
        Integer status code (0 for success, 1 if suspicious patterns found)
    """
    # Initialize tracers
    suspicious_tracer = SuspiciousFunctionTracer()
    #network_interceptor = NetworkInterceptor()
    any_suspicious = False
    sim_io = SimulatedIO()
    
    with COMPOSITE_TRACER:
        # Push our tracers
        COMPOSITE_TRACER.push_module(suspicious_tracer)
        
        #with network_interceptor:
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
                        enhanced_analyze_module(module, spec, sim_io, 
                                                tracers=[suspicious_tracer], 
                                                enable_coverage=True)
                    else:
                        analyze_module(module, spec, sim_io, 
                                        tracers=[suspicious_tracer])
                except Exception as e:
                    debug(f"Error analyzing {path}: {e}")
            
            elif path.is_dir():
                for python_file in path.glob('**/*.py'):
                    debug(f"\nAnalyzing file: {python_file}")
                    try:
                        module, spec = load_module_from_file(python_file)
                        if enable_coverage:
                            enhanced_analyze_module(module, spec, sim_io, 
                                                    tracers=[suspicious_tracer], 
                                                    enable_coverage=True)
                        else:
                            analyze_module(module, spec, sim_io, 
                                            tracers=[suspicious_tracer])
                    except Exception as e:
                        debug(f"Error analyzing {python_file}: {e}")
        
        # Clean up tracers
        COMPOSITE_TRACER.pop_config(suspicious_tracer)
    
    # Display suspicious findings
    print("\n=== SUSPICIOUS FUNCTIONS ===")
    findings = suspicious_tracer.get_findings()
    any_suspicious = False
    for finding in findings:
        any_suspicious = True
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
    
    if not findings:
        print("No suspicious patterns or data flow issues detected.")
    
    return 1 if any_suspicious else 0