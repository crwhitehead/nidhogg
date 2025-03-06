# nidhogg/analysis/analyzer.py
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

from crosshair.tracers import COMPOSITE_TRACER

from nidhogg.core.module_loader import load_module_from_file, analyze_module, enhanced_analyze_module
from nidhogg.core.simulator import SimulatedIO
from nidhogg.core.network_interceptor import NetworkInterceptor
from nidhogg.analysis.suspicious import SuspiciousFunctionTracer
from nidhogg.analysis.taint import TaintTrackingTracer
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
    taint_tracer = TaintTrackingTracer()
    network_interceptor = NetworkInterceptor()
    any_suspicious = False
    sim_io = SimulatedIO()
    
    with COMPOSITE_TRACER:
        # Push our tracers
        COMPOSITE_TRACER.push_module(suspicious_tracer)
        COMPOSITE_TRACER.push_module(taint_tracer)
        
        with network_interceptor:
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
                                                   tracers=[suspicious_tracer, taint_tracer], 
                                                   enable_coverage=True)
                        else:
                            analyze_module(module, spec, sim_io, 
                                          tracers=[suspicious_tracer, taint_tracer])
                    except Exception as e:
                        debug(f"Error analyzing {path}: {e}")
                
                elif path.is_dir():
                    for python_file in path.glob('**/*.py'):
                        debug(f"\nAnalyzing file: {python_file}")
                        try:
                            module, spec = load_module_from_file(python_file)
                            if enable_coverage:
                                enhanced_analyze_module(module, spec, sim_io, 
                                                       tracers=[suspicious_tracer, taint_tracer], 
                                                       enable_coverage=True)
                            else:
                                analyze_module(module, spec, sim_io, 
                                              tracers=[suspicious_tracer, taint_tracer])
                        except Exception as e:
                            debug(f"Error analyzing {python_file}: {e}")
        
        # Clean up tracers
        COMPOSITE_TRACER.pop_config(taint_tracer)
        COMPOSITE_TRACER.pop_config(suspicious_tracer)
    
    # Display suspicious findings
    print("\n=== SUSPICIOUS FUNCTIONS ===")
    findings = suspicious_tracer.get_findings()
    
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
    
    # Display taint analysis findings
    taint_report = taint_tracer.get_report()
    
    if taint_report['total_tainted_vars'] > 0 or taint_report['total_exfiltration_attempts'] > 0:
        print("\n=== DATA FLOW ANALYSIS ===")
        print(f"Found {taint_report['total_tainted_vars']} tainted variables")
        
        if verbose:
            for var in taint_report["tainted_variables"]:
                print(f"  - {var['name']}: {', '.join(var['taints'])}")
        
        print(f"\nDetected {taint_report['total_exfiltration_attempts']} potential data exfiltration attempts")
        
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
    
    # Analyze network requests captured by the network interceptor
    network_exfiltration = network_interceptor.analyze_data_exfiltration(
        [data['value'] for attempt in taint_report["exfiltration_attempts"] 
         for data in attempt['tainted_data']]
    )
    
    if network_exfiltration:
        print("\n=== NETWORK EXFILTRATION ANALYSIS ===")
        print(f"Detected {len(network_exfiltration)} potential network data exfiltration attempts")
        
        for attempt in network_exfiltration:
            print(f"  - {attempt['source_file']}:{attempt['source_line']}: "
                  f"Potential exfiltration via {attempt['method']} to {attempt['url']}")
            print(f"    Exfiltration type: {attempt['type']}")
            print(f"    Tainted data: {attempt['tainted_data']}")
    
    if not findings and taint_report['total_exfiltration_attempts'] == 0 and not network_exfiltration:
        print("No suspicious patterns or data flow issues detected.")
    
    return 1 if any_suspicious or taint_report['total_exfiltration_attempts'] > 0 or network_exfiltration else 0