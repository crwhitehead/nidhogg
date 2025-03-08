"""
Command-line interface for Nidhogg.

This module provides the command-line interface for scanning
Python files with Nidhogg.
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from nidhogg.analyzers.analyzer_factory import AnalyzerFactory
from nidhogg.core.config import AnalysisConfig, load_config
from nidhogg.core.event_system import EventType
from nidhogg.core.loader import find_functions_in_module, load_module_from_file
from nidhogg.core.tracer import create_tracer
from nidhogg.core.utils import colored, format_timestamp, parse_arg
from nidhogg.reporting.reporter_factory import ReporterFactory
from nidhogg.rules.finding import AnalysisResults, Finding, Severity
from nidhogg.rules.rule_engine import RuleEngine, RuleCategory

# Import CrossHair components
from crosshair.core_and_libs import standalone_statespace
from crosshair.tracers import COMPOSITE_TRACER

def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Nidhogg: Python Bytecode Analysis and Malware Detection Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target specification
    parser.add_argument('target', 
                      help='Python file to analyze')
    parser.add_argument('--function', '-f', 
                      help='Function in the module to run')
    parser.add_argument('args', nargs='*', 
                      help='Arguments to pass to the function')
    
    # Analysis options
    parser.add_argument('--trace-stdlib', action='store_true',
                      help='Trace standard library modules (slower but more thorough)')
    parser.add_argument('--sensitivity', choices=['low', 'medium', 'high'], default='medium',
                      help='Detection sensitivity level')
    parser.add_argument('--analyzers', 
                      help='Comma-separated list of analyzers to enable (opcode,call,import,behavioral)')
    
    # Output options
    parser.add_argument('--output', '-o', 
                      help='Output file for report')
    parser.add_argument('--format', choices=['console', 'json', 'json_compact', 'html'], 
                      default='console',
                      help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Include more detailed output')
    parser.add_argument('--config', 
                      help='Path to configuration file')
    
    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    """
    Create an analysis configuration from command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Analysis configuration
    """
    # Start with default config
    config = AnalysisConfig()
    
    # If a config file was specified, load it
    if args.config:
        config = load_config(args.config)
    
    # Override with command-line arguments
    config.target_file = args.target
    config.function_to_run = args.function
    config.function_args = args.args
    config.verbose = args.verbose
    config.trace_stdlib = args.trace_stdlib
    config.sensitivity = args.sensitivity
    config.report_format = args.format
    config.output_file = args.output
    
    # Parse analyzers from comma-separated list
    if args.analyzers:
        config.enabled_analyzers = args.analyzers.split(',')
    
    return config

def run_analysis(config: AnalysisConfig) -> AnalysisResults:
    """
    Run analysis on a Python file.
    
    Args:
        config: Analysis configuration
        
    Returns:
        Analysis results
    """
    # Create results object
    results = AnalysisResults(target_file=config.target_file)
    
    # Create tracer and event dispatcher
    tracer, event_dispatcher = create_tracer(
        target_file=config.target_file,
        trace_stdlib=config.trace_stdlib,
        verbose=config.verbose
    )
    
    # Create analyzers
    analyzers = AnalyzerFactory.create_default_analyzers(
        event_dispatcher=event_dispatcher,
        enabled_analyzers=config.enabled_analyzers,
        sensitivity=config.sensitivity
    )
    
    # Subscribe to findings
    def on_finding(event_data: dict) -> None:
        finding = event_data.get('finding')
        if finding:
            results.add_finding(finding)
    
    event_dispatcher.subscribe(EventType.SUSPICIOUS_PATTERN, on_finding)
    
    # Load rule engine
    rule_engine = RuleEngine()
    rule_engine.load_rules()
    
    try:
        # Print analysis start message
        print(colored(f"[{format_timestamp()}] Starting analysis of {config.target_file}", "cyan"))
        
        # Load the module
        module, spec = load_module_from_file(config.target_file)
        
        # Execute with tracing
        with standalone_statespace as space:
            COMPOSITE_TRACER.push_module(tracer)
            try:
                # Execute the module
                spec.loader.exec_module(module)
                
                # If a specific function was requested, run it
                if config.function_to_run:
                    # Find all functions in the module
                    functions = find_functions_in_module(module)
                    
                    # Find the requested function
                    func = None
                    for name, f in functions:
                        if name == config.function_to_run:
                            func = f
                            break
                    
                    if func is None:
                        print(colored(f"Function {config.function_to_run} not found in module", "red"))
                    else:
                        # Parse arguments
                        func_args = [parse_arg(arg) for arg in config.function_args]
                        
                        # Run the function
                        print(colored(f"Running function {config.function_to_run}", "cyan"))
                        result = func(*func_args)
                        print(colored(f"Function returned: {result}", "cyan"))
            
            finally:
                COMPOSITE_TRACER.pop_config(tracer)
                # Print code coverage statistics if verbose mode is enabled
                if config.verbose and hasattr(tracer, 'print_coverage_statistics'):
                    tracer.print_coverage_statistics()
        
        # Mark analysis as complete
        results.complete()
        
        return results
        
    except Exception as e:
        print(colored(f"Error during analysis: {str(e)}", "red"))
        import traceback
        traceback.print_exc()
        
        # Mark analysis as complete even if there was an error
        results.complete()
        
        return results

def main() -> int:
    """
    Main entry point for the CLI.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    args = parse_args()
    config = create_config_from_args(args)
    
    # Run the analysis
    results = run_analysis(config)
    
    # Create reporter
    reporter = ReporterFactory.create_reporter(
        reporter_type=config.report_format,
        output_file=config.output_file,
        verbose=config.verbose
    )
    
    # Generate report
    reporter.report_findings(results)
    
    # Print summary
    severity_counts = {severity: 0 for severity in Severity}
    for finding in results.findings:
        severity_counts[finding.severity] += 1
    
    # Return non-zero exit code if critical or high severity findings were detected
    if severity_counts[Severity.CRITICAL] > 0 or severity_counts[Severity.HIGH] > 0:
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())