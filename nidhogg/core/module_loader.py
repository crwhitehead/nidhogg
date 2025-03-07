import importlib
import importlib.util
import inspect
import contextlib
import ast
import sys
import os
import linecache
import traceback
from pathlib import Path
import types
from typing import Tuple, Dict, Any, Optional, List, Set, Callable

from nidhogg.core.simulator import SimulatedIO
from nidhogg.utils.debug import (
    debug, trace_execution, trace_line, LineTracer, 
    coverage_info, get_debug_level, DEBUG_TRACE, DEBUG_VERBOSE
)
from nidhogg.core.import_handler import safe_import

class FunctionCoverage:
    """Tracks execution coverage for functions in modules"""
    
    def __init__(self):
        self.functions_analyzed = set()
        self.executed_lines = {}
        self.function_results = {}
        self.current_function = None
    
    def register_function(self, function_name, filename, source_code, lineno):
        """Register a function for coverage tracking"""
        key = f"{filename}:{function_name}"
        self.functions_analyzed.add(key)
        
        # Store line range information for this function
        if filename not in self.executed_lines:
            self.executed_lines[filename] = set()
        
        # Parse the source code to get line count (approximately)
        lines = source_code.count('\n') + 1
        self.function_results[key] = {
            'name': function_name,
            'filename': filename,
            'lineno': lineno,
            'called': False,
            'line_count': lines,
            'exceptions': []
        }
    
    def mark_function_called(self, function_name, filename, success=True, exception=None):
        """Mark a function as called with success/failure status"""
        key = f"{filename}:{function_name}"
        if key in self.function_results:
            self.function_results[key]['called'] = True
            if exception:
                self.function_results[key]['exceptions'].append(str(exception))
    
    def record_line(self, filename, lineno):
        """Record an executed line"""
        if filename in self.executed_lines:
            self.executed_lines[filename].add(lineno)
    
    def get_coverage_summary(self):
        """Get a summary of function coverage"""
        total = len(self.function_results)
        called = sum(1 for data in self.function_results.values() if data['called'])
        
        summary = {
            'total_functions': total,
            'analyzed_functions': called,
            'coverage_percentage': (called / total * 100) if total > 0 else 0,
            'function_details': self.function_results,
            'executed_lines': self.executed_lines
        }
        
        return summary

# Global coverage tracker
coverage_tracker = FunctionCoverage()

@trace_execution
def load_module_from_file(file_path) -> Tuple[types.ModuleType, importlib.machinery.ModuleSpec]:
    """Load a Python module from a file path without importing it"""
    file_path = Path(file_path).resolve()
    module_name = file_path.stem
    
    debug(f"Loading module from file: {file_path}", level=DEBUG_VERBOSE)
    
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise ImportError(f"Could not load spec for {file_path}")
    
    module = importlib.util.module_from_spec(spec)
    
    # Temporarily modify sys.path to allow relative imports
    original_import = builtins.__import__
    builtins.__import__ = safe_import
    try:
        debug(f"Executing module: {module_name}", level=DEBUG_VERBOSE)
        spec.loader.exec_module(module)
    except Exception as e:
        debug(f"Error executing module: {e}", level=DEBUG_VERBOSE)
    finally:
        builtins.__import__ = original_import
    
    return module, spec

def get_function_source(func):
    """Get source code for a function"""
    try:
        return inspect.getsource(func)
    except (TypeError, OSError):
        return "# Source code not available"

def get_argument_values(func, param_types=None):
    """
    Generate appropriate argument values for a function based on its signature and type hints.
    
    Args:
        func: The function to generate arguments for
        param_types: Optional parameter type overrides
        
    Returns:
        Dictionary of parameter names and appropriate values
    """
    sig = inspect.signature(func)
    args = {}
    
    for param_name, param in sig.parameters.items():
        # Get the parameter type
        param_type = param_types.get(param_name, param.annotation) if param_types else param.annotation
        param_type_name = str(param_type)
        
        # Use default value if available
        if param.default is not inspect.Parameter.empty:
            args[param_name] = param.default
        elif param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
            # Generate appropriate values based on type
            if param_type is int or 'int' in param_type_name:
                args[param_name] = 0
            elif param_type is float or 'float' in param_type_name:
                args[param_name] = 0.0
            elif param_type is str or 'str' in param_type_name:
                args[param_name] = ""
            elif param_type is bool or 'bool' in param_type_name:
                args[param_name] = False
            elif param_type is list or 'list' in param_type_name or 'List' in param_type_name:
                args[param_name] = []
            elif param_type is dict or 'dict' in param_type_name or 'Dict' in param_type_name:
                args[param_name] = {}
            elif param_type is set or 'set' in param_type_name or 'Set' in param_type_name:
                args[param_name] = set()
            elif param_type is tuple or 'tuple' in param_type_name or 'Tuple' in param_type_name:
                args[param_name] = ()
            elif param_type is bytes or 'bytes' in param_type_name:
                args[param_name] = b""
            else:
                args[param_name] = None
    
    return args

def execute_function_with_tracing(func, args):
    """Execute a function with line-by-line tracing"""
    # Set up tracing for line coverage
    if get_debug_level() >= DEBUG_TRACE:
        # Use the LineTracer context manager for line-by-line tracing
        with LineTracer():
            try:
                result = func(**args)
                return result, None
            except Exception as e:
                return None, e
    else:
        # Execute without line tracing
        try:
            result = func(**args)
            return result, None
        except Exception as e:
            return None, e

@trace_execution
def analyze_module(module, spec, sim_io, tracers=None):
    """
    Analyze a module by loading it and executing its functions.
    
    Args:
        module: The module to analyze
        spec: Module spec
        sim_io: Simulated I/O handler
        tracers: Optional list of tracers to use
    """
    debug(f"Analyzing module: {module.__name__}", level=DEBUG_VERBOSE)
    
    # Load the module - this executes top-level code
    try:
        with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
            debug(f"Executing module top-level code: {module.__name__}", level=DEBUG_VERBOSE)
            spec.loader.exec_module(module)
    except Exception as e:
        debug(f"Error executing module: {str(e)}", level=DEBUG_VERBOSE)
        traceback.print_exc()
    
    # Find and execute functions in the module
    functions_found = 0
    functions_executed = 0
    
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            functions_found += 1
            try:
                # Get function source code and register for coverage
                source_code = get_function_source(obj)
                filename = inspect.getfile(obj)
                lineno = obj.__code__.co_firstlineno
                
                coverage_tracker.register_function(name, filename, source_code, lineno)
                
                # Get default arguments for the function
                args = get_argument_values(obj)
                
                # Skip if we have parameters we can't handle
                if len(args) != len(inspect.signature(obj).parameters) and len(inspect.signature(obj).parameters) > 0:
                    debug(f"Skipping {name}: cannot determine all argument values", level=DEBUG_VERBOSE)
                    continue
                
                debug(f"Executing function {name}() with args: {args}", level=DEBUG_VERBOSE)
                
                # Execute the function with I/O redirection
                with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                    result, exception = execute_function_with_tracing(obj, args)
                
                # Update coverage information
                coverage_tracker.mark_function_called(name, filename, exception is None, exception)
                
                if exception:
                    debug(f"Exception in {name}: {type(exception).__name__}: {str(exception)}", level=DEBUG_VERBOSE)
                else:
                    functions_executed += 1
                    debug(f"Successfully executed {name}() => {repr(result)[:100]}", level=DEBUG_VERBOSE)
                
            except Exception as e:
                debug(f"Error analyzing {name}: {str(e)}", level=DEBUG_VERBOSE)
    
    debug(f"Module analysis complete: {module.__name__}. Found {functions_found} functions, executed {functions_executed} successfully.", level=DEBUG_VERBOSE)

# Predefined sets of boundary values for different types
BOUNDARY_VALUES = {
    "str": ["", "   ", "test", "'; DROP TABLE users; --", "a" * 1000],
    "int": [0, 1, -1, 2**31-1, -2**31],
    "float": [0.0, 1.0, -1.0, float('inf'), float('-inf'), float('nan')],
    "bool": [True, False, None],
    "list": [[], [None], [1, 2, 3], ["a", "b", "c"]],
    "dict": [{}, {"key": "value"}, {i: i for i in range(5)}],
    "set": [set(), {1, 2, 3}],
    "tuple": [(), (1, 2), ("a", "b")],
    "none": [None],
}

@trace_execution
def enhanced_analyze_module(module, spec, sim_io, tracers=None, enable_coverage=False):
    """
    Enhanced module analysis with better path coverage.
    
    Args:
        module: The module to analyze
        spec: Module spec
        sim_io: Simulated I/O handler
        tracers: Optional list of tracers to use
        enable_coverage: Whether to enable enhanced coverage
    """
    # First do normal analysis
    debug(f"Starting standard analysis for module: {module.__name__}", level=DEBUG_VERBOSE)
    analyze_module(module, spec, sim_io, tracers)
    
    if not enable_coverage:
        return
    
    # Enhanced analysis starts
    coverage_info(f"=== STARTING ENHANCED COVERAGE ANALYSIS FOR {module.__name__} ===")
    
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            try:
                coverage_info(f"Testing function {name}() with boundary values")
                
                # Get function signature
                sig = inspect.signature(obj)
                source_code = get_function_source(obj)
                
                # Show function definition for clarity
                source_lines = source_code.strip().split('\n')
                coverage_info(f"Function definition: {source_lines[0]}")
                
                # Define multiple boundary value sets to test different code paths
                test_sets = []
                
                # Add first test with all default/empty values
                default_args = get_argument_values(obj)
                test_sets.append(("default/empty values", default_args.copy()))
                
                # Add boundary value test sets - try different combinations
                for param_name, param in sig.parameters.items():
                    param_type = str(param.annotation)
                    
                    # Create test sets for each parameter's boundary values
                    for boundary_type, values in BOUNDARY_VALUES.items():
                        if boundary_type in param_type.lower():
                            for i, value in enumerate(values):
                                test_args = default_args.copy()
                                test_args[param_name] = value
                                test_sets.append((f"{param_name}={value}", test_args))
                
                # Execute with each test set
                for i, (description, test_args) in enumerate(test_sets):
                    coverage_info(f"Test #{i+1}: {name}() with {description}")
                    
                    try:
                        with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                            result, exception = execute_function_with_tracing(obj, test_args)
                        
                        if exception:
                            coverage_info(f"  ✗ Exception: {type(exception).__name__}: {str(exception)}")
                        else:
                            coverage_info(f"  ✓ Returned: {repr(result)[:100]}")
                    except Exception as e:
                        coverage_info(f"  ✗ Test error: {str(e)}")
                
            except Exception as e:
                coverage_info(f"Error in enhanced analysis of {name}: {str(e)}")
    
    # Print coverage summary
    coverage_summary = coverage_tracker.get_coverage_summary()
    coverage_info(f"=== COVERAGE SUMMARY FOR {module.__name__} ===")
    coverage_info(f"Total functions: {coverage_summary['total_functions']}")
    coverage_info(f"Analyzed functions: {coverage_summary['analyzed_functions']}")
    coverage_info(f"Coverage: {coverage_summary['coverage_percentage']:.2f}%")
    
    # Detailed function coverage
    coverage_info("Function details:")
    for key, details in coverage_summary['function_details'].items():
        status = "✓" if details['called'] else "✗"
        coverage_info(f"  {status} {details['name']} (line {details['lineno']})")
        if details['exceptions']:
            coverage_info(f"    Exceptions: {', '.join(details['exceptions'])}")

# Make sure builtins is imported
import builtins