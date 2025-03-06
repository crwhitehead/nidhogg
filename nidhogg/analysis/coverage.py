# nidhogg/analysis/coverage.py
import sys
import inspect
import contextlib
from typing import Optional, Dict, Any

from crosshair.options import AnalysisKind, AnalysisOptions
from crosshair.analyzer import analyze_function
from nidhogg.utils.debug import debug

def setup_crosshair_options() -> AnalysisOptions:
    """Configure CrossHair options for maximum coverage"""
    # Create options that comply with CrossHair's API
    options = AnalysisOptions(
        analysis_kind=(AnalysisKind.PEP316,),  # Focus on PEP316-style contracts
        enabled=True,
        specs_complete=False,
        max_iterations=1000,
        timeout=10.0,
        per_condition_timeout=4.0,
        per_path_timeout=1.0,
        max_uninteresting_iterations=5,
        report_all=True,
        report_verbose=True
    )
    return options

def analyze_with_crosshair(func, sim_io=None) -> Dict[str, Any]:
    """
    Analyze a function using CrossHair's symbolic execution.
    
    Args:
        func: The function to analyze
        sim_io: Optional SimulatedIO object for redirecting output
    
    Returns:
        Dict containing analysis results and coverage information
    """
    # Create a wrapper function with pre/post conditions
    def wrapper_with_contracts(*args, **kwargs):
        """
        pre: True
        post: True
        """
        if sim_io:
            #with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
            return func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    
    # Copy metadata from original function
    wrapper_with_contracts.__module__ = func.__module__
    wrapper_with_contracts.__name__ = f"wrapped_{func.__name__}"
    wrapper_with_contracts.__qualname__ = f"wrapped_{func.__qualname__ if hasattr(func, '__qualname__') else func.__name__}"
    
    # Get CrossHair options
    options = setup_crosshair_options()
    
    # Analyze the function
    results = {}
    try:
        debug(f"Starting CrossHair analysis of {func.__name__}")
        analyze_function(wrapper_with_contracts, options)
        results["status"] = "completed"
    except Exception as e:
        debug(f"Error during CrossHair analysis: {e}")
        results["status"] = "error"
        results["error"] = str(e)
    
    return results

def generate_boundary_values(param_type: str) -> list:
    """
    Generate boundary values for a given parameter type to improve code coverage.
    
    Args:
        param_type: The type annotation as a string
    
    Returns:
        List of boundary values to test
    """
    if "str" in param_type.lower():
        return ["", "   ", "test", "'; SHOW TABLES; --", "a" * 1000]
    elif "int" in param_type.lower():
        return [0, 1, -1, sys.maxsize, -sys.maxsize - 1]
    elif "float" in param_type.lower():
        return [0.0, 1.0, -1.0, float('inf'), float('-inf'), float('nan')]
    elif "bool" in param_type.lower():
        return [True, False, None]
    elif "list" in param_type.lower() or "List" in param_type:
        return [[], [None], [1, 2, 3], ["a", "b", "c"]]
    elif "dict" in param_type.lower() or "Dict" in param_type:
        return [{}, {"key": "value"}, {i: i for i in range(5)}]
    elif "set" in param_type.lower() or "Set" in param_type:
        return [set(), {1, 2, 3}]
    elif "tuple" in param_type.lower() or "Tuple" in param_type:
        return [(), (1, 2), ("a", "b")]
    elif "none" in param_type.lower() or "None" in param_type:
        return [None]
    else:
        return [None]

def explore_paths(func, sim_io=None, max_combinations=5):
    """
    Explore multiple execution paths in a function using boundary values.
    
    Args:
        func: The function to analyze
        sim_io: Optional SimulatedIO object for redirecting output
        max_combinations: Maximum number of parameter combinations to try
    
    Returns:
        Dict containing execution results
    """
    try:
        sig = inspect.signature(func)
        import random
        import itertools
        
        # Generate boundary values for each parameter
        param_values = {}
        for param_name, param in sig.parameters.items():
            param_type = str(param.annotation)
            param_values[param_name] = generate_boundary_values(param_type)
        
        # Try a limited number of combinations
        executed_paths = 0
        exceptions = []
        
        # Generate all possible combinations if feasible
        # Otherwise randomly sample
        combinations = []
        for _ in range(max_combinations):
            args = {}
            for param_name, values in param_values.items():
                args[param_name] = random.choice(values)
            combinations.append(args)
    
        # Execute with each combination
        for args in combinations:
            try:
                if sim_io:
                    with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                        func(**args)
                else:
                    func(**args)
                executed_paths += 1
            except Exception as e:
                exceptions.append({
                    "args": str(args),
                    "error": str(e)
                })
                executed_paths += 1  # Count exception paths
        
        return {
            "status": "completed",
            "paths_executed": executed_paths,
            "exceptions": len(exceptions)
        }
            
    except Exception as e:
        debug(f"Error in path exploration: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

def force_exception_handlers(func, sim_io=None):
    """
    Try to trigger exception handlers in the function by providing
    inputs likely to cause exceptions.
    
    Args:
        func: The function to analyze
        sim_io: Optional SimulatedIO object for redirecting output
    
    Returns:
        Dict containing execution results
    """
    try:
        # First, check if there are exception handlers
        source = inspect.getsource(func)
        if "except" not in source and "finally" not in source:
            return {"status": "skipped", "reason": "no exception handlers"}
        
        sig = inspect.signature(func)
        args = {}
        
        # Create args that will likely cause exceptions
        for param_name, param in sig.parameters.items():
            param_type = str(param.annotation)
            if "int" in param_type.lower():
                args[param_name] = "not_an_int"  # Type error
            elif "str" in param_type.lower():
                args[param_name] = None  # NoneType error
            elif "list" in param_type.lower() or "List" in param_type:
                args[param_name] = {1: 'not_a_list'}  # Wrong type
            elif "dict" in param_type.lower() or "Dict" in param_type:
                args[param_name] = [1, 2, 3]  # Wrong type
            else:
                # Something that will likely cause attribute errors
                class BrokenObject:
                    def __getattr__(self, name):
                        if random.random() < 0.5:
                            raise AttributeError(f"'BrokenObject' has no attribute '{name}'")
                        return None
                    
                    def __str__(self):
                        return "BrokenObject"
                
                args[param_name] = BrokenObject()
        
        try:
            if sim_io:
                with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                    func(**args)
            else:
                func(**args)
            return {"status": "executed", "exception_triggered": False}
        except Exception as e:
            return {"status": "executed", "exception_triggered": True, "exception": str(e)}
            
    except Exception as e:
        debug(f"Error trying to trigger exception handlers: {e}")
        return {"status": "error", "error": str(e)}