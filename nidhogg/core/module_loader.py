import importlib
import importlib.util
import inspect
import contextlib
from pathlib import Path
import sys
import types
from typing import Tuple, Dict, Any, Optional, List
import builtins

from nidhogg.core.simulator import SimulatedIO
from nidhogg.utils.debug import debug
from nidhogg.core.import_handler import safe_import

def load_module_from_file(file_path) -> Tuple[types.ModuleType, importlib.machinery.ModuleSpec]:
    """Load a Python module from a file path without importing it"""
    file_path = Path(file_path).resolve()
    module_name = file_path.stem
    
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None:
        raise ImportError(f"Could not load spec for {file_path}")
    
    module = importlib.util.module_from_spec(spec)
    
    # Temporarily modify sys.path to allow relative imports

    original_import = builtins.__import__
    builtins.__import__ = safe_import
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        debug(f"Error executing module: {e}")
    finally:
        builtins.__import__ = original_import
    
    return module, spec

def analyze_module(module, spec, sim_io, tracers=None):
    """Analyze a module by loading it and executing its functions"""
    # Load the module - this executes top-level code
    try:
        with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
            spec.loader.exec_module(module)
    except Exception as e:
        debug(f"Error executing module: {e}")
    
    # Find and execute functions in the module
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            try:
                # Get default arguments for the function
                sig = inspect.signature(obj)
                args = {}
                for param_name, param in sig.parameters.items():
                    if param.default is not inspect.Parameter.empty:
                        args[param_name] = param.default
                    elif param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
                        # For simple types, use safe defaults
                        if param.annotation is int:
                            args[param_name] = 0
                        elif param.annotation is str:
                            args[param_name] = ""
                        elif param.annotation is bool:
                            args[param_name] = False
                        elif param.annotation is list or str(param.annotation).startswith("typing.List"):
                            args[param_name] = []
                        elif param.annotation is dict or str(param.annotation).startswith("typing.Dict"):
                            args[param_name] = {}
                        elif param.annotation is set or str(param.annotation).startswith("typing.Set"):
                            args[param_name] = set()
                        else:
                            args[param_name] = None
                
                # Skip if we have parameters we can't handle
                if len(args) != len(sig.parameters) and len(sig.parameters) > 0:
                    debug(f"Skipping {name}: cannot determine all argument values")
                    continue
                
                debug(f"Executing function {name} with args {args}")
                with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                    obj(**args)
            except Exception as e:
                debug(f"Error executing {name}: {e}")

def enhanced_analyze_module(module, spec, sim_io, tracers=None, enable_coverage=False):
    """Enhanced module analysis with better path coverage"""
    # First do normal analysis
    analyze_module(module, spec, sim_io, tracers)
    
    if not enable_coverage:
        return

    # Additional analysis for improved coverage
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) and obj.__module__ == module.__name__:
            try:
                # Get default arguments for the function
                sig = inspect.signature(obj)
                
                # Define boundary values to test different code paths
                boundary_sets = [
                    # Empty/null values
                    {"str_args": "", "int_args": 0, "list_args": [], "dict_args": {}, "bool_args": False},
                    # Edge cases
                    {"str_args": "   ", "int_args": -1, "list_args": [None], "dict_args": {"key": None}, "bool_args": True},
                    # Potentially problematic values 
                    {"str_args": "'; DROP TABLE users; --", "int_args": sys.maxsize, "list_args": [1, 2, 3] * 10, 
                     "dict_args": {i: i for i in range(10)}, "bool_args": None},
                ]
                
                for boundary_set in boundary_sets:
                    boundary_args = {}
                    for param_name, param in sig.parameters.items():
                        if param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
                            param_type = str(param.annotation)
                            if "str" in param_type:
                                boundary_args[param_name] = boundary_set["str_args"]
                            elif "int" in param_type:
                                boundary_args[param_name] = boundary_set["int_args"]
                            elif "list" in param_type.lower() or "List" in param_type:
                                boundary_args[param_name] = boundary_set["list_args"]
                            elif "dict" in param_type.lower() or "Dict" in param_type:
                                boundary_args[param_name] = boundary_set["dict_args"]
                            elif "bool" in param_type:
                                boundary_args[param_name] = boundary_set["bool_args"]
                            else:
                                boundary_args[param_name] = None
                    
                    if len(boundary_args) == len(sig.parameters) or len(sig.parameters) == 0:
                        debug(f"Executing function {name} with boundary args {boundary_args}")
                        try:
                            with contextlib.redirect_stdout(sim_io.stdout), contextlib.redirect_stderr(sim_io.stderr):
                                obj(**boundary_args)
                        except Exception as e:
                            debug(f"Expected error with boundary values in {name}: {e}")
                
            except Exception as e:
                debug(f"Error in enhanced analysis of {name}: {e}")