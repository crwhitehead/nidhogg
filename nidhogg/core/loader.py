"""
Module and file loading utilities for Nidhogg.

This module provides safe methods for loading Python modules
from files for analysis.
"""

import importlib
import importlib.util
import importlib.machinery
import os
import sys
import types
from typing import Any, Dict, List, Optional, Tuple

from nidhogg.core.utils import normalize_path

"""
Module and file loading utilities for Nidhogg.

This module provides safe methods for loading Python modules
from files for analysis.
"""
from nidhogg.core.utils import normalize_path


def load_module_from_file(file_path: str, 
                          sandbox: bool = True) -> Tuple[types.ModuleType, importlib.machinery.ModuleSpec]:
    """
    Load a module from a file path with optional sandboxing.
    
    Args:
        file_path: Path to the Python file
        sandbox: Whether to apply security restrictions
        
    Returns:
        Tuple of (loaded module, module spec)
        
    Raises:
        ImportError: If the module cannot be loaded
    """
    # Get absolute path to ensure correct module name
    abs_path = normalize_path(file_path)
    
    # Create a module name from the file path
    module_name = os.path.splitext(os.path.basename(abs_path))[0]
    
    # Create spec
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    if spec is None:
        raise ImportError(f"Could not load spec from {abs_path}")
    
    # Create module
    module = importlib.util.module_from_spec(spec)
    
    # Add to sys.modules to allow relative imports
    sys.modules[module_name] = module
    
    return module, spec


def find_functions_in_module(module: types.ModuleType) -> List[Tuple[str, Any]]:
    """
    Find all functions defined in the module.
    
    Args:
        module: Module to inspect
        
    Returns:
        List of (name, function) tuples
    """
    import inspect
    functions = []
    
    for name, value in inspect.getmembers(module):
        # Skip imported functions (only include those defined in the module)
        if inspect.isfunction(value) and value.__module__ == module.__name__:
            functions.append((name, value))
        # Include methods in classes defined in the module
        elif inspect.isclass(value) and value.__module__ == module.__name__:
            for method_name, method in inspect.getmembers(value, inspect.isfunction):
                if not method_name.startswith('__'):  # Skip special methods
                    functions.append((f"{name}.{method_name}", method))
    
    return functions


def import_object_from_path(path: str) -> Tuple[Any, List[str]]:
    """
    Import an object from a string path.
    
    Args:
        path: The import path, e.g., 'module.submodule.function'
        
    Returns:
        The imported object and any remaining path parts
        
    Raises:
        ImportError: If the object cannot be imported
    """
    parts = path.split('.')
    
    # Try different module/attribute combinations
    for i in range(len(parts), 0, -1):
        try:
            module_path = '.'.join(parts[:i])
            module = importlib.import_module(module_path)
            obj = module
            
            for part in parts[i:]:
                obj = getattr(obj, part)
                
            return obj, []
        except (ImportError, AttributeError):
            continue
            
    raise ImportError(f"Could not import {path}")