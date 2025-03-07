# crosshair/import_handler.py
import importlib
import importlib.util
import sys
import types
from typing import Optional, Any, Dict, Union
import builtins

def create_simulated_module(module_name: str) -> types.ModuleType:
    """
    Create a simulated module when actual import fails.
    
    Args:
        module_name: Name of the module to simulate
    
    Returns:
        A simulated module type
    """
    # Split the module name to handle nested modules
    parts = module_name.split('.')
    
    # Create the base module
    simulated_module = types.ModuleType(module_name)
    simulated_module.__file__ = f"[SIMULATED] {module_name}"
    simulated_module.__dict__['__simulated__'] = True
    
    # For nested modules, create parent modules as needed
    current_module = simulated_module
    for i in range(len(parts) - 1):
        parent_name = '.'.join(parts[:i+1])
        parent_module = types.ModuleType(parent_name)
        parent_module.__file__ = f"[SIMULATED] {parent_name}"
        parent_module.__dict__['__simulated__'] = True
        setattr(parent_module, parts[i+1], current_module)
        current_module = parent_module
        sys.modules[parent_name] = parent_module
    
    # Add to sys.modules to prevent re-importing
    sys.modules[module_name] = simulated_module
    
    return simulated_module

GLOBAL_ORIGINAL_IMPORT = builtins.__import__

def safe_import(name: str, 
                globals: Optional[Dict[str, Any]] = None, 
                locals: Optional[Dict[str, Any]] = None, 
                fromlist: tuple = (), 
                level: int = 0) -> Union[types.ModuleType, Any]:
    """
    Safe import function that creates simulated modules when imports fail.
    
    This function mimics the behavior of __import__(), but creates simulated 
    modules for missing dependencies.
    
    Args:
        name: Name of the module to import
        globals: Global namespace dictionary
        locals: Local namespace dictionary
        fromlist: Tuple of names to import
        level: Relative import level (0 = absolute import)
    
    Returns:
        The imported (or simulated) module
    """
    print("Importinging", name, fromlist, level)
    try:
        # First, try standard import with the full import signature
        return GLOBAL_ORIGINAL_IMPORT(name, globals, locals, fromlist, level)
    except ImportError:
        # Create a simulated module if import fails
        simulated_module = create_simulated_module(name)
        
        # If fromlist is provided, dynamically create requested attributes
        if fromlist:
            for item in fromlist:
                if not hasattr(simulated_module, item):
                    setattr(simulated_module, item, types.SimpleNamespace())
        
        # Handle relative imports
        if level > 0 and globals and '__name__' in globals:
            parent_module_name = globals['__name__']
            try:
                parent_module = sys.modules.get(parent_module_name)
                if parent_module:
                    # Attach the simulated module to its parent
                    setattr(parent_module, name.split('.')[-1], simulated_module)
            except Exception:
                pass
        
        return simulated_module

def patch_import():
    """
    Patch the built-in import mechanism to use safe import.
    
    This can be used as a context manager or called directly.
    """
    # Store the original import function
    _original_import = __import__
    
    try:
        # Temporarily replace __import__ with safe version
        import builtins
        builtins.__import__ = safe_import
        yield
    finally:
        # Restore the original import function
        builtins.__import__ = _original_import

def override_package_paths():
    """
    Dynamically add potential package paths to sys.path
    
    This helps with relative and local imports during analysis
    """
    import os
    
    # Add current working directory
    current_dir = os.getcwd()
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    
    # Add parent directories
    parent_dirs = [
        os.path.dirname(current_dir),
        os.path.dirname(os.path.dirname(current_dir))
    ]
    for parent in parent_dirs:
        if parent not in sys.path:
            sys.path.append(parent)

# Automatically override import mechanism when this module is imported
override_package_paths()