# nidhogg/analysis/suspicious.py
from typing import List, Dict, Any
from crosshair.tracers import TracingModule
import random

from nidhogg.core.safe_replacements import (
    safe_eval, safe_exec, safe_system, safe_popen, safe_subprocess_run,
    safe_pickle_loads, safe_urlopen, safe_open, safe_import
)
from nidhogg.utils.debug import debug

class SuspiciousFunctionTracer(TracingModule):
    """Tracer that identifies and neutralizes suspicious function calls"""
    
    def __init__(self):
        # Define suspicious functions to monitor and their replacements
        self.suspicious_functions = {
            'eval': {
                'module': 'builtins', 
                'risk': 'high', 
                'description': 'Dynamic code execution',
                'replacement': safe_eval
            },
            'exec': {
                'module': 'builtins', 
                'risk': 'high', 
                'description': 'Dynamic code execution',
                'replacement': safe_exec
            },
            'system': {
                'module': 'posix', # technically stored here
                'risk': 'high', 
                'description': 'Command execution',
                'replacement': safe_system
            },
            'popen': {
                'module': 'os', 
                'risk': 'high', 
                'description': 'Command execution',
                'replacement': safe_popen
            },
            'run': {
                'module': 'subprocess', 
                'risk': 'high', 
                'description': 'Command execution',
                'replacement': safe_subprocess_run
            },
            'call': {
                'module': 'subprocess', 
                'risk': 'high', 
                'description': 'Command execution',
                'replacement': safe_subprocess_run
            },
            'check_output': {
                'module': 'subprocess', 
                'risk': 'high', 
                'description': 'Command execution',
                'replacement': lambda *a, **kw: b"[BLOCKED SUBPROCESS]"
            },
            'urlopen': {
                'module': 'urllib.request', 
                'risk': 'medium', 
                'description': 'Network access',
                'replacement': safe_urlopen
            },
            'load': {
                'module': 'pickle', 
                'risk': 'high', 
                'description': 'Unsafe deserialization',
                'replacement': lambda *a, **kw: "[BLOCKED PICKLE]"
            },
            'loads': {
                'module': 'pickle', 
                'risk': 'high', 
                'description': 'Unsafe deserialization',
                'replacement': safe_pickle_loads
            },
            'open': {
                'module': 'builtins', 
                'risk': 'low', 
                'description': 'File operation',
                'replacement': safe_open
            },
            '__import__': {
                'module': 'builtins', 
                'risk': 'medium', 
                'description': 'Dynamic import',
                'replacement': safe_import
            },
        }
        self.findings = []
        
        # System paths to ignore/whitelist (to avoid false positives)
        self.system_paths = [
            "<frozen importlib",
            "/usr/lib/python",
            "lib/python",
            "site-packages/",
            "__pycache__",
            "nidhogg"
        ]
    
    def is_system_path(self, path: str) -> bool:
        """Check if a path is a system module path to be ignored"""
        return any(system_path in path for system_path in self.system_paths)
    
    def trace_call(self, frame, fn, binding_target):
        """Intercept function calls - return replacements for dangerous functions"""
        try:
            fn_name = getattr(fn, "__name__", None)
            fn_module = getattr(fn, "__module__", None)
            #print("Calling ", fn_name, fn_module)
            if fn_name and fn_module:
                # Skip system modules
                filename = frame.f_code.co_filename
                if self.is_system_path(filename):
                    return None
                
                # Check for suspicious functions
                for sus_fn, details in self.suspicious_functions.items():
                    if fn_name == sus_fn and (
                        fn_module == details['module'] or 
                        fn_module.startswith(details['module'] + '.')
                    ):
                        lineno = frame.f_lineno
                        
                        # Get argument info
                        arg_info = self._get_args_info(frame, fn)
                        
                        # Record the finding
                        self.findings.append({
                            'function': f"{fn_module}.{fn_name}",
                            'risk': details['risk'],
                            'description': details['description'],
                            'filename': filename,
                            'line': lineno,
                            'args': arg_info,
                        })
                        
                        debug(f"DETECTED & NEUTERED: {fn_module}.{fn_name} at {filename}:{lineno}")
                        
                        # Return the safe replacement function
                        return details['replacement']
        except Exception as e:
            debug(f"Error in tracer: {e}")
        
        return None
    
    def _get_args_info(self, frame, fn):
        """Get info about arguments if possible"""
        try:
            # Try different approaches to get argument info
            if hasattr(frame, 'f_locals'):
                # Try to get parameter names from function
                params = {}
                if hasattr(fn, '__code__'):
                    for i, name in enumerate(fn.__code__.co_varnames[:fn.__code__.co_argcount]):
                        if name in frame.f_locals:
                            value = frame.f_locals[name]
                            params[name] = str(value)[:100]  # Limit to 100 chars
                    return params
                
                # Fallback - just return the first arg if available
                if len(frame.f_locals) > 0:
                    first_arg = list(frame.f_locals.values())[0]
                    return {'arg': str(first_arg)[:100]}
        except:
            pass
        return {}
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all suspicious function findings"""
        return self.findings