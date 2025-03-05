# nidhogg/analysis/taint.py
import re
import inspect
import ast
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from crosshair.tracers import TracingModule

from nidhogg.utils.debug import debug

# Define taint types
class TaintType(Enum):
    FILE_DATA = auto()       # Data read from files
    ENV_DATA = auto()        # Environment variables
    CONFIG_DATA = auto()     # Configuration files
    USER_INPUT = auto()      # User-provided input
    CREDENTIAL = auto()      # Passwords, tokens, keys
    PERSONAL_DATA = auto()   # PII, names, addresses, etc.
    DATABASE = auto()        # Database query results
    SYSTEM_INFO = auto()     # System/hardware information
    
    def __str__(self):
        return self.name

# Taint propagation levels
class PropagationLevel(Enum):
    DIRECT = auto()          # Direct assignment
    DERIVED = auto()         # Mathematical/string operations on tainted data
    CONDITIONAL = auto()     # Control flow influenced by tainted data
    
    def __str__(self):
        return self.name

@dataclass
class TaintInfo:
    """Stores information about a taint and its source"""
    taint_type: TaintType
    source: str              # Source of the taint (e.g., function name or file path)
    propagation: PropagationLevel = PropagationLevel.DIRECT
    line_number: Optional[int] = None
    original_value: Any = None
    
    def __str__(self):
        return f"{self.taint_type} from {self.source} (line {self.line_number or 'unknown'}, {self.propagation})"

@dataclass
class TaintedVariable:
    """Represents a tainted variable with its metadata"""
    name: str
    taints: List[TaintInfo] = field(default_factory=list)
    
    def add_taint(self, taint_info: TaintInfo):
        self.taints.append(taint_info)
    
    def has_taint_type(self, taint_type: TaintType) -> bool:
        return any(t.taint_type == taint_type for t in self.taints)
    
    def __str__(self):
        return f"{self.name}: {', '.join(str(t) for t in self.taints)}"

class TaintTracker:
    """Tracks tainted variables and their propagation"""
    
    def __init__(self):
        # Dictionary mapping variable IDs to their taint information
        self.tainted_vars: Dict[int, TaintedVariable] = {}
        
        # Variables indexed by name for faster lookup
        self.var_by_name: Dict[str, Set[int]] = {}
        
        # Define source functions that introduce taint
        self.taint_sources = {
            # File operations - FILE_DATA taint
            'open': {'module': 'builtins', 'taint_type': TaintType.FILE_DATA},
            'read': {'module': 'io', 'taint_type': TaintType.FILE_DATA},
            'readline': {'module': 'io', 'taint_type': TaintType.FILE_DATA},
            'readlines': {'module': 'io', 'taint_type': TaintType.FILE_DATA},
            'load': {'module': 'json', 'taint_type': TaintType.FILE_DATA},
            'loads': {'module': 'json', 'taint_type': TaintType.FILE_DATA},
            'read_csv': {'module': 'pandas', 'taint_type': TaintType.FILE_DATA},
            'read_excel': {'module': 'pandas', 'taint_type': TaintType.FILE_DATA},
            'read_sql': {'module': 'pandas', 'taint_type': TaintType.DATABASE},
            
            # Environment/system info - ENV_DATA taint
            'getenv': {'module': 'os', 'taint_type': TaintType.ENV_DATA},
            'environ': {'module': 'os', 'taint_type': TaintType.ENV_DATA},
            'uname': {'module': 'os', 'taint_type': TaintType.SYSTEM_INFO},
            'gethostname': {'module': 'socket', 'taint_type': TaintType.SYSTEM_INFO},
            'getuser': {'module': 'getpass', 'taint_type': TaintType.SYSTEM_INFO},
            
            # User input - USER_INPUT taint
            'input': {'module': 'builtins', 'taint_type': TaintType.USER_INPUT},
            'raw_input': {'module': 'builtins', 'taint_type': TaintType.USER_INPUT},
            'getpass': {'module': 'getpass', 'taint_type': TaintType.CREDENTIAL},
            
            # Config parsers - CONFIG_DATA taint
            'ConfigParser': {'module': 'configparser', 'taint_type': TaintType.CONFIG_DATA},
            'parse': {'module': 'configparser', 'taint_type': TaintType.CONFIG_DATA},
            'get': {'module': 'configparser.ConfigParser', 'taint_type': TaintType.CONFIG_DATA},
            
            # Database operations - DATABASE taint
            'execute': {'module': 'sqlite3.Cursor', 'taint_type': TaintType.DATABASE},
            'fetchone': {'module': 'sqlite3.Cursor', 'taint_type': TaintType.DATABASE},
            'fetchall': {'module': 'sqlite3.Cursor', 'taint_type': TaintType.DATABASE},
            'query': {'module': 'pymysql.connections', 'taint_type': TaintType.DATABASE},
            
            # Credentials - CREDENTIAL taint
            'get_credentials': {'module': 'keyring', 'taint_type': TaintType.CREDENTIAL},
            'getpass': {'module': 'getpass', 'taint_type': TaintType.CREDENTIAL},
            'get_password': {'module': 'keyring', 'taint_type': TaintType.CREDENTIAL},
        }
        
        # Define sensitive patterns to detect in string literals
        self.sensitive_patterns = {
            TaintType.CREDENTIAL: [
                r'password\s*=',
                r'passwd\s*=',
                r'secret\s*=',
                r'api[-_]?key\s*=',
                r'access[-_]?token\s*=',
                r'auth[-_]?token\s*=',
                r'BEGIN.*PRIVATE KEY',
            ],
            TaintType.PERSONAL_DATA: [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b',  # SSN
                r'\b(?:\d{16}|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b',  # Credit card
            ]
        }
        
        # Define exfiltration sinks - functions that could leak data
        self.exfiltration_sinks = {
            # Network operations
            'urlopen': {'module': 'urllib.request'},
            'Request': {'module': 'urllib.request'},
            'send': {'module': 'socket.socket'},
            'sendall': {'module': 'socket.socket'},
            'sendto': {'module': 'socket.socket'},
            'connect': {'module': 'socket.socket'},
            'post': {'module': 'requests'},
            'get': {'module': 'requests'},
            'put': {'module': 'requests'},
            'delete': {'module': 'requests'},
            'patch': {'module': 'requests'},
            'request': {'module': 'requests'},
            
            # Process execution
            'system': {'module': 'os'},
            'popen': {'module': 'os'},
            'spawn': {'module': 'os'},
            'call': {'module': 'subprocess'},
            'run': {'module': 'subprocess'},
            'check_output': {'module': 'subprocess'},
            'check_call': {'module': 'subprocess'},
            'exec': {'module': 'builtins'},
            
            # File writing
            'write': {'module': 'io'},
            'writelines': {'module': 'io'},
            'dump': {'module': 'json'},
            'dumps': {'module': 'json'},
            'save': {'module': 'pickle'},
            'to_csv': {'module': 'pandas.DataFrame'},
            'to_excel': {'module': 'pandas.DataFrame'},
            
            # Other potential exfiltration
            'upload_file': {'module': 'requests'},
            'send_message': {'module': 'smtplib'},
            'ftp_upload': {'module': 'ftplib'},
        }
        
        # Storage for detected exfiltration attempts
        self.exfiltration_attempts = []
        
    def taint_variable(self, var_name: str, var_id: int, taint_info: TaintInfo) -> None:
        """Add taint to a variable"""
        if var_id not in self.tainted_vars:
            self.tainted_vars[var_id] = TaintedVariable(var_name)
        
        self.tainted_vars[var_id].add_taint(taint_info)
        
        # Update name index
        if var_name not in self.var_by_name:
            self.var_by_name[var_name] = set()
        self.var_by_name[var_name].add(var_id)
    
    def is_tainted(self, var_id: int) -> bool:
        """Check if a variable is tainted"""
        return var_id in self.tainted_vars
    
    def get_taints(self, var_id: int) -> List[TaintInfo]:
        """Get all taints associated with a variable"""
        if var_id in self.tainted_vars:
            return self.tainted_vars[var_id].taints
        return []
    
    def propagate_taint(self, from_var_id: int, to_var_id: int, to_var_name: str, 
                        propagation: PropagationLevel = PropagationLevel.DIRECT) -> None:
        """Propagate taint from one variable to another"""
        if not self.is_tainted(from_var_id):
            return
        
        for taint in self.get_taints(from_var_id):
            # Create a new TaintInfo with the propagation level
            new_taint = TaintInfo(
                taint_type=taint.taint_type,
                source=taint.source,
                propagation=propagation,
                line_number=taint.line_number
            )
            self.taint_variable(to_var_name, to_var_id, new_taint)
    
    def propagate_taint_from_name(self, from_var_name: str, to_var_id: int, to_var_name: str,
                                propagation: PropagationLevel = PropagationLevel.DIRECT) -> None:
        """Propagate taint from a variable name to another variable"""
        if from_var_name not in self.var_by_name:
            return
        
        for from_id in self.var_by_name[from_var_name]:
            self.propagate_taint(from_id, to_var_id, to_var_name, propagation)
    
    def detect_sink_usage(self, fn, args: List[Any], kwargs: Dict[str, Any], 
                          frame, result: Any = None) -> Optional[Dict]:
        """Check if tainted data is being passed to an exfiltration sink"""
        fn_name = getattr(fn, "__name__", None)
        fn_module = getattr(fn, "__module__", None)
        
        if not fn_name or not fn_module:
            return None
        
        # Check if this is an exfiltration sink
        found_sink = None
        for sink_name, sink_info in self.exfiltration_sinks.items():
            if fn_name == sink_name and (
                fn_module == sink_info['module'] or 
                fn_module.startswith(sink_info['module'] + '.')
            ):
                found_sink = {'name': sink_name, 'module': fn_module}
                break
        
        if not found_sink:
            return None
        
        # Check for tainted arguments
        tainted_args = []
        
        # Check positional arguments
        for i, arg in enumerate(args):
            arg_id = id(arg)
            if self.is_tainted(arg_id):
                tainted_args.append({
                    'position': i,
                    'value': str(arg)[:100],
                    'taints': [str(t) for t in self.get_taints(arg_id)]
                })
        
        # Check keyword arguments
        for key, arg in kwargs.items():
            arg_id = id(arg)
            if self.is_tainted(arg_id):
                tainted_args.append({
                    'keyword': key,
                    'value': str(arg)[:100],
                    'taints': [str(t) for t in self.get_taints(arg_id)]
                })
        
        # If no tainted arguments, check result for methods that might smuggle data
        # (e.g., connect() doesn't take data directly but might be used to exfiltrate later)
        if not tainted_args and result is not None:
            result_id = id(result)
            if self.is_tainted(result_id):
                tainted_args.append({
                    'result': True,
                    'value': str(result)[:100],
                    'taints': [str(t) for t in self.get_taints(result_id)]
                })
        
        if tainted_args:
            # Found exfiltration attempt
            exfiltration = {
                'sink': found_sink,
                'filename': frame.f_code.co_filename,
                'line': frame.f_lineno,
                'tainted_data': tainted_args
            }
            
            self.exfiltration_attempts.append(exfiltration)
            return exfiltration
        
        return None
    
    def detect_taint_source(self, fn, args: List[Any], kwargs: Dict[str, Any], 
                           frame, result: Any = None) -> Optional[TaintInfo]:
        """Check if a function is a taint source and tag the result"""
        fn_name = getattr(fn, "__name__", None)
        fn_module = getattr(fn, "__module__", None)
        
        if not fn_name or not fn_module:
            return None
        
        # Check if this is a taint source
        for source_name, source_info in self.taint_sources.items():
            if fn_name == source_name and (
                fn_module == source_info['module'] or 
                fn_module.startswith(source_info['module'] + '.')
            ):
                # It's a taint source - create taint info
                taint_info = TaintInfo(
                    taint_type=source_info['taint_type'],
                    source=f"{fn_module}.{fn_name}",
                    line_number=frame.f_lineno,
                    original_value=result
                )
                
                # If there's a result, taint it
                if result is not None:
                    result_id = id(result)
                    self.taint_variable("result", result_id, taint_info)
                
                return taint_info
        
        return None
    
    def detect_string_literals(self, s: str) -> List[TaintInfo]:
        """Detect if a string literal contains sensitive patterns"""
        taints = []
        
        # Check each pattern category
        for taint_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    taint_info = TaintInfo(
                        taint_type=taint_type,
                        source="string_literal",
                        original_value=s
                    )
                    taints.append(taint_info)
                    break  # Only need one match per category
        
        return taints
    
    def analyze_frame(self, frame) -> None:
        """Analyze a stack frame for variable tainting"""
        # Check each local variable for potential taint
        for var_name, value in frame.f_locals.items():
            var_id = id(value)
            
            # String literals - check for sensitive patterns
            if isinstance(value, str):
                taints = self.detect_string_literals(value)
                for taint in taints:
                    self.taint_variable(var_name, var_id, taint)

    def generate_report(self) -> Dict:
        """Generate a report of tainted variables and exfiltration attempts"""
        report = {
            "tainted_variables": [],
            "exfiltration_attempts": self.exfiltration_attempts,
            "total_tainted_vars": len(self.tainted_vars),
            "total_exfiltration_attempts": len(self.exfiltration_attempts),
        }
        
        # Add tainted variables to report
        for var_id, tainted_var in self.tainted_vars.items():
            report["tainted_variables"].append({
                "name": tainted_var.name,
                "taints": [str(t) for t in tainted_var.taints]
            })
        
        return report

class TaintTrackingTracer(TracingModule):
    """Tracer module for tracking data flow between variables"""
    
    def __init__(self):
        self.taint_tracker = TaintTracker()
        
    def trace_call(self, frame, fn, binding_target):
        """Trace function calls to detect taint sources and sinks"""
        try:
            # Extract arguments
            args = []
            kwargs = {}
            
            if frame.f_locals:
                # Try to get arguments from frame locals
                for i, (name, value) in enumerate(frame.f_locals.items()):
                    if name == 'self':
                        continue
                    elif name == 'args' and isinstance(value, tuple):
                        args.extend(value)
                    elif name == 'kwargs' and isinstance(value, dict):
                        kwargs.update(value)
                    elif i > 0:  # Skip 'self' or first param if appropriate
                        args.append(value)
            
            # Check if this is a taint source
            self.taint_tracker.detect_taint_source(fn, args, kwargs, frame)
            
            # Check if this is an exfiltration sink
            exfiltration = self.taint_tracker.detect_sink_usage(fn, args, kwargs, frame)
            if exfiltration:
                debug(f"POTENTIAL EXFILTRATION: {exfiltration['sink']['module']}.{exfiltration['sink']['name']} "
                      f"at {exfiltration['filename']}:{exfiltration['line']}")
            
            # Analyze current frame for taint propagation
            self.taint_tracker.analyze_frame(frame)
            
        except Exception as e:
            debug(f"Error in taint tracker: {e}")
        
        return None  # Don't replace the function
    
    def trace_assignment(self, frame, target_name, value):
        """Trace variable assignments for taint propagation"""
        try:
            if value is not None:
                value_id = id(value)
                
                # Check if assigned value is tainted
                if self.taint_tracker.is_tainted(value_id):
                    # Propagate taint to the target variable
                    target_id = id(frame.f_locals.get(target_name))
                    self.taint_tracker.propagate_taint(value_id, target_id, target_name)
                
                # If it's a string, check for sensitive data patterns
                elif isinstance(value, str):
                    taints = self.taint_tracker.detect_string_literals(value)
                    for taint in taints:
                        target_id = id(frame.f_locals.get(target_name))
                        self.taint_tracker.taint_variable(target_name, target_id, taint)
        
        except Exception as e:
            debug(f"Error in assignment tracer: {e}")
            
    def get_report(self) -> Dict:
        """Get the taint analysis report"""
        return self.taint_tracker.generate_report()