# nidhogg/analysis/taint.py
import re
import inspect
import ast
import copy
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional, Tuple, Union, cast
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
    data_snapshot: Any = None   # A small snapshot of the original value for context
    
    def __str__(self):
        return f"{self.taint_type} from {self.source} (line {self.line_number or 'unknown'}, {self.propagation})"

    def __eq__(self, other):
        if not isinstance(other, TaintInfo):
            return False
        return (self.taint_type == other.taint_type and 
                self.source == other.source and
                self.propagation == other.propagation)
    
    def __hash__(self):
        return hash((self.taint_type, self.source, self.propagation))

@dataclass
class TaintedVariable:
    """Represents a tainted variable with its metadata"""
    name: str
    taints: Set[TaintInfo] = field(default_factory=set)
    
    def add_taint(self, taint_info: TaintInfo):
        self.taints.add(taint_info)
    
    def has_taint_type(self, taint_type: TaintType) -> bool:
        return any(t.taint_type == taint_type for t in self.taints)
    
    def __str__(self):
        return f"{self.name}: {', '.join(str(t) for t in self.taints)}"

class TaintTracker:
    """Tracks tainted variables and their propagation"""
    
    def __init__(self):
        # Dictionary mapping variable names to their taint information
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        
        # Track tainted values and their associated variables for propagation
        self.tainted_values: Dict[int, List[str]] = {}
        
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
    
    def _get_data_snapshot(self, value: Any) -> Any:
        """Create a small snapshot of a value for context"""
        try:
            if isinstance(value, str):
                return value[:50] + ('...' if len(value) > 50 else '')
            elif isinstance(value, (list, tuple)):
                return str(value[:3]) + ('...' if len(value) > 3 else '')
            elif isinstance(value, dict):
                keys = list(value.keys())[:3]
                return '{' + ', '.join(f'{k}: {value[k]}' for k in keys) + ('...' if len(value) > 3 else '') + '}'
            else:
                return str(value)[:50]
        except:
            return "<unprintable value>"
        
    def taint_variable(self, var_name: str, taint_info: TaintInfo, value: Any = None) -> None:
        """Add taint to a variable"""
        if var_name not in self.tainted_vars:
            self.tainted_vars[var_name] = TaintedVariable(var_name)
        
        self.tainted_vars[var_name].add_taint(taint_info)
        
        # If value is provided, associate this variable with the value for propagation
        if value is not None:
            try:
                value_id = id(value)
                if value_id not in self.tainted_values:
                    self.tainted_values[value_id] = []
                if var_name not in self.tainted_values[value_id]:
                    self.tainted_values[value_id].append(var_name)
            except:
                pass  # Some objects may not be hashable or have stable ids
    
    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted by name"""
        return var_name in self.tainted_vars
    
    def get_taint_by_name(self, var_name: str) -> Set[TaintInfo]:
        """Get all taints associated with a variable by name"""
        if var_name in self.tainted_vars:
            return self.tainted_vars[var_name].taints
        return set()
    
    def get_taint_by_value(self, value: Any) -> Set[TaintInfo]:
        """Get all taints associated with a value"""
        result = set()
        try:
            value_id = id(value)
            if value_id in self.tainted_values:
                for var_name in self.tainted_values[value_id]:
                    result.update(self.get_taint_by_name(var_name))
        except:
            pass
        return result
    
    def propagate_taint(self, from_var: str, to_var: str, 
                       propagation: PropagationLevel = PropagationLevel.DIRECT,
                       value: Any = None) -> None:
        """Propagate taint from one variable to another by variable names"""
        if not self.is_tainted(from_var):
            return
        
        for taint in self.get_taint_by_name(from_var):
            # Create a new TaintInfo with the propagation level
            new_taint = TaintInfo(
                taint_type=taint.taint_type,
                source=taint.source,
                propagation=propagation,
                line_number=taint.line_number,
                data_snapshot=taint.data_snapshot
            )
            self.taint_variable(to_var, new_taint, value)
    
    def propagate_container_taints(self, container_name: str, element_name: str, 
                                 propagation: PropagationLevel = PropagationLevel.DERIVED) -> None:
        """Propagate taints from a container to its elements and vice versa"""
        # Container to element
        if self.is_tainted(container_name):
            self.propagate_taint(container_name, element_name, propagation)
        
        # Element to container
        if self.is_tainted(element_name):
            self.propagate_taint(element_name, container_name, propagation)
    
    def propagate_value_taint(self, value: Any, to_var: str, 
                           propagation: PropagationLevel = PropagationLevel.DIRECT) -> None:
        """Propagate taint from a value to a variable, using value-based taint tracking"""
        taint_info_set = self.get_taint_by_value(value)
        for taint_info in taint_info_set:
            new_taint = TaintInfo(
                taint_type=taint_info.taint_type,
                source=taint_info.source,
                propagation=propagation,
                line_number=taint_info.line_number,
                data_snapshot=taint_info.data_snapshot
            )
            self.taint_variable(to_var, new_taint, value)
    
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
        
        # Get local variables from the frame
        local_vars = frame.f_locals
        
        # Check positional arguments
        for i, arg in enumerate(args):
            # Try to find the variable name for this argument
            arg_name = None
            for name, value in local_vars.items():
                if value is arg:
                    arg_name = name
                    break
            
            taint_info = set()
            # Check taint by name if we found the name
            if arg_name and self.is_tainted(arg_name):
                taint_info = self.get_taint_by_name(arg_name)
            
            # Also check taint by value
            taint_info.update(self.get_taint_by_value(arg))
            
            if taint_info:
                tainted_args.append({
                    'position': i,
                    'name': arg_name,
                    'value': str(arg)[:100],
                    'taints': [str(t) for t in taint_info]
                })
        
        # Check keyword arguments
        for key, arg in kwargs.items():
            taint_info = self.get_taint_by_value(arg)
            
            # Also look for the variable name in locals
            for name, value in local_vars.items():
                if value is arg and self.is_tainted(name):
                    taint_info.update(self.get_taint_by_name(name))
            
            if taint_info:
                tainted_args.append({
                    'keyword': key,
                    'value': str(arg)[:100],
                    'taints': [str(t) for t in taint_info]
                })
        
        # If no tainted arguments, check result for methods that might smuggle data
        # (e.g., connect() doesn't take data directly but might be used to exfiltrate later)
        if not tainted_args and result is not None:
            taint_info = self.get_taint_by_value(result)
            if taint_info:
                tainted_args.append({
                    'result': True,
                    'value': str(result)[:100],
                    'taints': [str(t) for t in taint_info]
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
                # Get the actual line number from the call frame
                line_number = frame.f_lineno
                
                # Try to get a more precise line number from the caller frame
                if frame.f_back:
                    caller_frame = frame.f_back
                    caller_line = caller_frame.f_lineno
                    if caller_line > 0:  # Sanity check
                        line_number = caller_line
                
                # It's a taint source - create taint info
                data_snapshot = self._get_data_snapshot(result) if result is not None else None
                taint_info = TaintInfo(
                    taint_type=source_info['taint_type'],
                    source=f"{fn_module}.{fn_name}",
                    line_number=line_number,
                    data_snapshot=data_snapshot
                )
                
                # If there's a result, taint it
                if result is not None:
                    # Attempt to find the target variable name in caller's frame
                    var_name = None
                    if frame.f_back:
                        back_frame = frame.f_back
                        
                        # Check if this is an assignment operation by looking at the bytecode
                        caller_code = back_frame.f_code
                        if caller_code:
                            try:
                                import dis
                                # Get the current instruction in the caller
                                instructions = list(dis.get_instructions(caller_code))
                                # Find the instruction at the current position
                                last_inst = None
                                for inst in instructions:
                                    if inst.offset == back_frame.f_lasti:
                                        last_inst = inst
                                        break
                                    
                                # If this is storing to a name, we can get the target
                                if last_inst and last_inst.opname in ('STORE_NAME', 'STORE_ATTR'):
                                    var_name = last_inst.argval
                            except Exception as e:
                                debug(f"Error analyzing bytecode: {e}")
                        
                        # Fallback to searching for the result in locals
                        if not var_name:
                            for name, value in back_frame.f_locals.items():
                                if value is result:
                                    var_name = name
                                    break
                    
                    if var_name:
                        self.taint_variable(var_name, taint_info, result)
                    else:
                        # Use a generic name if we can't find the variable
                        self.taint_variable("result", taint_info, result)
                        
                        # Also try to taint any variable that might hold this result
                        if frame.f_back:
                            # For output parameters that might be modified
                            for name, value in frame.f_back.f_locals.items():
                                # If it's a container that might receive the result
                                if isinstance(value, (list, dict, set)) and result is not None:
                                    self.taint_variable(name, taint_info, value)
                
                return taint_info
        
        return None
    
    def detect_string_literals(self, s: str, frame=None) -> List[TaintInfo]:
        """Detect if a string literal contains sensitive patterns"""
        taints = []
        
        # Get line number if frame is provided
        line_number = None
        if frame:
            line_number = frame.f_lineno
        
        # Check each pattern category
        for taint_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    taint_info = TaintInfo(
                        taint_type=taint_type,
                        source="string_literal",
                        line_number=line_number,
                        data_snapshot=self._get_data_snapshot(s)
                    )
                    taints.append(taint_info)
                    break  # Only need one match per category
        
        return taints
    
    def analyze_assignment(self, target_name: str, value: Any, frame) -> None:
        """Analyze an assignment operation for taint propagation"""
        # Check if assigned value is associated with any tainted variables
        self.propagate_value_taint(value, target_name)
        
        # Check if assignment is a container operation
        if isinstance(value, (list, tuple, set)):
            # For each element in the container, check if it's tainted
            for item in value:
                self.propagate_value_taint(item, target_name, PropagationLevel.DERIVED)
        
        elif isinstance(value, dict):
            # Check both keys and values in dictionaries
            for k, v in value.items():
                self.propagate_value_taint(k, target_name, PropagationLevel.DERIVED)
                self.propagate_value_taint(v, target_name, PropagationLevel.DERIVED)
        
        # If it's a string, check for sensitive patterns
        if isinstance(value, str):
            taints = self.detect_string_literals(value, frame)
            for taint in taints:
                self.taint_variable(target_name, taint, value)
    
    def analyze_frame(self, frame) -> None:
        """Analyze a stack frame for variable tainting"""
        # Analyze each local variable for potential taint
        for var_name, value in frame.f_locals.items():
            self.analyze_assignment(var_name, value, frame)
            
            # String literals may contain sensitive data
            if isinstance(value, str):
                taints = self.detect_string_literals(value, frame)
                for taint in taints:
                    self.taint_variable(var_name, taint, value)
            
            # Inspect container types more deeply for taint propagation
            if isinstance(value, (list, tuple, set)):
                for i, item in enumerate(value):
                    item_name = f"{var_name}[{i}]"
                    # Bidirectional taint propagation between container and elements
                    self.propagate_container_taints(var_name, item_name)
                    
                    # Check items in containers for sensitive patterns
                    if isinstance(item, str):
                        taints = self.detect_string_literals(item, frame)
                        for taint in taints:
                            self.taint_variable(item_name, taint, item)
                            # Also propagate to container
                            self.taint_variable(var_name, taint, value)
            
            elif isinstance(value, dict):
                for k, v in value.items():
                    # Use stable string representation of key
                    key_str = str(k)
                    item_name = f"{var_name}[{key_str}]"
                    # Bidirectional taint propagation
                    self.propagate_container_taints(var_name, item_name)
                    
                    # Check dict values for sensitive patterns
                    if isinstance(v, str):
                        taints = self.detect_string_literals(v, frame)
                        for taint in taints:
                            self.taint_variable(item_name, taint, v)
                            # Also propagate to container
                            self.taint_variable(var_name, taint, value)
                    
                    # Also check dict keys for sensitive patterns
                    if isinstance(k, str):
                        taints = self.detect_string_literals(k, frame)
                        for taint in taints:
                            # Taint both the item and container
                            self.taint_variable(item_name, taint, v)
                            self.taint_variable(var_name, taint, value)

    def analyze_control_flow(self, condition: Any, affected_vars: List[str], frame) -> None:
        """
        Analyze control flow taint propagation
        
        When a tainted value affects a condition, variables modified within
        the conditional block inherit taint with CONDITIONAL propagation level
        """
        # Check if condition is tainted
        condition_taint = self.get_taint_by_value(condition)
        
        if not condition_taint:
            return
            
        # Propagate taint to all affected variables
        for var_name in affected_vars:
            for taint in condition_taint:
                new_taint = TaintInfo(
                    taint_type=taint.taint_type,
                    source=taint.source,
                    propagation=PropagationLevel.CONDITIONAL,
                    line_number=taint.line_number,
                    data_snapshot=taint.data_snapshot
                )
                self.taint_variable(var_name, new_taint, frame.f_locals.get(var_name))

    def generate_report(self) -> Dict:
        """Generate a report of tainted variables and exfiltration attempts"""
        report = {
            "tainted_variables": [],
            "exfiltration_attempts": self.exfiltration_attempts,
            "total_tainted_vars": len(self.tainted_vars),
            "total_exfiltration_attempts": len(self.exfiltration_attempts),
        }
        
        # Add tainted variables to report
        for var_name, tainted_var in self.tainted_vars.items():
            report["tainted_variables"].append({
                "name": tainted_var.name,
                "taints": [str(t) for t in tainted_var.taints]
            })
        
        return report

class TaintTrackingTracer(TracingModule):
    """Tracer module for tracking data flow between variables"""
    
    def __init__(self):
        self.taint_tracker = TaintTracker()
        # Set of source file names that have been scanned for module-level constants
        self.scanned_files = set()
        
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
            taint_info = self.taint_tracker.detect_taint_source(fn, args, kwargs, frame)
            
            # Check if this is an exfiltration sink
            exfiltration = self.taint_tracker.detect_sink_usage(fn, args, kwargs, frame)
            if exfiltration:
                debug(f"POTENTIAL EXFILTRATION: {exfiltration['sink']['module']}.{exfiltration['sink']['name']} "
                      f"at {exfiltration['filename']}:{exfiltration['line']}")
            
            # Analyze current frame for taint propagation
            self.taint_tracker.analyze_frame(frame)
            
            # For specific control flow functions, check for condition-based taint
            fn_name = getattr(fn, "__name__", "")
            if fn_name in ('if_statement', 'while_loop', 'for_loop'):
                if len(args) >= 2:
                    condition = args[0]
                    affected_vars = args[1:]  # Variables modified in the conditional block
                    self.taint_tracker.analyze_control_flow(condition, affected_vars, frame)
            
            # Scan module-level constants if we haven't seen this file yet
            filename = frame.f_code.co_filename
            if filename not in self.scanned_files:
                self.scanned_files.add(filename)
                self._scan_module_constants(frame)
                    
        except Exception as e:
            debug(f"Error in taint tracker: {e}")
        
        return None  # Don't replace the function
        
    def _scan_module_constants(self, frame):
        """Scan a module for constants that might contain sensitive data"""
        try:
            # Get the module globals
            module_globals = frame.f_globals
            if not module_globals:
                return
                
            # Scan the source file to get line numbers for constants
            filename = frame.f_code.co_filename
            line_mapping = {}
            
            try:
                with open(filename, 'r') as f:
                    lines = f.readlines()
                    
                # Simple parsing to identify constants and their line numbers
                for i, line in enumerate(lines):
                    line_num = i + 1  # Line numbers start at 1
                    line = line.strip()
                    
                    # Look for assignments to constants
                    if '=' in line and not line.startswith('#'):
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            var_name = parts[0].strip()
                            if var_name.startswith('__') and var_name.endswith('__') or var_name.isupper():
                                line_mapping[var_name] = line_num
            except Exception as e:
                debug(f"Error reading source file: {e}")
            
            # Check module globals for sensitive data
            for var_name, value in module_globals.items():
                # Focus on constants and module attributes
                if var_name.startswith('__') and var_name.endswith('__') or var_name.isupper():
                    if isinstance(value, str):
                        # Create a TaintInfo with the correct line number
                        line_num = line_mapping.get(var_name)
                        
                        taints = self.taint_tracker.detect_string_literals(value)
                        for taint in taints:
                            # Set the line number if we found it
                            if line_num:
                                taint.line_number = line_num
                            
                            # Taint the constant
                            self.taint_tracker.taint_variable(var_name, taint, value)
                            
        except Exception as e:
            debug(f"Error scanning module constants: {e}")
    
    def trace_assignment(self, frame, target_name, value):
        """Trace variable assignments for taint propagation"""
        try:
            if value is not None:
                # Analyze the assignment for taint propagation
                self.taint_tracker.analyze_assignment(target_name, value, frame)
                
                # Handle container updates specially
                if '[' in target_name and ']' in target_name:
                    # This is a container element assignment like list[i] = value
                    container_name = target_name.split('[')[0]
                    # Propagate taint between container and element
                    self.taint_tracker.propagate_container_taints(container_name, target_name)
                    
                    # If the value is also a container, do deep propagation
                    if isinstance(value, (list, tuple, dict, set)):
                        for taint in self.taint_tracker.get_taint_by_name(container_name):
                            # Copy the line number from the current frame
                            taint_with_line = TaintInfo(
                                taint_type=taint.taint_type,
                                source=taint.source,
                                propagation=taint.propagation,
                                line_number=frame.f_lineno,
                                data_snapshot=taint.data_snapshot
                            )
                            self.taint_tracker.taint_variable(target_name, taint_with_line, value)
                    
                    # Propagate any taint from the value
                    self.taint_tracker.propagate_value_taint(value, target_name)
                
                # Check if it's a module-level variable or constant (capitals)
                if target_name.startswith('__') and target_name.endswith('__') or target_name.isupper():
                    # For module constants, store line number more aggressively
                    if isinstance(value, str):
                        taints = self.taint_tracker.detect_string_literals(value, frame)
                        if taints:
                            for taint in taints:
                                # Make sure the line number is set
                                if not taint.line_number:
                                    taint.line_number = frame.f_lineno
                                self.taint_tracker.taint_variable(target_name, taint, value)
        
        except Exception as e:
            debug(f"Error in assignment tracer: {e}")
            
    def get_report(self) -> Dict:
        """Get the taint analysis report"""
        return self.taint_tracker.generate_report()