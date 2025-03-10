"""
Call analyzer for Nidhogg.

This module provides enhanced analysis of function calls to detect suspicious
patterns that may indicate malicious code.
"""

import inspect
from typing import Any, Dict, List, Optional, Set, Tuple

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity


class CallAnalyzer(BaseAnalyzer):
    """
    Analyzer for suspicious function calls.
    
    This analyzer monitors function calls to detect patterns
    that may indicate malicious behavior, such as:
    - System command execution
    - File operations
    - Network connections
    - Registry access
    - Process manipulation
    """
    
    # Categories of suspicious functions
    SUSPICIOUS_FUNCTIONS = {
        # System command execution
        'command_execution': {
            'os.system', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_call',
            'subprocess.check_output', 'subprocess.run', 'os.popen', 'system'
        },
        # File operations
        'file_operations': {
            'open', 'file', 'os.remove', 'os.unlink', 'os.rmdir', 'shutil.rmtree',
            'shutil.copyfile', 'os.chmod', 'os.mkdir', 'os.makedirs'
        },
        # Network operations
        'network_operations': {
            'socket.socket', 'socket.connect', 'urllib.request.urlopen', 
            'http.client.HTTPConnection', 'http.client.HTTPSConnection',
            'ftplib.FTP', 'smtplib.SMTP', 'telnetlib.Telnet', 'requests.get',
            'requests.post', 'requests.put'
        },
        # Registry operations (Windows)
        'registry_operations': {
            'winreg.OpenKey', 'winreg.CreateKey', 'winreg.DeleteKey', 
            'winreg.SetValue', 'winreg.DeleteValue'
        },
        # Process manipulation
        'process_manipulation': {
            'os.kill', 'signal.kill', 'psutil.Process'
        },
        # Encryption operations (potential ransomware)
        'encryption_operations': {
            'cryptography.fernet.Fernet', 'Crypto.Cipher.AES.new', 
            'Crypto.Cipher.DES.new', 'Crypto.Cipher.PKCS1_OAEP.new'
        },
        # Dynamic code evaluation
        'code_execution': {
            'eval', 'exec', 'compile', 'globals', '__import__'
        }
    }
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium"):
        """
        Initialize the call analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
        """
        super().__init__(event_dispatcher, sensitivity)
        self.call_history: List[Dict[str, Any]] = []
        self.nested_functions: Dict[str, List[str]] = {}  # Track nested function definitions
        
    def get_monitored_events(self) -> List[EventType]:
        """Get the event types this analyzer monitors."""
        return [EventType.FUNCTION_CALLED, EventType.OPCODE_EXECUTED]
    
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an event from the event dispatcher.
        
        Args:
            event_data: Event data dictionary
        """
        event_type = event_data.get('event_type', None)
        
        if event_type == EventType.FUNCTION_CALLED:
            self._analyze_function_call(event_data)
        elif event_type == EventType.OPCODE_EXECUTED:
            opname = event_data['opname']
            
            # Track function definitions for detecting code hiding in nested functions
            if opname == 'MAKE_FUNCTION':
                self._track_function_definition(event_data)
            
            # Track attribute loading to detect suspicious functions
            elif opname == 'LOAD_ATTR':
                self._analyze_attribute_access(event_data)
                
            # Track CALL opcodes to try to detect the function being called
            elif opname.startswith('CALL_') or opname == 'CALL':
                self._analyze_call_opcode(event_data)
    
    def _analyze_function_call(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze a function call event with enhanced detection.
        
        Args:
            event_data: Event data dictionary
        """
        # Extract function details from enhanced tracing
        function_name = event_data.get('called_function_name', event_data.get('function_name', ''))
        called_function = event_data.get('called_function')
        call_args = event_data.get('call_args', [])
        frame = event_data.get('frame')
        
        # Store this call in history
        self.call_history.append(event_data)
        
        # Try to determine the full qualified name of the function
        if not function_name:
            function_name = self._get_qualified_name(frame)
        
        # Check if this is a direct suspicious function call
        self._check_suspicious_function(function_name, event_data)
        
        # Enhanced detection: look for functions that might be wrappers around system calls
        # by checking the function's code content if available
        if called_function and hasattr(called_function, '__code__'):
            self._analyze_function_code(called_function, event_data)
        
    def _analyze_function_code(self, function, event_data: Dict[str, Any]) -> None:
        """
        Analyze a function's code for suspicious content.
        
        Args:
            function: Function object to analyze
            event_data: Event data dictionary
        """
        try:
            # Skip if function has no code attribute
            if not hasattr(function, '__code__'):
                return
                
            function_code = function.__code__
            
            # Check for suspicious constant strings in the function
            if hasattr(function_code, 'co_consts'):
                for const in function_code.co_consts:
                    if isinstance(const, str):
                        # Check for suspicious commands
                        suspicious_commands = [
                            'cat /etc/', 'wget ', 'curl ', 'rm -rf', 'chmod +x', 
                            'sudo ', 'net user', 'powershell', 'bash -i', 'nc '
                        ]
                        
                        for cmd in suspicious_commands:
                            if cmd in const:
                                self.add_finding(
                                    rule_id="CALL-HIDDEN-CMD",
                                    description=f"Suspicious command string found in function: '{const}'",
                                    severity=Severity.HIGH,
                                    details={
                                        'function': function.__name__,
                                        'command_string': const,
                                        'module': function.__module__,
                                        'location': event_data.get('filename', 'unknown') + ':' + 
                                                  str(event_data.get('line_no', 0))
                                    }
                                )
                                break
            
            # Check for suspicious names in the function
            if hasattr(function_code, 'co_names'):
                suspicious_names = ['eval', 'exec', 'system', 'popen', 'subprocess', 'os']
                for name in function_code.co_names:
                    if name in suspicious_names:
                        self.add_finding(
                            rule_id="CALL-SUSP-NAME",
                            description=f"Function contains suspicious name: '{name}'",
                            severity=Severity.MEDIUM,
                            details={
                                'function': function.__name__,
                                'suspicious_name': name,
                                'module': function.__module__,
                                'location': event_data.get('filename', 'unknown') + ':' + 
                                          str(event_data.get('line_no', 0))
                            }
                        )
                
        except Exception as e:
            # Don't let analysis errors crash the program
            print(f"Error analyzing function code: {e}")
    
    def _analyze_call_opcode(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze a CALL opcode event to try to detect the function being called.
        
        Args:
            event_data: Event data dictionary
        """
        # Enhanced detection for call opcodes - additional detection method
        frame = event_data.get('frame')
        
        if frame:
            # Try to inspect the frame to identify what's being called
            try:
                # This is a best-effort approach and will be imperfect
                if hasattr(frame, 'f_code') and hasattr(frame, 'f_lineno'):
                    line_no = frame.f_lineno
                    filename = frame.f_code.co_filename
                    
                    # Try to get the source line (if available)
                    try:
                        with open(filename, 'r') as f:
                            lines = f.readlines()
                            if 0 <= line_no - 1 < len(lines):
                                source_line = lines[line_no - 1].strip()
                                
                                # Look for suspicious patterns in the source line
                                suspicious_patterns = ['system(', 'exec(', 'eval(', 'os.', 'subprocess.']
                                for pattern in suspicious_patterns:
                                    if pattern in source_line:
                                        self.add_finding(
                                            rule_id="CALL-SOURCE-LINE",
                                            description=f"Suspicious pattern found in source line: '{pattern}'",
                                            severity=Severity.MEDIUM,
                                            details={
                                                'source_line': source_line,
                                                'pattern': pattern,
                                                'location': filename + ':' + str(line_no)
                                            }
                                        )
                    except (FileNotFoundError, IOError):
                        # Source file not available
                        pass
            except Exception as e:
                # Don't crash on analysis errors
                print(f"Error analyzing call opcode: {e}")
    
    def _track_function_definition(self, event_data: Dict[str, Any]) -> None:
        """
        Track function definitions to detect nested functions that might hide malicious code.
        
        Args:
            event_data: Event data dictionary
        """
        frame = event_data.get('frame')
        
        if not frame:
            return
            
        # Track the current function being defined
        function_name = event_data.get('function_name', '')
        filename = event_data.get('filename', '')
        location = f"{filename}:{function_name}"
        
        # Get the parent function (if any)
        if frame and frame.f_back:
            parent_function = frame.f_back.f_code.co_name
            parent_filename = frame.f_back.f_code.co_filename
            parent_location = f"{parent_filename}:{parent_function}"
            
            # Record this nested function relationship
            if parent_location not in self.nested_functions:
                self.nested_functions[parent_location] = []
                
            self.nested_functions[parent_location].append(location)
            
            # Alert about deeply nested functions (potential obfuscation)
            parent_chain = self._get_nested_function_chain(parent_location)
            if len(parent_chain) >= 2:  # Function nested at least 2 levels deep
                self.add_finding(
                    rule_id="CALL-NESTED-FUNC",
                    description="Deeply nested function definition detected (potential code hiding)",
                    severity=Severity.MEDIUM,
                    details={
                        'function': function_name,
                        'parent_chain': parent_chain,
                        'location': filename + ':' + str(event_data.get('line_no', 0))
                    }
                )
    
    def _get_nested_function_chain(self, location: str) -> List[str]:
        """
        Get the chain of nested parent functions for a location.
        
        Args:
            location: Function location string
            
        Returns:
            List of parent function locations
        """
        chain = []
        current = location
        visited = set()  # Avoid cycles
        
        while current and current not in visited:
            chain.append(current)
            visited.add(current)
            
            # Find parent
            parent = None
            for potential_parent, children in self.nested_functions.items():
                if current in children:
                    parent = potential_parent
                    break
                    
            if not parent:
                break
                
            current = parent
            
        return chain
    
    def _analyze_attribute_access(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze attribute access to detect suspicious function calls.
        
        Args:
            event_data: Event data dictionary
        """
        frame = event_data.get('frame')
        
        if not frame or not hasattr(frame, 'f_code'):
            return
            
        # Get the attribute name
        try:
            offset = event_data.get('offset')
            if offset is not None and offset + 1 < len(frame.f_code.co_code):
                attr_index = frame.f_code.co_code[offset + 1]
                if attr_index < len(frame.f_code.co_names):
                    attr_name = frame.f_code.co_names[attr_index]
                    
                    # Check for suspicious attributes
                    if attr_name in ('system', 'popen', 'exec', 'eval'):
                        self.add_finding(
                            rule_id="CALL-SUSP-ATTR",
                            description=f"Access to suspicious attribute: '{attr_name}'",
                            severity=Severity.HIGH,
                            details={
                                'attribute': attr_name,
                                'location': event_data.get('filename', 'unknown') + ':' + 
                                          str(event_data.get('line_no', 0))
                            }
                        )
        except Exception as e:
            # Don't crash on analysis errors
            print(f"Error analyzing attribute access: {e}")
    
    def _check_suspicious_function(self, function_name: str, event_data: Dict[str, Any]) -> None:
        """
        Check if a function name matches any known suspicious patterns.
        
        Args:
            function_name: Qualified function name
            event_data: Event data dictionary
        """
        # Check each suspicious category
        for category, functions in self.SUSPICIOUS_FUNCTIONS.items():
            for suspicious_func in functions:
                # Try different matching approaches for better detection
                if (function_name == suspicious_func or 
                    function_name.endswith('.' + suspicious_func) or
                    suspicious_func in function_name):
                    
                    self._report_suspicious_call(category, function_name, event_data)
                    return
    
    def _get_qualified_name(self, frame) -> str:
        """
        Try to get the qualified name of a function from a frame.
        
        Args:
            frame: Frame to inspect
            
        Returns:
            Qualified name of the function or partial name if full name can't be determined
        """
        if not frame:
            return "unknown"
            
        # Try to get function name
        function_name = frame.f_code.co_name if hasattr(frame, 'f_code') else "unknown"
        
        # Try to get module name
        module_name = frame.f_globals.get('__name__', "") if hasattr(frame, 'f_globals') else ""
        
        if module_name:
            return f"{module_name}.{function_name}"
        else:
            return function_name
    
    def _report_suspicious_call(self, 
                              category: str, 
                              function_name: str, 
                              event_data: Dict[str, Any]) -> None:
        """
        Report a suspicious function call.
        
        Args:
            category: Category of suspicious behavior
            function_name: Name of the called function
            event_data: Event data dictionary
        """
        severity_map = {
            'command_execution': Severity.HIGH,
            'file_operations': Severity.MEDIUM,
            'network_operations': Severity.MEDIUM,
            'registry_operations': Severity.MEDIUM,
            'process_manipulation': Severity.HIGH,
            'encryption_operations': Severity.HIGH,
            'code_execution': Severity.HIGH
        }
        
        severity = severity_map.get(category, Severity.MEDIUM)
        
        # Adjust severity based on sensitivity setting
        if self.sensitivity == "low" and severity == Severity.MEDIUM:
            severity = Severity.LOW
        elif self.sensitivity == "high" and severity == Severity.MEDIUM:
            severity = Severity.HIGH
        
        self.add_finding(
            rule_id=f"CALL-{category.upper()}",
            description=f"Suspicious function call: {function_name}",
            severity=severity,
            details={
                'function': function_name,
                'category': category,
                'location': event_data.get('filename', 'unknown') + ':' + 
                          str(event_data.get('line_no', 0)),
                'call_args': event_data.get('call_args', [])
            }
        )