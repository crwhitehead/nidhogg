"""
Call analyzer for Nidhogg.

This module provides analysis of function calls to detect suspicious
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
            'subprocess.check_output', 'subprocess.run', 'os.popen'
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
            'ftplib.FTP', 'smtplib.SMTP', 'telnetlib.Telnet'
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
            
            # Track CALL opcodes to try to detect the function being called
            if opname.startswith('CALL_'):
                self._analyze_call_opcode(event_data)
    
    def _analyze_function_call(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze a function call event.
        
        Args:
            event_data: Event data dictionary
        """
        function_name = event_data['function_name']
        frame = event_data['frame']
        
        # Store this call in history
        self.call_history.append(event_data)
        
        # Try to determine the full qualified name of the function
        qualified_name = self._get_qualified_name(frame)
        
        # Check if this function matches any of our suspicious categories
        for category, functions in self.SUSPICIOUS_FUNCTIONS.items():
            for sus_func in functions:
                # Check for exact match or match at the end of qualified name
                if (qualified_name == sus_func or 
                    qualified_name.endswith('.' + sus_func)):
                    self._report_suspicious_call(category, qualified_name, event_data)
                    return
    
    def _analyze_call_opcode(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze a CALL opcode event.
        
        Args:
            event_data: Event data dictionary
        """
        frame = event_data['frame']
        
        # Can't do much without frame information
        if not frame:
            return
            
        # Try to inspect the stack to see what's being called
        try:
            # This is a best-effort attempt that may not always work
            if hasattr(frame, 'f_stack'):
                # Some Python versions expose stack - attempt to get top item
                pass
        except Exception:
            # Don't crash the analyzer if we can't inspect the stack
            pass
    
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
            'encryption_operations': Severity.HIGH
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
                'location': event_data['filename'] + ':' + str(event_data['line_no'])
            }
        )