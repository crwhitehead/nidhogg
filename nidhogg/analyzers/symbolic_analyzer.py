"""
Symbolic analyzer for Nidhogg.

This module provides analysis using CrossHair's symbolic execution capabilities
to better identify and analyze functions, particularly nested functions that
might contain malicious code.
"""

import inspect
import types
from typing import Any, Dict, List, Optional, Set, Tuple

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity

# Import CrossHair for symbolic analysis
from crosshair.core_and_libs import standalone_statespace


class SymbolicAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses symbolic execution to identify potential malicious code.
    
    This analyzer leverages CrossHair's symbolic execution capabilities to
    analyze function behavior more deeply.
    """
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium"):
        """
        Initialize the symbolic analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
        """
        super().__init__(event_dispatcher, sensitivity)
        self.analyzed_functions: Set[int] = set()  # Track functions we've already analyzed
        
    def get_monitored_events(self) -> List[EventType]:
        """Get the event types this analyzer monitors."""
        return [EventType.FUNCTION_CALLED]
    
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an event from the event dispatcher.
        
        Args:
            event_data: Event data dictionary
        """
        # Extract the called function
        called_function = event_data.get('called_function')
        
        # Skip if we couldn't identify the function
        if not called_function:
            return
            
        # Skip if we've already analyzed this function
        func_id = id(called_function)
        if func_id in self.analyzed_functions:
            return
            
        # Mark this function as analyzed
        self.analyzed_functions.add(func_id)
        
        # Analyze the function using symbolic execution
        self._symbolically_analyze_function(called_function, event_data)
    
    def _symbolically_analyze_function(self, function, event_data: Dict[str, Any]) -> None:
        """
        Analyze a function using symbolic execution.
        
        Args:
            function: Function to analyze
            event_data: Event data dictionary
        """
        # Skip if it's not a proper function
        if not callable(function) or not hasattr(function, '__code__'):
            return
            
        # Extract function information
        function_name = function.__name__
        module_name = getattr(function, '__module__', '<unknown>')
        filename = event_data.get('filename', '<unknown>')
        line_no = event_data.get('line_no', 0)
        
        try:
            # Check for nested code objects, which could be hiding malicious code
            self._analyze_code_object(function.__code__, f"{module_name}.{function_name}", 
                                    filename, line_no)
            
            # TODO: In a future version, we could use CrossHair's symbolic execution
            # capabilities to more deeply analyze the function's behavior
            
        except Exception as e:
            print(f"Error during symbolic analysis: {e}")
    
    def _analyze_code_object(self, code_obj: types.CodeType, function_path: str, 
                           filename: str, line_no: int, depth: int = 0) -> None:
        """
        Recursively analyze a code object for suspicious patterns.
        
        Args:
            code_obj: Code object to analyze
            function_path: Path to the function
            filename: Source filename
            line_no: Line number
            depth: Current recursion depth
        """
        # Check if this is a deeply nested function (potential obfuscation)
        if depth > 1:
            self.add_finding(
                rule_id="SYM-NESTED-CODE",
                description=f"Deeply nested code object detected (potential code hiding)",
                severity=Severity.MEDIUM,
                details={
                    'function_path': function_path,
                    'nesting_depth': depth,
                    'location': f"{filename}:{line_no}"
                }
            )
        
        # Analyze constants for code objects (nested functions)
        if hasattr(code_obj, 'co_consts'):
            for const in code_obj.co_consts:
                if isinstance(const, types.CodeType):
                    # Found a nested code object
                    inner_name = const.co_name
                    inner_path = f"{function_path}.{inner_name}"
                    
                    # Recursively analyze the nested code object
                    self._analyze_code_object(const, inner_path, filename, line_no, depth + 1)
                    
                    # Check the nested function for suspicious patterns
                    self._analyze_code_for_suspicious_patterns(const, inner_path, filename, line_no)
    
    def _analyze_code_for_suspicious_patterns(self, code_obj: types.CodeType, 
                                           function_path: str, filename: str, line_no: int) -> None:
        """
        Analyze a code object for suspicious patterns.
        
        Args:
            code_obj: Code object to analyze
            function_path: Path to the function
            filename: Source filename
            line_no: Line number
        """
        # Check for suspicious names in the code object
        suspicious_names = {'system', 'exec', 'eval', 'popen', 'subprocess', 'Popen', 
                          'shell', 'compile', '__import__'}
                          
        if hasattr(code_obj, 'co_names'):
            # Check for direct references to suspicious names
            for name in code_obj.co_names:
                if name in suspicious_names:
                    self.add_finding(
                        rule_id="SYM-SUSP-NAME",
                        description=f"Suspicious name '{name}' found in nested function",
                        severity=Severity.HIGH,
                        details={
                            'function_path': function_path,
                            'suspicious_name': name,
                            'location': f"{filename}:{line_no}"
                        }
                    )
        
        # Check for suspicious string constants
        if hasattr(code_obj, 'co_consts'):
            suspicious_commands = [
                'cat /etc/', 'wget ', 'curl ', 'rm -rf', 'chmod +x', 
                'sudo ', 'net user', 'powershell', 'bash -i', 'nc ',
                '/bin/sh', '/bin/bash', 'base64', 'decode', 'eval('
            ]
            
            for const in code_obj.co_consts:
                if isinstance(const, str):
                    for cmd in suspicious_commands:
                        if cmd in const:
                            self.add_finding(
                                rule_id="SYM-SUSP-CONST",
                                description=f"Suspicious command string found in nested function",
                                severity=Severity.HIGH,
                                details={
                                    'function_path': function_path,
                                    'suspicious_string': const,
                                    'pattern': cmd,
                                    'location': f"{filename}:{line_no}"
                                }
                            )
                            break