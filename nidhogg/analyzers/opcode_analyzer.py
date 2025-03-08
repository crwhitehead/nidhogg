"""
Opcode analyzer for Nidhogg.

This module provides analysis of bytecode instructions to detect
suspicious opcode patterns that may indicate malicious code.
"""

import collections
import dis
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity


class OpcodeAnalyzer(BaseAnalyzer):
    """
    Analyzer for suspicious opcode patterns.
    
    This analyzer monitors bytecode operations to detect patterns
    that may indicate malicious behavior, such as:
    - Eval/exec usage
    - Code object construction
    - Suspicious string manipulation
    - Base64 or other encoding patterns
    """
    
    # Opcodes of particular interest for security analysis
    SENSITIVE_OPCODES = {
        'LOAD_ATTR': ['eval', 'exec', 'compile', 'globals', '__import__', 'subprocess'],
        'LOAD_METHOD': ['eval', 'exec', 'compile', 'globals', '__import__', 'subprocess'],
        'LOAD_NAME': ['eval', 'exec', 'compile', 'globals', '__import__', 'subprocess'],
        'LOAD_GLOBAL': ['eval', 'exec', 'compile', 'globals', '__import__', 'subprocess'],
    }
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium",
                 history_size: int = 20):
        """
        Initialize the opcode analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
            history_size: Number of opcodes to keep in history
        """
        super().__init__(event_dispatcher, sensitivity)
        self.history_size = history_size
        self.opcode_history: Dict[str, Deque[Tuple[int, str]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=history_size)
        )
        self.string_constants: Dict[str, List[str]] = collections.defaultdict(list)
        self.current_function = ""
    
    def get_monitored_events(self) -> List[EventType]:
        """Get the event types this analyzer monitors."""
        return [EventType.OPCODE_EXECUTED]
    
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an opcode execution event.
        
        Args:
            event_data: Event data dictionary
        """
        opname = event_data['opname']
        function_name = event_data['function_name']
        filename = event_data['filename']
        frame = event_data['frame']
        
        # Track current function for context
        self.current_function = f"{filename}:{function_name}"
        
        # Add to opcode history for this function
        self.opcode_history[self.current_function].append((event_data['offset'], opname))
        
        # Check for eval/exec patterns
        if opname in ['LOAD_ATTR', 'LOAD_METHOD', 'LOAD_NAME', 'LOAD_GLOBAL']:
            self._check_sensitive_loads(event_data)
        
        # Check for string constant loading (for obfuscation detection)
        elif opname == 'LOAD_CONST' and hasattr(frame, 'f_code'):
            const_index = frame.f_code.co_code[event_data['offset'] + 1]
            if const_index < len(frame.f_code.co_consts):
                const_value = frame.f_code.co_consts[const_index]
                if isinstance(const_value, str):
                    self._analyze_string_constant(const_value, event_data)
        
        # Check for suspicious sequences
        self._check_for_suspicious_sequences(event_data)
    
    def _check_sensitive_loads(self, event_data: Dict[str, Any]) -> None:
        """
        Check for loading of sensitive functions.
        
        Args:
            event_data: Event data dictionary
        """
        opname = event_data['opname']
        frame = event_data['frame']
        
        if opname not in self.SENSITIVE_OPCODES:
            return
            
        # Try to determine what's being loaded
        if opname == 'LOAD_ATTR':
            # Check last attribute access if possible
            if hasattr(frame, 'f_code') and hasattr(frame.f_code, 'co_names'):
                offset = event_data['offset']
                if offset + 1 < len(frame.f_code.co_code):
                    name_index = frame.f_code.co_code[offset + 1]
                    if name_index < len(frame.f_code.co_names):
                        name = frame.f_code.co_names[name_index]
                        if name in self.SENSITIVE_OPCODES[opname]:
                            self._report_sensitive_function(name, event_data)
    
    def _analyze_string_constant(self, string_value: str, event_data: Dict[str, Any]) -> None:
        """
        Analyze a string constant for suspicious patterns.
        
        Args:
            string_value: String constant value
            event_data: Event data dictionary
        """
        # Add to string constants list for this function
        self.string_constants[self.current_function].append(string_value)
        
        # Check for base64-like strings
        if len(string_value) > 20:
            b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            string_chars = set(string_value)
            
            # If most chars are base64 alphabet and string has high entropy, it's suspicious
            if len(string_chars - b64_chars) <= 4 and self._calculate_entropy(string_value) > 3.5:
                self.add_finding(
                    rule_id="OPCODE-001",
                    description="Potential obfuscated/encoded data detected",
                    severity=Severity.MEDIUM,
                    details={
                        'string_length': len(string_value),
                        'string_prefix': string_value[:20] + '...',
                        'location': event_data['filename'] + ':' + str(event_data['line_no'])
                    }
                )
    
    def _check_for_suspicious_sequences(self, event_data: Dict[str, Any]) -> None:
        """
        Check for suspicious opcode sequences.
        
        Args:
            event_data: Event data dictionary
        """
        # Get recent opcode history for current function
        history = list(self.opcode_history[self.current_function])
        
        # Not enough history yet
        if len(history) < 3:
            return
            
        # Check for eval/exec sequence patterns
        # Example: LOAD_NAME(eval) + LOAD_CONST(string) + CALL_FUNCTION
        opcodes = [op for _, op in history[-3:]]
        if (opcodes[0] in ('LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_ATTR') and
                opcodes[1] == 'LOAD_CONST' and
                opcodes[2].startswith('CALL_')):
            self.add_finding(
                rule_id="OPCODE-002",
                description="Potential dynamic code execution detected",
                severity=Severity.HIGH,
                details={
                    'opcode_sequence': opcodes,
                    'location': event_data['filename'] + ':' + str(event_data['line_no'])
                }
            )
    
    def _report_sensitive_function(self, function_name: str, event_data: Dict[str, Any]) -> None:
        """
        Report detection of a sensitive function.
        
        Args:
            function_name: Name of the sensitive function
            event_data: Event data dictionary
        """
        severity = Severity.HIGH if function_name in ('eval', 'exec') else Severity.MEDIUM
        
        self.add_finding(
            rule_id="OPCODE-003",
            description=f"Use of potentially dangerous function '{function_name}'",
            severity=severity,
            details={
                'function': function_name,
                'location': event_data['filename'] + ':' + str(event_data['line_no'])
            }
        )
    
    def _calculate_entropy(self, string_value: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher values indicate more randomness, which can be a sign of encoding.
        
        Args:
            string_value: String to calculate entropy for
            
        Returns:
            Entropy value (higher is more random)
        """
        import math
        
        # Count character frequencies
        char_count = collections.Counter(string_value)
        entropy = 0.0
        
        # Calculate Shannon entropy
        for count in char_count.values():
            freq = count / len(string_value)
            entropy -= freq * math.log2(freq)
            
        return entropy