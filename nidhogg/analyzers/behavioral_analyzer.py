"""
Behavioral analyzer for Nidhogg.

This module provides analysis of code behavior patterns to detect
suspicious activities that may indicate malicious code.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity


class BehavioralAnalyzer(BaseAnalyzer):
    """
    Analyzer for suspicious behavioral patterns.
    
    This analyzer looks for higher-level patterns across multiple
    events to detect malicious behaviors such as:
    - Anti-analysis techniques
    - Persistence mechanisms
    - Data exfiltration patterns
    - Process injection
    """
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium"):
        """
        Initialize the behavioral analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
        """
        super().__init__(event_dispatcher, sensitivity)
        self.file_operations: List[Dict[str, Any]] = []
        self.network_operations: List[Dict[str, Any]] = []
        self.command_executions: List[Dict[str, Any]] = []
        self.module_imports: Set[str] = set()
        self.detected_behaviors: Set[str] = set()
        
    def get_monitored_events(self) -> List[EventType]:
        """Get the event types this analyzer monitors."""
        return [
            EventType.OPCODE_EXECUTED,
            EventType.FUNCTION_CALLED,
            EventType.MODULE_IMPORTED,
            EventType.FILE_ACCESS,
            EventType.NETWORK_ACCESS,
            EventType.SUSPICIOUS_PATTERN
        ]
    
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an event from the event dispatcher.
        
        Args:
            event_data: Event data dictionary
        """
        event_type = event_data.get('event_type', None)
        
        # Track events by type for later analysis
        if event_type == EventType.FILE_ACCESS:
            self.file_operations.append(event_data)
            self._analyze_file_behavior(event_data)
        
        elif event_type == EventType.NETWORK_ACCESS:
            self.network_operations.append(event_data)
            self._analyze_network_behavior(event_data)
        
        elif event_type == EventType.FUNCTION_CALLED:
            # We're particularly interested in command executions
            function_name = event_data.get('function_name', '')
            if function_name in ('system', 'popen', 'Popen', 'run', 'call', 'check_output'):
                self.command_executions.append(event_data)
                self._analyze_command_execution(event_data)
        
        elif event_type == EventType.MODULE_IMPORTED:
            self.module_imports.add(event_data.get('module_name', ''))
            self._analyze_import_combinations()
            
        elif event_type == EventType.SUSPICIOUS_PATTERN:
            # Another analyzer already found something suspicious
            # Incorporate it into our behavioral analysis
            finding = event_data.get('finding')
            if finding:
                self._analyze_finding_pattern(finding)
    
    def _analyze_file_behavior(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze file operation patterns.
        
        Args:
            event_data: Event data dictionary
        """
        # Look for patterns like:
        # - Many file operations in a loop
        # - Read-modify-write patterns on multiple files
        # - Access to sensitive directories
        
        # Check for sensitive file access
        file_path = event_data.get('file_path', '')
        if any(sensitive in file_path.lower() for sensitive in (
                'windows', 'system32', 'passwd', 'shadow', '/etc/', '/bin/',
                '/boot/', '/root/', 'appdata', 'startup')):
            
            if 'sensitive_file_access' not in self.detected_behaviors:
                self.detected_behaviors.add('sensitive_file_access')
                self.add_finding(
                    rule_id="BEHAVIOR-FILE-001",
                    description="Access to sensitive system files detected",
                    severity=Severity.MEDIUM,
                    details={
                        'file_path': file_path,
                        'operation': event_data.get('operation', 'access'),
                        'location': event_data.get('filename', '<unknown>') + ':' + 
                                  str(event_data.get('line_no', 0))
                    }
                )
    
    def _analyze_network_behavior(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze network operation patterns.
        
        Args:
            event_data: Event data dictionary
        """
        # Look for patterns like:
        # - Unusual ports
        # - Many connections in succession
        # - Data exfiltration patterns
        
        # Check for unusual ports
        port = event_data.get('port', 0)
        if port in (4444, 1337, 31337, 8080, 8888):  # Common C2 ports
            if 'suspicious_network_port' not in self.detected_behaviors:
                self.detected_behaviors.add('suspicious_network_port')
                self.add_finding(
                    rule_id="BEHAVIOR-NET-001",
                    description=f"Connection to suspicious port {port} detected",
                    severity=Severity.HIGH,
                    details={
                        'port': port,
                        'host': event_data.get('host', 'unknown'),
                        'location': event_data.get('filename', '<unknown>') + ':' + 
                                  str(event_data.get('line_no', 0))
                    }
                )
    
    def _analyze_command_execution(self, event_data: Dict[str, Any]) -> None:
        """
        Analyze command execution patterns.
        
        Args:
            event_data: Event data dictionary
        """
        # Check for suspicious commands
        command = event_data.get('command', '')
        if any(cmd in command.lower() for cmd in (
                'powershell', 'wget', 'curl', 'nc ', 'netcat', 'chmod +x',
                'bash -i', 'sh -i', 'sudo ', 'runas', 'reg add')):
            
            if 'suspicious_command' not in self.detected_behaviors:
                self.detected_behaviors.add('suspicious_command')
                self.add_finding(
                    rule_id="BEHAVIOR-CMD-001",
                    description="Execution of suspicious system command",
                    severity=Severity.HIGH,
                    details={
                        'command': command,
                        'location': event_data.get('filename', '<unknown>') + ':' + 
                                  str(event_data.get('line_no', 0))
                    }
                )
    
    def _analyze_import_combinations(self) -> None:
        """Analyze combinations of imports for suspicious behavior patterns."""
        # Persistence pattern: registry + startup access
        if (any(m.startswith('winreg') for m in self.module_imports) and
            any(m in ('win32api', 'win32service') for m in self.module_imports)):
            
            if 'persistence_behavior' not in self.detected_behaviors:
                self.detected_behaviors.add('persistence_behavior')
                self.add_finding(
                    rule_id="BEHAVIOR-PERSIST-001",
                    description="Potential persistence mechanism detected",
                    severity=Severity.HIGH,
                    details={
                        'related_modules': [m for m in self.module_imports if
                                          any(s in m for s in ('winreg', 'win32api', 'win32service'))]
                    }
                )
    
    def _analyze_finding_pattern(self, finding: Any) -> None:
        """
        Analyze a finding from another analyzer.
        
        Args:
            finding: Finding object from another analyzer
        """
        # Look for patterns across multiple findings
        rule_id = getattr(finding, 'rule_id', '')
        
        # If we've detected both obfuscation and command execution, that's extra suspicious
        if (rule_id.startswith('OPCODE-') and 'obfuscated' in getattr(finding, 'description', '').lower() and
            len(self.command_executions) > 0):
            
            if 'obfuscated_execution' not in self.detected_behaviors:
                self.detected_behaviors.add('obfuscated_execution')
                self.add_finding(
                    rule_id="BEHAVIOR-COMPLEX-001",
                    description="Obfuscated command execution pattern detected",
                    severity=Severity.CRITICAL,
                    details={
                        'related_finding': finding.to_dict() if hasattr(finding, 'to_dict') else str(finding),
                        'command_executions': len(self.command_executions)
                    }
                )