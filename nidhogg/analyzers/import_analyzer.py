"""
Import analyzer for Nidhogg.

This module provides analysis of module imports to detect suspicious
patterns that may indicate malicious code.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity


class ImportAnalyzer(BaseAnalyzer):
    """
    Analyzer for suspicious module imports.
    
    This analyzer monitors imports to detect patterns that may
    indicate malicious behavior, such as:
    - Obfuscation modules
    - Network or system access
    - Unusual or suspicious combinations of imports
    """
    
    # Categorized suspicious modules
    SUSPICIOUS_MODULES = {
        'system_access': {
            'os', 'sys', 'subprocess', 'shutil', 'platform', 'ctypes', 'winreg'
        },
        'network_access': {
            'socket', 'urllib', 'http.client', 'ftplib', 'telnetlib', 'smtplib',
            'requests', 'paramiko', 'urllib3', 'pycurl'
        },
        'code_execution': {
            'code', 'codeop', 'importlib', 'runpy'
        },
        'obfuscation': {
            'base64', 'binascii', 'binhex', 'codecs', 'crypt', 'hashlib',
            'marshal', 'pickle', 'zlib'
        },
        'persistence': {
            'winreg', 'win32api', 'win32con', 'win32service', 'servicemanager',
            'schedule', 'crontab'
        },
        'process_manipulation': {
            'multiprocessing', 'threading', 'concurrent', 'signal', 'psutil'
        }
    }
    
    # Suspicious combinations of imports
    SUSPICIOUS_COMBINATIONS = [
        ({'os', 'subprocess'}, {'base64', 'binascii'}, 'Possible obfuscated command execution'),
        ({'socket', 'urllib'}, {'base64', 'zlib'}, 'Possible obfuscated network traffic'),
        ({'ctypes'}, {'win32'}, 'Possible direct API access'),
    ]
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium"):
        """
        Initialize the import analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
        """
        super().__init__(event_dispatcher, sensitivity)
        self.imported_modules: Set[str] = set()
        
    def get_monitored_events(self) -> List[EventType]:
        """Get the event types this analyzer monitors."""
        return [EventType.MODULE_IMPORTED, EventType.OPCODE_EXECUTED]
    
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an event from the event dispatcher.
        
        Args:
            event_data: Event data dictionary
        """
        # Direct module import event
        if event_data.get('event_type') == EventType.MODULE_IMPORTED:
            self._analyze_import(event_data['module_name'], event_data)
        
        # Opcode events - look for import instructions
        elif event_data.get('event_type') == EventType.OPCODE_EXECUTED:
            opname = event_data['opname']
            
            if opname == 'IMPORT_NAME':
                # Try to get the module name from the frame
                frame = event_data.get('frame')
                if frame and hasattr(frame, 'f_code'):
                    if hasattr(frame.f_code, 'co_names'):
                        offset = event_data['offset']
                        if offset + 1 < len(frame.f_code.co_code):
                            name_index = frame.f_code.co_code[offset + 1]
                            if name_index < len(frame.f_code.co_names):
                                module_name = frame.f_code.co_names[name_index]
                                self._analyze_import(module_name, event_data)
    
    def _analyze_import(self, module_name: str, event_data: Dict[str, Any]) -> None:
        """
        Analyze a module import.
        
        Args:
            module_name: Name of the imported module
            event_data: Event data dictionary
        """
        # Store this module in our set of imported modules
        self.imported_modules.add(module_name)
        
        # Check individual module suspiciousness
        for category, modules in self.SUSPICIOUS_MODULES.items():
            # Check for an exact match or a prefix match (e.g., "socket" matches "socket.socket")
            matching_modules = [m for m in modules if 
                               module_name == m or module_name.startswith(m + '.')]
            
            if matching_modules:
                # Only trigger alert if sensitivity matches
                if (self.sensitivity == "high" or 
                    (self.sensitivity == "medium" and category != "system_access")):
                    self._report_suspicious_import(category, module_name, event_data)
        
        # Check for suspicious combinations of modules
        self._check_suspicious_combinations(event_data)
    
    def _check_suspicious_combinations(self, event_data: Dict[str, Any]) -> None:
        """
        Check for suspicious combinations of imported modules.
        
        Args:
            event_data: Event data dictionary
        """
        # Need at least two modules for a combination
        if len(self.imported_modules) < 2:
            return
            
        # Check each suspicious combination
        for set1, set2, description in self.SUSPICIOUS_COMBINATIONS:
            # Check if we have modules from both sets
            present_in_set1 = any(m in self.imported_modules for m in set1)
            present_in_set2 = any(m in self.imported_modules for m in set2)
            
            # If we have modules from both sets, report it
            if present_in_set1 and present_in_set2:
                intersect1 = set1.intersection(self.imported_modules)
                intersect2 = set2.intersection(self.imported_modules)
                
                self.add_finding(
                    rule_id="IMPORT-COMBO",
                    description=f"Suspicious module combination: {description}",
                    severity=Severity.MEDIUM,
                    details={
                        'modules_from_set1': list(intersect1),
                        'modules_from_set2': list(intersect2),
                        'location': event_data.get('filename', '<unknown>') + ':' + 
                                   str(event_data.get('line_no', 0))
                    }
                )
    
    def _report_suspicious_import(self, 
                                category: str, 
                                module_name: str, 
                                event_data: Dict[str, Any]) -> None:
        """
        Report a suspicious module import.
        
        Args:
            category: Category of suspicious behavior
            module_name: Name of the imported module
            event_data: Event data dictionary
        """
        # Map categories to severity levels
        severity_map = {
            'system_access': Severity.LOW,
            'network_access': Severity.MEDIUM,
            'code_execution': Severity.HIGH,
            'obfuscation': Severity.MEDIUM,
            'persistence': Severity.HIGH,
            'process_manipulation': Severity.MEDIUM
        }
        
        severity = severity_map.get(category, Severity.MEDIUM)
        
        # Adjust severity based on sensitivity setting
        if self.sensitivity == "low" and severity == Severity.MEDIUM:
            severity = Severity.LOW
        elif self.sensitivity == "high" and severity == Severity.MEDIUM:
            severity = Severity.HIGH
        
        self.add_finding(
            rule_id=f"IMPORT-{category.upper()}",
            description=f"Suspicious module import: {module_name}",
            severity=severity,
            details={
                'module': module_name,
                'category': category,
                'location': event_data.get('filename', '<unknown>') + ':' + 
                           str(event_data.get('line_no', 0))
            }
        )