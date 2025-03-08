"""
Base analyzer class for Nidhogg.

This module defines the base analyzer interface that all analyzers
must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.rules.finding import Finding, Severity


class BaseAnalyzer(ABC):
    """
    Base class for all analyzers.
    
    Analyzers subscribe to events from the event dispatcher,
    process them, and report findings.
    """
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 sensitivity: str = "medium"):
        """
        Initialize the analyzer.
        
        Args:
            event_dispatcher: Event dispatcher to subscribe to
            sensitivity: Detection sensitivity level (low, medium, high)
        """
        self.event_dispatcher = event_dispatcher
        self.sensitivity = sensitivity
        self.findings: List[Finding] = []
        self._register_event_handlers()
    
    def _register_event_handlers(self) -> None:
        """Register event handlers with the event dispatcher."""
        for event_type in self.get_monitored_events():
            self.event_dispatcher.subscribe(event_type, self.handle_event)
    
    @abstractmethod
    def get_monitored_events(self) -> List[EventType]:
        """
        Get the event types this analyzer monitors.
        
        Returns:
            List of event types to subscribe to
        """
        pass
    
    @abstractmethod
    def handle_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process an event from the event dispatcher.
        
        Args:
            event_data: Event data dictionary
        """
        pass
    
    def add_finding(self, 
                   rule_id: str,
                   description: str,
                   severity: Severity,
                   details: Dict[str, Any]) -> None:
        """
        Add a finding from this analyzer.
        
        Args:
            rule_id: Identifier of the rule that triggered this finding
            description: Human-readable description of the finding
            severity: Severity level of the finding
            details: Additional details about the finding
        """
        finding = Finding(
            rule_id=rule_id,
            description=description,
            severity=severity,
            details=details,
            analyzer=self.__class__.__name__
        )
        
        self.findings.append(finding)
        
        # Dispatch event for this finding
        self.event_dispatcher.dispatch(
            EventType.SUSPICIOUS_PATTERN, 
            {'finding': finding}
        )
    
    def get_findings(self) -> List[Finding]:
        """
        Get all findings from this analyzer.
        
        Returns:
            List of findings
        """
        return self.findings
    
    def clear_findings(self) -> None:
        """Clear all findings from this analyzer."""
        self.findings.clear()