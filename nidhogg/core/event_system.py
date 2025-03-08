"""
Event system for the Nidhogg bytecode analysis framework.

This module provides an event dispatcher to facilitate communication
between different components of the analysis system.
"""

from enum import Enum, auto
from typing import Any, Callable, Dict, List, Set


class EventType(Enum):
    """Types of events that can be dispatched in the system."""
    OPCODE_EXECUTED = auto()
    FUNCTION_CALLED = auto()
    MODULE_IMPORTED = auto()
    FILE_ACCESS = auto()
    NETWORK_ACCESS = auto()
    SUSPICIOUS_PATTERN = auto()
    ANALYSIS_STARTED = auto()
    ANALYSIS_COMPLETED = auto()


EventCallback = Callable[[Dict[str, Any]], None]


class EventDispatcher:
    """
    Central event dispatcher for the analysis system.
    
    This class allows components to subscribe to and publish events,
    facilitating loose coupling between the core tracer and analysis modules.
    """
    
    def __init__(self):
        """Initialize an empty event dispatcher."""
        self._subscribers: Dict[EventType, List[EventCallback]] = {
            event_type: [] for event_type in EventType
        }
    
    def subscribe(self, event_type: EventType, callback: EventCallback) -> None:
        """
        Subscribe to an event type.
        
        Args:
            event_type: The type of event to subscribe to
            callback: Function to call when event occurs
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: EventType, callback: EventCallback) -> None:
        """
        Unsubscribe from an event type.
        
        Args:
            event_type: The type of event to unsubscribe from
            callback: The callback function to remove
        """
        if event_type in self._subscribers and callback in self._subscribers[event_type]:
            self._subscribers[event_type].remove(callback)
    
    def dispatch(self, event_type: EventType, data: Dict[str, Any]) -> None:
        """Dispatch an event to all subscribers."""
        print(f"[DEBUG] Dispatching event: {event_type.name}")
        if 'finding' in data:
            finding = data['finding']
            print(f"[DEBUG] Event contains finding: {finding.rule_id} - {finding.description}")
            
        if event_type in self._subscribers:
            subscriber_count = len(self._subscribers[event_type])
            print(f"[DEBUG] Found {subscriber_count} subscribers for {event_type.name}")
            for callback in self._subscribers[event_type]:
                callback(data)
        else:
            print(f"[DEBUG] No subscribers for {event_type.name}")