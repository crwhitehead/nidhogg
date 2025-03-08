"""
Analyzer factory for Nidhogg.

This module provides factory functions for creating analyzers
based on configuration.
"""

from typing import Dict, List, Optional, Set, Type

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.analyzers.opcode_analyzer import OpcodeAnalyzer
from nidhogg.analyzers.call_analyzer import CallAnalyzer
from nidhogg.analyzers.import_analyzer import ImportAnalyzer
from nidhogg.analyzers.behavioral_analyzer import BehavioralAnalyzer
from nidhogg.core.event_system import EventDispatcher


class AnalyzerFactory:
    """Factory for creating and managing analyzers."""
    
    # Registry of available analyzer types
    ANALYZER_REGISTRY: Dict[str, Type[BaseAnalyzer]] = {
        'opcode': OpcodeAnalyzer,
        'call': CallAnalyzer,
        'import': ImportAnalyzer,
        'behavioral': BehavioralAnalyzer,
    }
    
    @classmethod
    def register_analyzer(cls, name: str, analyzer_class: Type[BaseAnalyzer]) -> None:
        """
        Register a new analyzer type.
        
        Args:
            name: Name to register the analyzer under
            analyzer_class: Analyzer class to register
        """
        cls.ANALYZER_REGISTRY[name] = analyzer_class
    
    @classmethod
    def create_analyzer(cls, 
                      analyzer_type: str, 
                      event_dispatcher: EventDispatcher,
                      **kwargs) -> BaseAnalyzer:
        """
        Create an analyzer of the specified type.
        
        Args:
            analyzer_type: Type of analyzer to create
            event_dispatcher: Event dispatcher to pass to the analyzer
            **kwargs: Additional arguments to pass to the analyzer constructor
            
        Returns:
            A new analyzer instance
            
        Raises:
            ValueError: If the analyzer type is unknown
        """
        if analyzer_type not in cls.ANALYZER_REGISTRY:
            raise ValueError(f"Unknown analyzer type: {analyzer_type}")
        
        analyzer_class = cls.ANALYZER_REGISTRY[analyzer_type]
        return analyzer_class(event_dispatcher, **kwargs)
    
    @classmethod
    def create_default_analyzers(cls,
                               event_dispatcher: EventDispatcher,
                               enabled_analyzers: Optional[List[str]] = None,
                               sensitivity: str = "medium") -> List[BaseAnalyzer]:
        """
        Create a set of default analyzers.
        
        Args:
            event_dispatcher: Event dispatcher to pass to the analyzers
            enabled_analyzers: List of analyzer types to enable (None for all)
            sensitivity: Detection sensitivity level
            
        Returns:
            List of analyzer instances
        """
        analyzers = []
        
        # If enabled_analyzers is None or contains "all", enable all analyzers
        if enabled_analyzers is None or "all" in enabled_analyzers:
            enabled_analyzers = list(cls.ANALYZER_REGISTRY.keys())
        
        # Create each enabled analyzer
        for analyzer_type in enabled_analyzers:
            if analyzer_type in cls.ANALYZER_REGISTRY:
                analyzer = cls.create_analyzer(
                    analyzer_type, 
                    event_dispatcher,
                    sensitivity=sensitivity
                )
                analyzers.append(analyzer)
        
        return analyzers