"""
Reporter factory for Nidhogg.

This module provides factory functions for creating reporters
based on configuration.
"""

from typing import Dict, Optional, Type

from nidhogg.reporting.base_reporter import BaseReporter
from nidhogg.reporting.console_reporter import ConsoleReporter
from nidhogg.reporting.json_reporter import JsonReporter, CompactJsonReporter
from nidhogg.reporting.html_reporter import HtmlReporter


class ReporterFactory:
    """Factory for creating and managing reporters."""
    
    # Registry of available reporter types
    REPORTER_REGISTRY: Dict[str, Type[BaseReporter]] = {
        'console': ConsoleReporter,
        'json': JsonReporter,
        'json_compact': CompactJsonReporter,
        'html': HtmlReporter,
    }
    
    @classmethod
    def register_reporter(cls, name: str, reporter_class: Type[BaseReporter]) -> None:
        """
        Register a new reporter type.
        
        Args:
            name: Name to register the reporter under
            reporter_class: Reporter class to register
        """
        cls.REPORTER_REGISTRY[name] = reporter_class
    
    @classmethod
    def create_reporter(cls, 
                      reporter_type: str, 
                      output_file: Optional[str] = None,
                      **kwargs) -> BaseReporter:
        """
        Create a reporter of the specified type.
        
        Args:
            reporter_type: Type of reporter to create
            output_file: Optional file to write output to
            **kwargs: Additional arguments to pass to the reporter constructor
            
        Returns:
            A new reporter instance
            
        Raises:
            ValueError: If the reporter type is unknown
        """
        if reporter_type not in cls.REPORTER_REGISTRY:
            raise ValueError(f"Unknown reporter type: {reporter_type}")
        
        reporter_class = cls.REPORTER_REGISTRY[reporter_type]
        
        # Special handling for HTML reporter, which requires an output file
        if reporter_type == 'html' and not output_file:
            raise ValueError("HTML reporter requires an output file")
        
        return reporter_class(output_file=output_file, **kwargs)