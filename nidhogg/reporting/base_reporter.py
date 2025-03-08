"""
Base reporter for Nidhogg.

This module defines the base reporter interface that all reporters
must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from nidhogg.rules.finding import AnalysisResults, Finding


class BaseReporter(ABC):
    """
    Base class for all reporters.
    
    Reporters are responsible for formatting and outputting
    analysis results.
    """
    
    def __init__(self, output_file: Optional[str] = None):
        """
        Initialize the reporter.
        
        Args:
            output_file: Optional file to write output to
        """
        self.output_file = output_file
    
    @abstractmethod
    def report_findings(self, results: AnalysisResults) -> None:
        """
        Report analysis findings.
        
        Args:
            results: Analysis results to report
        """
        pass
    
    @abstractmethod
    def report_finding(self, finding: Finding) -> None:
        """
        Report a single finding.
        
        Args:
            finding: Finding to report
        """
        pass
    
    @abstractmethod
    def report_summary(self, results: AnalysisResults) -> None:
        """
        Report a summary of the analysis results.
        
        Args:
            results: Analysis results to summarize
        """
        pass