"""
Console reporter for Nidhogg.

This module provides console output formatting for analysis results.
"""

import json
import time
from typing import Any, Dict, List, Optional

from nidhogg.core.utils import colored
from nidhogg.reporting.base_reporter import BaseReporter
from nidhogg.rules.finding import AnalysisResults, Finding, Severity

try:
    from colorama import Fore, Style
except ImportError:
    # Create dummy color objects if colorama is not installed
    class DummyColor:
        def __getattr__(self, name):
            return ""
    
    class DummyStyle:
        RESET_ALL = ""
    
    Fore = DummyColor()
    Style = DummyStyle()


class ConsoleReporter(BaseReporter):
    """
    Reporter for console output.
    
    This reporter formats analysis results for output to the console
    with optional ANSI color formatting.
    """
    
    # Severity color mapping
    SEVERITY_COLORS = {
        Severity.INFO: Fore.BLUE,
        Severity.LOW: Fore.GREEN,
        Severity.MEDIUM: Fore.YELLOW,
        Severity.HIGH: Fore.RED,
        Severity.CRITICAL: Fore.MAGENTA
    }
    
    def __init__(self, 
                output_file: Optional[str] = None,
                colorize: bool = True,
                verbose: bool = False):
        """
        Initialize the console reporter.
        
        Args:
            output_file: Optional file to write output to
            colorize: Whether to use ANSI colors
            verbose: Whether to include more detailed output
        """
        super().__init__(output_file)
        self.colorize = colorize
        self.verbose = verbose
        self.output_stream = None
        
        if output_file:
            self.output_stream = open(output_file, 'w')
    
    def __del__(self):
        """Clean up resources."""
        if self.output_stream and self.output_stream != self.output_stream:
            self.output_stream.close()
    
    def _print(self, text: str) -> None:
        """
        Print text to the output stream.
        
        Args:
            text: Text to print
        """
        if self.output_stream:
            self.output_stream.write(text + '\n')
        else:
            print(text)
    
    def report_findings(self, results: AnalysisResults) -> None:
        """
        Report all findings from the analysis results.
        
        Args:
            results: Analysis results to report
        """
        if not results.findings:
            self._print(self._colorize("No findings detected.", Fore.GREEN))
            return
        
        # Print header
        self._print('\n' + self._colorize('=' * 80, Fore.CYAN))
        self._print(self._colorize(f" NIDHOGG ANALYSIS REPORT: {results.target_file}", Fore.CYAN))
        self._print(self._colorize('=' * 80, Fore.CYAN))
        
        # Print findings
        for finding in sorted(results.findings, 
                            key=lambda f: self._severity_to_int(f.severity),
                            reverse=True):
            self.report_finding(finding)
        
        # Print summary
        self.report_summary(results)
    
    def report_finding(self, finding: Finding) -> None:
        """
        Report a single finding.
        
        Args:
            finding: Finding to report
        """
        severity_color = self.SEVERITY_COLORS.get(finding.severity, Fore.WHITE)
        
        # Format header
        header = f"[{finding.severity.value.upper()}] {finding.description}"
        self._print('\n' + self._colorize('-' * 80, Fore.BLUE))
        self._print(self._colorize(header, severity_color))
        
        # Format details
        location = finding.details.get('location', 'Unknown location')
        if location:
            self._print(f"Location: {location}")
        
        # Rule reference
        self._print(f"Rule ID: {finding.rule_id}")
        
        # Detailed information
        if self.verbose:
            self._print("\nDetails:")
            details = finding.details.copy()
            if 'location' in details:
                del details['location']  # Already printed
            
            for key, value in details.items():
                if isinstance(value, (dict, list)):
                    value_str = json.dumps(value, indent=2)
                    self._print(f"  {key}:")
                    for line in value_str.split('\n'):
                        self._print(f"    {line}")
                else:
                    self._print(f"  {key}: {value}")
    
    def report_summary(self, results: AnalysisResults) -> None:
        """
        Report a summary of the analysis results.
        
        Args:
            results: Analysis results to summarize
        """
        # Count findings by severity
        severity_counts = {severity: 0 for severity in Severity}
        for finding in results.findings:
            severity_counts[finding.severity] += 1
        
        # Print summary
        self._print('\n' + self._colorize('=' * 80, Fore.CYAN))
        self._print(self._colorize(" SUMMARY", Fore.CYAN))
        self._print(self._colorize('=' * 80, Fore.CYAN))
        
        # Total findings
        total = len(results.findings)
        if total == 0:
            self._print(self._colorize("No findings detected.", Fore.GREEN))
        else:
            self._print(f"Total findings: {total}")
            
            # Findings by severity
            for severity in sorted(Severity, key=self._severity_to_int, reverse=True):
                count = severity_counts[severity]
                if count > 0:
                    self._print(self._colorize(
                        f"  {severity.value.upper()}: {count}",
                        self.SEVERITY_COLORS.get(severity, Fore.WHITE)
                    ))
        
        # Analysis duration
        if results.end_time and results.start_time:
            duration = results.end_time - results.start_time
            self._print(f"\nAnalysis duration: {duration:.2f} seconds")
        
        self._print(self._colorize('=' * 80, Fore.CYAN))
    
    def _colorize(self, text: str, color: Any) -> str:
        """
        Apply color to text if colorize is enabled.
        
        Args:
            text: Text to colorize
            color: Color to apply
            
        Returns:
            Colorized text or original text if colorize is disabled
        """
        if self.colorize:
            return colored(text, color)
        return text
    
    @staticmethod
    def _severity_to_int(severity: Severity) -> int:
        """
        Convert severity to integer for sorting.
        
        Args:
            severity: Severity enum value
            
        Returns:
            Integer value (higher is more severe)
        """
        mapping = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        return mapping.get(severity, 0)