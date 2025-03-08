"""
JSON reporter for Nidhogg.

This module provides JSON output formatting for analysis results.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional, TextIO

from nidhogg.reporting.base_reporter import BaseReporter
from nidhogg.rules.finding import AnalysisResults, Finding


class JsonReporter(BaseReporter):
    """
    Reporter for JSON output.
    
    This reporter formats analysis results as JSON for machine-readable output
    or further processing.
    """
    
    def __init__(self, 
                output_file: Optional[str] = None,
                indent: int = 2,
                stream_output: bool = False):
        """
        Initialize the JSON reporter.
        
        Args:
            output_file: Optional file to write output to
            indent: Number of spaces to indent JSON output
            stream_output: Whether to output findings as they are reported
        """
        super().__init__(output_file)
        self.indent = indent
        self.stream_output = stream_output
        self.output_stream: Optional[TextIO] = None
        self.findings: List[Dict[str, Any]] = []
        
        if output_file:
            self.output_stream = open(output_file, 'w')
            # Initialize JSON file with opening bracket
            if self.stream_output:
                self.output_stream.write('{"findings": [\n')
                self.output_stream.flush()
        
    def __del__(self):
        """Clean up resources and finalize JSON output if streaming."""
        if self.output_stream and self.stream_output:
            # Finalize the JSON array and object
            self.output_stream.write(']}\n')
            self.output_stream.flush()
        
        if self.output_stream and self.output_stream != sys.stdout:
            self.output_stream.close()
    
    def report_findings(self, results: AnalysisResults) -> None:
        """
        Report all findings from the analysis results.
        
        Args:
            results: Analysis results to report
        """
        # If we're not streaming, collect all findings and write them at once
        if not self.stream_output:
            # Convert results to JSON and write to output
            json_output = json.dumps(results.to_dict(), indent=self.indent)
            
            if self.output_stream:
                self.output_stream.write(json_output)
                self.output_stream.write('\n')
                self.output_stream.flush()
            else:
                print(json_output)
        else:
            # If streaming, finalize with a summary
            self.report_summary(results)
    
    def report_finding(self, finding: Finding) -> None:
        """
        Report a single finding.
        
        Args:
            finding: Finding to report
        """
        finding_dict = finding.to_dict()
        
        if self.stream_output and self.output_stream:
            # Write comma separator if not the first finding
            if self.findings:
                self.output_stream.write(',\n')
            
            # Write the finding as JSON
            json_output = json.dumps(finding_dict, indent=self.indent)
            self.output_stream.write(json_output)
            self.output_stream.flush()
        
        # Save finding for summary
        self.findings.append(finding_dict)
    
    def report_summary(self, results: AnalysisResults) -> None:
        """
        Report a summary of the analysis results.
        
        For JSON output, this just ensures all data is written if not streaming.
        
        Args:
            results: Analysis results to summarize
        """
        # For streaming output, we just need to finalize the JSON structure,
        # which happens in __del__
        
        # For non-streaming, we've already written everything in report_findings
        pass


class CompactJsonReporter(JsonReporter):
    """A variant of JsonReporter that produces compact (non-indented) JSON."""
    
    def __init__(self, 
                output_file: Optional[str] = None,
                stream_output: bool = False):
        """
        Initialize the compact JSON reporter.
        
        Args:
            output_file: Optional file to write output to
            stream_output: Whether to output findings as they are reported
        """
        super().__init__(output_file, indent=None, stream_output=stream_output)