"""
HTML reporter for Nidhogg.

This module provides HTML output formatting for analysis results.
"""

import datetime
import json
import os
from typing import Any, Dict, List, Optional

from nidhogg.reporting.base_reporter import BaseReporter
from nidhogg.rules.finding import AnalysisResults, Finding, Severity


class HtmlReporter(BaseReporter):
    """
    Reporter for HTML output.
    
    This reporter formats analysis results as an HTML report
    with interactive features.
    """
    
    # HTML templates
    HTML_HEADER = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nidhogg Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 20px;
            border-radius: 5px;
        }
        h1, h2 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        .finding-header {
            padding: 10px 15px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-body {
            padding: 15px;
            border-top: 1px solid #ddd;
            display: none;
        }
        .severity-info { background-color: #d1ecf1; color: #0c5460; }
        .severity-low { background-color: #d4edda; color: #155724; }
        .severity-medium { background-color: #fff3cd; color: #856404; }
        .severity-high { background-color: #f8d7da; color: #721c24; }
        .severity-critical { background-color: #f5c6cb; color: #721c24; border: 2px solid #dc3545; }
        .severity-badge {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
        }
        .details-table th, .details-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .details-table th {
            background-color: #f2f2f2;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9rem;
        }
        .rule-id {
            font-family: monospace;
            color: #6c757d;
        }
        #summary-counts {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 10px;
        }
        .count-badge {
            padding: 5px 10px;
            border-radius: 5px;
        }
        .toggle-details {
            background: none;
            border: none;
            color: #007bff;
            cursor: pointer;
        }
        code {
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: monospace;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Nidhogg Analysis Report</h1>
"""
    
    HTML_FOOTER = """
        <script>
            // Add click handlers for collapsible sections
            document.querySelectorAll('.finding-header').forEach(header => {
                header.addEventListener('click', () => {
                    const body = header.nextElementSibling;
                    body.style.display = body.style.display === 'block' ? 'none' : 'block';
                });
            });

            // Add click handlers for "Show Details" buttons
            document.querySelectorAll('.toggle-details').forEach(button => {
                button.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const detailsEl = document.getElementById(button.dataset.target);
                    if (detailsEl) {
                        detailsEl.style.display = detailsEl.style.display === 'block' ? 'none' : 'block';
                        button.textContent = detailsEl.style.display === 'block' ? 'Hide Details' : 'Show Details';
                    }
                });
            });
        </script>
    </div>
</body>
</html>
"""
    
    def __init__(self, output_file: Optional[str] = None):
        """
        Initialize the HTML reporter.
        
        Args:
            output_file: File to write HTML output to (required)
        """
        if not output_file:
            raise ValueError("output_file is required for HtmlReporter")
        
        super().__init__(output_file)
        self.findings: List[Finding] = []
    
    def report_findings(self, results: AnalysisResults) -> None:
        """
        Report all findings from the analysis results.
        
        Args:
            results: Analysis results to report
        """
        # Store the findings
        self.findings = results.findings
        
        # Generate the HTML report
        self._generate_html_report(results)
    
    def report_finding(self, finding: Finding) -> None:
        """
        Report a single finding.
        
        Args:
            finding: Finding to report
        """
        # For HTML output, we just collect the findings and generate the report all at once
        self.findings.append(finding)
    
    def report_summary(self, results: AnalysisResults) -> None:
        """
        Report a summary of the analysis results.
        
        Args:
            results: Analysis results to summarize
        """
        # For HTML output, we include the summary in the report_findings method
        pass
    
    def _generate_html_report(self, results: AnalysisResults) -> None:
        """
        Generate and write the HTML report.
        
        Args:
            results: Analysis results to include in the report
        """
        with open(self.output_file, 'w', encoding='utf-8') as f:
            # Write the HTML header
            f.write(self.HTML_HEADER)
            
            # Write the report timestamp and target file
            timestamp = datetime.datetime.fromtimestamp(results.start_time).strftime("%Y-%m-%d %H:%M:%S")
            duration = results.end_time - results.start_time if results.end_time else 0
            
            f.write(f"""
            <div class="summary">
                <h2>Analysis Summary</h2>
                <p>Target: <code>{results.target_file}</code></p>
                <p class="timestamp">Generated on {timestamp} (Duration: {duration:.2f} seconds)</p>
            """)
            
            # Count findings by severity
            severity_counts = {severity: 0 for severity in Severity}
            for finding in self.findings:
                severity_counts[finding.severity] += 1
            
            # Write the severity counts
            f.write('<div id="summary-counts">')
            for severity in sorted(Severity, key=self._severity_to_int, reverse=True):
                count = severity_counts[severity]
                color_class = f"severity-{severity.value}"
                f.write(f'<div class="count-badge {color_class}">{severity.value.upper()}: {count}</div>')
            f.write(f'<div class="count-badge">TOTAL: {len(self.findings)}</div>')
            f.write('</div></div>')
            
            # Write the findings
            if self.findings:
                f.write('<h2>Findings</h2>')
                
                # Sort findings by severity
                sorted_findings = sorted(
                    self.findings,
                    key=lambda f: self._severity_to_int(f.severity),
                    reverse=True
                )
                
                for i, finding in enumerate(sorted_findings):
                    self._write_finding_html(f, finding, i)
            else:
                f.write('<div class="finding severity-low"><div class="finding-header">No issues detected</div></div>')
            
            # Write the HTML footer
            f.write(self.HTML_FOOTER)
    
    def _write_finding_html(self, f, finding: Finding, index: int) -> None:
        """
        Write a single finding as HTML.
        
        Args:
            f: File handle to write to
            finding: Finding to write
            index: Index of the finding
        """
        severity_class = f"severity-{finding.severity.value}"
        details_id = f"details-{index}"
        
        # Format location
        location = finding.details.get('location', 'Unknown location')
        
        f.write(f"""
        <div class="finding">
            <div class="finding-header {severity_class}">
                <div>
                    <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                    {finding.description}
                </div>
                <button class="toggle-details" data-target="{details_id}">Show Details</button>
            </div>
            <div class="finding-body">
                <p><strong>Location:</strong> {location}</p>
                <p><strong>Rule ID:</strong> <span class="rule-id">{finding.rule_id}</span></p>
                <div id="{details_id}" style="display:none">
                    <h3>Details</h3>
        """)
        
        # Write details table
        details = finding.details.copy()
        if 'location' in details:
            del details['location']  # Already shown above
            
        if details:
            f.write('<table class="details-table"><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>')
            
            for key, value in details.items():
                formatted_value = self._format_value_html(value)
                f.write(f'<tr><td>{key}</td><td>{formatted_value}</td></tr>')
                
            f.write('</tbody></table>')
        
        f.write('</div></div></div>')
    
    def _format_value_html(self, value: Any) -> str:
        """
        Format a value for HTML display.
        
        Args:
            value: Value to format
            
        Returns:
            HTML formatted value
        """
        if isinstance(value, (dict, list)):
            # Format as JSON
            json_str = json.dumps(value, indent=2)
            return f'<pre>{json_str}</pre>'
        elif isinstance(value, str) and (value.startswith('{') or value.startswith('[')):
            # Try to parse as JSON
            try:
                json_obj = json.loads(value)
                json_str = json.dumps(json_obj, indent=2)
                return f'<pre>{json_str}</pre>'
            except json.JSONDecodeError:
                pass
        
        # Default formatting
        return f'<code>{value}</code>'
    
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