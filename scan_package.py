#!/usr/bin/env python3
"""
scan_package.py - Script to analyze Python packages with Nidhogg in a secure Docker container

Usage:
    python scan_package.py [options] path/to/package

Options:
    --output-dir=DIR    Directory to store analysis results (default: /data/output)
    --verbose           Enable verbose output
    --coverage          Enable enhanced code coverage analysis
    --extract           Extract the package before scanning (for .tar.gz, .whl, etc.)
"""

import os
import sys
import json
import time
import argparse
import tempfile
import shutil
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import Nidhogg components
from nidhogg.analysis.analyzer import detect_malware, global_suspicious_tracer, extract_package
from nidhogg.utils.debug import set_debug


def analyze_package(package_path: str, output_dir: str, verbose: bool = False, 
                   coverage: bool = False, extract: bool = False) -> Dict:
    """
    Analyze a Python package with Nidhogg and save results
    
    Args:
        package_path: Path to the package file or directory
        output_dir: Directory to store analysis results
        verbose: Enable verbose output
        coverage: Enable enhanced code coverage
        extract: Extract the package before scanning
        
    Returns:
        Dictionary with analysis results
    """
    start_time = time.time()
    print(f"Starting analysis of: {package_path}")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Set debug mode if verbose
    if verbose:
        set_debug(True)
    
    # Extract the package if needed
    scan_path = package_path
    temp_dir = None
    
    if extract and not os.path.isdir(package_path):
        try:
            temp_dir = tempfile.mkdtemp(prefix="nidhogg_analysis_")
            scan_path = extract_package(package_path, temp_dir)
        except Exception as e:
            print(f"Failed to extract package: {e}")
            # Continue with original path
            scan_path = package_path
    
    try:
        # Reset the global tracer's findings
        global_suspicious_tracer.findings = []
        
        # Run malware detection - this returns an exit code, but we want the data
        status_code = detect_malware([scan_path], verbose, coverage)
        
        # Gather results - important: get findings AFTER the scan
        # Use the global tracer that was used during detection
        suspicious_findings = global_suspicious_tracer.get_findings()
        
        # Create a comprehensive report
        report = {
            "analysis_timestamp": time.time(),
            "analysis_duration": time.time() - start_time,
            "package_path": package_path,
            "exit_code": status_code,
            "risk_level": "malicious" if status_code > 0 or len(suspicious_findings) > 0 else "clean",
            "suspicious_functions": suspicious_findings,
            "suspicious_functions_count": len(suspicious_findings)
        }
        
        # Save full report to output directory
        package_name = os.path.basename(package_path)
        report_path = os.path.join(output_dir, f"{package_name}_report.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Analysis complete. Report saved to: {report_path}")
        print(f"Risk level: {report['risk_level']}")
        print(f"Found {len(suspicious_findings)} suspicious function calls")
        
        return report
    
    finally:
        # Clean up the temporary directory if we created one
        if temp_dir and temp_dir != package_path:
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    print("Scanning now!")
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Analyze Python packages with Nidhogg")
    parser.add_argument("package_path", help="Path to the package to analyze")
    parser.add_argument("--output-dir", default="/data/output", 
                        help="Directory to store analysis results")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--coverage", action="store_true", 
                        help="Enable enhanced code coverage analysis")
    parser.add_argument("--extract", action="store_true", 
                        help="Extract the package before scanning")
    
    args = parser.parse_args()
    
    # Run the analysis
    try:
        analyze_package(
            args.package_path, 
            args.output_dir,
            args.verbose,
            args.coverage,
            args.extract
        )
    except Exception as e:
        print(f"Error during analysis: {e}")
        print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()