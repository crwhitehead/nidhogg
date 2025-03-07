#!/usr/bin/env python3
"""
scan_package.py - Script to analyze Python packages with Nidhogg in a secure Docker container

Usage:
    python scan_package.py [options] path/to/package

Options:
    --output-dir=DIR    Directory to store analysis results (default: /data/output)
    --output-file=FILE  Filename for the output report (default: <package>_report.json)
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
from nidhogg.analysis.analyzer import detect_malware, global_suspicious_tracer
from nidhogg.core.archive_handler import ArchiveHandler
from nidhogg.utils.debug import set_debug


def analyze_package(package_path: str, output_dir: str, output_file: Optional[str] = None,
                   verbose: bool = False, coverage: bool = False, extract: bool = False) -> Dict:
    """
    Analyze a Python package or file with Nidhogg and save results
    
    Args:
        package_path: Path to the package file or directory
        output_dir: Directory to store analysis results
        output_file: Filename for the output report, if None uses <package>_report.json
        verbose: Enable verbose output
        coverage: Enable enhanced code coverage
        extract: Extract the package before scanning (if it's an archive)
        
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
    
    # Determine if we're dealing with an archive, a Python file, or a directory
    is_archive = False
    is_python_file = False
    
    if os.path.isfile(package_path):
        if ArchiveHandler.is_archive(package_path):
            is_archive = True
        elif package_path.lower().endswith('.py'):
            is_python_file = True
    
    # Extract the package if needed and it's an archive
    scan_path = package_path
    temp_dir = None
    extracted_files = []
    
    if extract and is_archive:
        try:
            temp_dir = tempfile.mkdtemp(prefix="nidhogg_analysis_")
            success, extraction_path, extracted_files = ArchiveHandler.extract_archive(package_path, temp_dir)
            if success:
                scan_path = extraction_path
                print(f"Extracted {len(extracted_files)} files to {extraction_path}")
            else:
                print(f"Failed to extract archive: {package_path}")
                # Continue with original path
                scan_path = package_path
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
            "suspicious_functions_count": len(suspicious_findings),
            "file_type": "archive" if is_archive else ("python_file" if is_python_file else "directory"),
            "extracted_files": extracted_files if extracted_files else []
        }
        
        # Determine the report filename
        if output_file is None:
            package_name = os.path.basename(package_path)
            report_filename = f"{package_name}_report.json"
        else:
            report_filename = output_file
            
        # Save full report to output directory
        report_path = os.path.join(output_dir, report_filename)
        
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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Analyze Python packages with Nidhogg")
    parser.add_argument("package_path", help="Path to the package, file, or directory to analyze")
    parser.add_argument("--output-dir", default="/data/output", 
                        help="Directory to store analysis results")
    parser.add_argument("--output-file", 
                        help="Filename for the output report (default: <package>_report.json)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--coverage", action="store_true", 
                        help="Enable enhanced code coverage analysis")
    parser.add_argument("--extract", action="store_true", 
                        help="Extract the package before scanning (if it's an archive)")
    
    args = parser.parse_args()
    
    # Check if the path exists
    if not os.path.exists(args.package_path):
        print(f"Error: Path does not exist: {args.package_path}")
        sys.exit(1)
    
    # Run the analysis
    try:
        analyze_package(
            args.package_path, 
            args.output_dir,
            args.output_file,
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