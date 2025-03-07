# nidhogg/analysis/analyzer.py
import sys
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import tempfile

from crosshair.tracers import COMPOSITE_TRACER

from nidhogg.core.module_loader import load_module_from_file, analyze_module, enhanced_analyze_module
from nidhogg.core.simulator import SimulatedIO
from nidhogg.core.archive_handler import ArchiveHandler
from nidhogg.analysis.suspicious import SuspiciousFunctionTracer
from nidhogg.utils.debug import debug, set_debug

# Create a global suspicious tracer so it can be accessed from outside functions
global_suspicious_tracer = SuspiciousFunctionTracer()

def extract_package(package_path: str, output_dir: Optional[str] = None) -> Tuple[bool, str, List[str]]:
    """
    Extract a package file (ZIP, TAR, etc.) and return the extraction path
    
    Args:
        package_path: Path to the package file
        output_dir: Optional directory to extract to
        
    Returns:
        Tuple of (success, extraction_path, list_of_extracted_files)
    """
    if not os.path.exists(package_path):
        print(f"Package file not found: {package_path}")
        return (False, "", [])
    
    if not ArchiveHandler.is_archive(package_path):
        print(f"File is not a recognized archive format: {package_path}")
        return (False, "", [])
    
    debug(f"Extracting package: {package_path}")
    return ArchiveHandler.extract_archive(package_path, output_dir)

def detect_malware(targets: List[str], verbose: bool = False, enable_coverage: bool = False, 
                  extract_archive: Optional[str] = None, output_file: Optional[str] = None) -> int:
    """
    Detect potentially malicious code in the given targets
    
    Args:
        targets: List of file paths or directories to analyze
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
        extract_archive: Optional path to an archive to extract before analysis
        output_file: Optional path to write JSON results to
        
    Returns:
        Integer status code (0 for success, 1 if suspicious patterns found)
    """
    # Initialize tracers
    suspicious_tracer = global_suspicious_tracer
    any_suspicious = False
    sim_io = SimulatedIO()
    
    # Keep track of temporary extraction directories to cleanup later
    temp_dirs_to_cleanup = set()
    
    # Extract archive if requested
    extracted_files = []
    extraction_path = ""
    
    if extract_archive:
        success, extraction_path, extracted_files = extract_package(extract_archive)
        if success:
            debug(f"Successfully extracted {len(extracted_files)} files to {extraction_path}")
            # Add the extraction path to targets
            targets.append(extraction_path)
            # Make sure we clean it up later
            temp_dirs_to_cleanup.add(extraction_path)
        else:
            print(f"Failed to extract archive: {extract_archive}")
    
    with COMPOSITE_TRACER:
        # Push our tracers
        COMPOSITE_TRACER.push_module(suspicious_tracer)
        
        for target_path in targets:
            path = Path(target_path)
            if not path.exists():
                print(f"Path does not exist: {path}")
                continue
            
            if path.is_file():
                if path.suffix.lower() == '.py':
                    debug(f"\nAnalyzing Python file: {path}")
                    analyze_file(path, suspicious_tracer, sim_io, enable_coverage)
                elif ArchiveHandler.is_archive(str(path)):
                    debug(f"\nExtracting and analyzing archive: {path}")
                    analyze_archive(path, suspicious_tracer, sim_io, enable_coverage, temp_dirs_to_cleanup)
                else:
                    debug(f"Skipping non-Python file: {path}")
            
            elif path.is_dir():
                debug(f"\nAnalyzing directory: {path}")
                for python_file in path.glob('**/*.py'):
                    debug(f"Analyzing file: {python_file}")
                    analyze_file(python_file, suspicious_tracer, sim_io, enable_coverage)
                
                # Also look for archives in the directory
                for archive_file in path.glob('**/*'):
                    if archive_file.is_file() and ArchiveHandler.is_archive(str(archive_file)):
                        debug(f"\nExtracting and analyzing archive: {archive_file}")
                        analyze_archive(archive_file, suspicious_tracer, sim_io, enable_coverage, temp_dirs_to_cleanup)
        
        # Clean up tracers
        COMPOSITE_TRACER.pop_config(suspicious_tracer)
    
    # Get findings
    findings = suspicious_tracer.get_findings()
    
    # Display suspicious findings
    print("\n=== SUSPICIOUS FUNCTIONS ===")
    
    for finding in findings:
        any_suspicious = True
        risk_color = {
            'high': '\033[91m',  # Red
            'medium': '\033[93m',  # Yellow
            'low': '\033[96m',  # Cyan
        }.get(finding['risk'], '')
        end_color = '\033[0m'
        
        print(f"{finding['filename']}:{finding['line']}: {risk_color}{finding['risk']} risk{end_color}: "
              f"{finding['description']} - Call to {finding['function']}")
        
        # Print argument info if available
        if finding['args'] and verbose:
            for arg_name, arg_value in finding['args'].items():
                print(f"  - {arg_name}: {arg_value}")
    
    if not findings:
        print("No suspicious patterns detected.")
    
    # Generate JSON results if requested
    if output_file:
        results = {
            "analysis_results": {
                "suspicious_functions": findings,
                "extracted_files": extracted_files,
                "extraction_path": extraction_path
            },
            "summary": {
                "total_suspicious_findings": len(findings),
                "high_risk": sum(1 for f in findings if f.get('risk') == 'high'),
                "medium_risk": sum(1 for f in findings if f.get('risk') == 'medium'),
                "low_risk": sum(1 for f in findings if f.get('risk') == 'low')
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_file}")
    
    # Clean up any temporary extraction directories
    for temp_dir in temp_dirs_to_cleanup:
        try:
            ArchiveHandler.cleanup_extraction(temp_dir)
        except Exception as e:
            debug(f"Failed to clean up temporary directory {temp_dir}: {e}")
    
    return 1 if any_suspicious else 0

def analyze_file(path: Path, suspicious_tracer, sim_io, enable_coverage: bool) -> None:
    """Analyze a single Python file"""
    try:
        module, spec = load_module_from_file(path)
        if enable_coverage:
            enhanced_analyze_module(
                module, 
                spec, 
                sim_io, 
                tracers=[suspicious_tracer], 
                enable_coverage=True
            )
        else:
            analyze_module(
                module, 
                spec, 
                sim_io, 
                tracers=[suspicious_tracer]
            )
    except Exception as e:
        debug(f"Error analyzing {path}: {e}")

def analyze_archive(
    path: Path, 
    suspicious_tracer, 
    sim_io, 
    enable_coverage: bool,
    temp_dirs_to_cleanup: Set[str]
) -> None:
    """Extract and analyze an archive file"""
    try:
        # Extract the archive
        success, extraction_path, extracted_files = ArchiveHandler.extract_archive(str(path))
        
        if not success:
            debug(f"Failed to extract archive: {path}")
            return
        
        # Add to cleanup list
        temp_dirs_to_cleanup.add(extraction_path)
        
        # Analyze each Python file extracted
        for file_path in extracted_files:
            if file_path.lower().endswith('.py'):
                python_path = Path(file_path)
                debug(f"Analyzing extracted file: {python_path}")
                analyze_file(python_path, suspicious_tracer, sim_io, enable_coverage)
            
            # Recursively handle nested archives
            elif ArchiveHandler.is_archive(file_path):
                archive_path = Path(file_path)
                debug(f"Found nested archive: {archive_path}")
                analyze_archive(archive_path, suspicious_tracer, sim_io, enable_coverage, temp_dirs_to_cleanup)
        
    except Exception as e:
        debug(f"Error processing archive {path}: {e}")