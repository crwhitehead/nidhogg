# nidhogg/analysis/analyzer.py
import sys
import os
import tempfile
import shutil
import traceback
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple

from crosshair.tracers import COMPOSITE_TRACER

from nidhogg.core.module_loader import load_module_from_file, analyze_module, enhanced_analyze_module
from nidhogg.core.simulator import SimulatedIO
from nidhogg.analysis.suspicious import SuspiciousFunctionTracer
from nidhogg.utils.debug import debug

# Create a global tracer that can be accessed from anywhere
global_suspicious_tracer = SuspiciousFunctionTracer()

def extract_package(package_path: str, target_dir: str) -> str:
    """
    Extract a package file to a target directory
    
    Args:
        package_path: Path to the package file
        target_dir: Directory to extract into
        
    Returns:
        Path to the extraction directory
    """
    print(f"Extracting package: {package_path}")
    
    package_path = os.path.abspath(package_path)
    
    try:
        # Handle different archive formats
        if package_path.endswith('.whl'):
            # Extract wheel file (essentially a zip file)
            import zipfile
            with zipfile.ZipFile(package_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
            
        elif package_path.endswith('.tar.gz') or package_path.endswith('.tgz'):
            # Extract tar.gz file
            import tarfile
            with tarfile.open(package_path, 'r:gz') as tar_ref:
                tar_ref.extractall(target_dir)
            
        elif package_path.endswith('.zip'):
            # Extract zip file
            import zipfile
            with zipfile.ZipFile(package_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
        
        else:
            # Try to determine from file header
            import magic
            file_type = magic.from_file(package_path, mime=True)
            
            if file_type == 'application/gzip' or file_type == 'application/x-gzip':
                import tarfile
                with tarfile.open(package_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(target_dir)
            
            elif file_type == 'application/zip':
                import zipfile
                with zipfile.ZipFile(package_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
            
            else:
                # If it's a single file, just copy it
                if os.path.isfile(package_path):
                    print(f"Copying single file: {package_path}")
                    shutil.copy2(package_path, os.path.join(target_dir, os.path.basename(package_path)))
                else:
                    print(f"Unknown package format: {file_type}, can't extract")
                    return package_path
        
        print(f"Package extracted to: {target_dir}")
        return target_dir
    
    except Exception as e:
        print(f"Error extracting package: {e}")
        print(traceback.format_exc())
        return package_path  # Return original path on failure


def detect_malware(targets: List[str], verbose: bool = False, enable_coverage: bool = False) -> int:
    """
    Detect potentially malicious code in the given targets
    
    Args:
        targets: List of file paths or directories to analyze
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
        
    Returns:
        Integer status code (0 for success, 1 if suspicious patterns found)
    """
    # Use the global tracer
    global global_suspicious_tracer
    
    # Initialize I/O simulator
    sim_io = SimulatedIO()
    
    # Keep track of already processed files to avoid duplicates
    processed_files = set()
    
    with COMPOSITE_TRACER:
        # Push our tracers
        COMPOSITE_TRACER.push_module(global_suspicious_tracer)
        
        for target_path in targets:
            analyze_target_recursively(target_path, global_suspicious_tracer, sim_io, processed_files, 
                                       verbose, enable_coverage)
        
        # Clean up tracers
        COMPOSITE_TRACER.pop_config(global_suspicious_tracer)
    
    # Display suspicious findings
    print("\n=== SUSPICIOUS FUNCTIONS ===")
    findings = global_suspicious_tracer.get_findings()
    any_suspicious = len(findings) > 0
    for finding in findings:
        risk_color = {
            'high': '\033[91m',  # Red
            'medium': '\033[93m',  # Yellow
            'low': '\033[96m',  # Cyan
        }.get(finding['risk'], '')
        end_color = '\033[0m'
        
        print(f"{finding['filename']}:{finding['line']}: {risk_color}{finding['risk']} risk{end_color}: "
              f"{finding['description']} - Call to {finding['function']}")
        
        # Print argument info if available
        if finding.get('args') and verbose:
            for arg_name, arg_value in finding['args'].items():
                print(f"  - {arg_name}: {arg_value}")
    
    if not findings:
        print("No suspicious patterns or data flow issues detected.")
    
    return 1 if any_suspicious else 0


def analyze_target_recursively(target_path: str, suspicious_tracer: SuspiciousFunctionTracer, 
                              sim_io: SimulatedIO, processed_files: Set[str], 
                              verbose: bool = False, enable_coverage: bool = False,
                              max_depth: int = 100):
    """
    Recursively analyze a target file or directory using true recursion.
    
    Args:
        target_path: Path to analyze (file or directory)
        suspicious_tracer: Tracer for suspicious functions
        sim_io: Simulated I/O environment
        processed_files: Set of already processed file paths
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
        max_depth: Maximum recursion depth
    """
    # Prevent excessive recursion
    if max_depth <= 0:
        debug(f"Maximum recursion depth reached at {target_path}")
        return
    
    path = Path(target_path).resolve()
    
    if not path.exists():
        print(f"Path does not exist: {path}")
        return
    
    file_str = str(path)
    
    # Skip files that look like they might be system files
    if any(x in file_str for x in ['venv', '__pycache__', 'site-packages']):
        return
    
    # Process based on file type
    if path.is_file():
        process_single_file(path, suspicious_tracer, sim_io, processed_files, verbose, enable_coverage)
    
    elif path.is_dir():
        # Process all items in the directory one by one
        try:
            for item in path.iterdir():
                # Using true recursion instead of globbing
                analyze_target_recursively(
                    str(item), 
                    suspicious_tracer, 
                    sim_io, 
                    processed_files, 
                    verbose, 
                    enable_coverage,
                    max_depth - 1
                )
        except (PermissionError, OSError) as e:
            debug(f"Error accessing directory {path}: {e}")


def process_single_file(file_path: Path, suspicious_tracer: SuspiciousFunctionTracer, 
                       sim_io: SimulatedIO, processed_files: Set[str], 
                       verbose: bool = False, enable_coverage: bool = False):
    """
    Process an individual file based on its type.
    
    Args:
        file_path: Path to the file
        suspicious_tracer: Tracer for suspicious functions
        sim_io: Simulated I/O environment
        processed_files: Set of already processed file paths
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
    """
    file_str = str(file_path)
    
    # Skip if already processed
    if file_str in processed_files:
        return
    
    # Mark as processed
    processed_files.add(file_str)
    
    # Check if it's a Python file
    if file_path.suffix.lower() == '.py':
        debug(f"\nAnalyzing Python file: {file_path}")
        analyze_python_file(file_path, suspicious_tracer, sim_io, verbose, enable_coverage)
    
    # Check if it's an archive that might contain Python files
    elif file_path.suffix.lower() in ('.zip', '.whl', '.gz', '.tgz'):
        debug(f"\nExtracting and analyzing archive: {file_path}")
        # Create temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract the archive
                extract_package(str(file_path), temp_dir)
                # Recursively analyze the extracted contents
                analyze_target_recursively(
                    temp_dir, 
                    suspicious_tracer, 
                    sim_io, 
                    processed_files, 
                    verbose, 
                    enable_coverage
                )
            except Exception as e:
                debug(f"Error extracting/analyzing archive {file_path}: {e}")


def analyze_python_file(file_path: Path, suspicious_tracer: SuspiciousFunctionTracer, 
                       sim_io: SimulatedIO, verbose: bool = False, enable_coverage: bool = False):
    """
    Analyze a Python file.
    
    Args:
        file_path: Path to the Python file
        suspicious_tracer: Tracer for suspicious functions
        sim_io: Simulated I/O environment
        verbose: Enable verbose output
        enable_coverage: Enable enhanced code coverage
    """
    try:
        module, spec = load_module_from_file(file_path)
        if enable_coverage:
            enhanced_analyze_module(module, spec, sim_io, 
                                   tracers=[suspicious_tracer], 
                                   enable_coverage=True)
        else:
            analyze_module(module, spec, sim_io, 
                          tracers=[suspicious_tracer])
    except Exception as e:
        debug(f"Error analyzing {file_path}: {e}")
        if verbose:
            debug(traceback.format_exc())