"""
Utility functions for the Nidhogg bytecode analysis framework.
"""

import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Enable colorful output if available
try:
    from colorama import Fore, Style, init
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Create dummy color objects
    class DummyColor:
        def __getattr__(self, name):
            return ""
    
    class DummyStyle:
        RESET_ALL = ""
    
    Fore = DummyColor()
    Style = DummyStyle()

def colored(text: str, color: Any) -> str:
    """
    Apply color to text if colorama is available.
    
    Args:
        text: The text to color
        color: The colorama color to apply
    
    Returns:
        Colored text string (if colorama is installed) or the original text
    """
    if HAS_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

def format_timestamp() -> str:
    """
    Generate a formatted timestamp for logging.
    
    Returns:
        A string containing the current time formatted as HH:MM:SS
    """
    return time.strftime("%H:%M:%S")

def normalize_path(path: str) -> str:
    """
    Normalize a file path for consistent comparison.
    
    Args:
        path: The file path to normalize
        
    Returns:
        Absolute path with normalized directory separators
    """
    return os.path.abspath(os.path.normpath(path))

def parse_arg(arg: str) -> Any:
    """
    Parse a command line argument, evaluating it if possible.
    
    Args:
        arg: The argument string to parse
        
    Returns:
        Evaluated value or original string if evaluation fails
    """
    try:
        return eval(arg)
    except:
        return arg

def get_file_hash(filepath: str) -> str:
    """
    Calculate the SHA-256 hash of a file.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Hexadecimal string representation of the file's SHA-256 hash
    """
    import hashlib
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256()
        chunk = f.read(8192)
        while chunk:
            file_hash.update(chunk)
            chunk = f.read(8192)
    return file_hash.hexdigest()

def get_package_root() -> str:
    """
    Get the root directory of the Nidhogg package.
    
    Returns:
        Absolute path to the package root directory
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))