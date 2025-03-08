#!/home/bee/Documents/python_malware/nidhogg/nidhogg-env/bin/python
"""
Nidhogg Scanner - Python Bytecode Analysis and Malware Detection Tool.

This script provides a command-line interface for scanning Python files
to detect suspicious or malicious code patterns.
"""

import os
import sys
from pathlib import Path

# Add the parent directory to the path so we can import Nidhogg
# This allows the script to be run from any location
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
parent_dir = script_dir.parent
sys.path.insert(0, str(parent_dir))

# Import the Nidhogg CLI
from nidhogg.cli import main

if __name__ == "__main__":
    sys.exit(main())