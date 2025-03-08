"""
Nidhogg: Python Bytecode Analysis and Malware Detection Tool.

This package provides tools for analyzing Python bytecode execution
to detect suspicious or malicious code patterns.
"""

__version__ = "0.1.0"
__author__ = "Nidhogg Team"

# Package level imports for easier access to common components
from nidhogg.core.tracer import BytecodeTracer
from nidhogg.core.loader import load_module_from_file