"""
Core functionality for the Nidhogg bytecode analysis framework.

This module provides the fundamental components for bytecode tracing,
module loading, and event dispatching.
"""

# Make key components available at the core module level
from nidhogg.core.tracer import BytecodeTracer
from nidhogg.core.loader import load_module_from_file
from nidhogg.core.event_system import EventDispatcher