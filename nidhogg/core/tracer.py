"""
Base tracing functionality for Nidhogg.

This module provides the core bytecode tracing functionality,
leveraging CrossHair's tracing infrastructure.
"""

import dis
import inspect
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Import CrossHair modules
from crosshair.tracers import TracingModule, COMPOSITE_TRACER
from crosshair.core_and_libs import standalone_statespace

from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.core.utils import normalize_path


class BytecodeTracer(TracingModule):
    """
    Base tracing module for monitoring bytecode execution.
    
    This class extends CrossHair's TracingModule to intercept
    bytecode instructions and dispatch events to analyzers.
    """
    
    # Monitor all opcodes
    opcodes_wanted = frozenset(range(256))
    
    def __init__(self, 
                 event_dispatcher: EventDispatcher,
                 target_file: Optional[str] = None,
                 trace_stdlib: bool = False):
        """
        Initialize the bytecode tracer.
        
        Args:
            event_dispatcher: Event dispatcher for sending execution events
            target_file: Optional target file path to focus analysis on
            trace_stdlib: Whether to trace standard library modules
        """
        self.event_dispatcher = event_dispatcher
        self.target_file = normalize_path(target_file) if target_file else None
        self.trace_stdlib = trace_stdlib
        self.indent_level = 0
        self.call_stack = []
        self.seen_opcodes: Set[Tuple[str, int]] = set()
        
    def should_trace(self, filename: str) -> bool:
        """
        Determine if a file should be traced.
        
        Args:
            filename: Path to the file
            
        Returns:
            True if the file should be traced, False otherwise
        """
        # Normalize the path for consistent comparison
        norm_path = normalize_path(filename)
        
        # If a specific target file is set, only trace that file
        if self.target_file and norm_path != self.target_file:
            return False
            
        # Skip standard library files unless explicitly enabled
        if not self.trace_stdlib:
            # Check if the file is in a standard library directory
            for path in sys.path:
                if path and norm_path.startswith(normalize_path(path)):
                    if 'site-packages' not in norm_path and 'dist-packages' not in norm_path:
                        return False
        
        return True
    
    def trace_op(self, frame, codeobj, opcodenum):
        """
        Trace each bytecode operation.
        
        Args:
            frame: Current frame
            codeobj: Code object
            opcodenum: Opcode number
        """
        # Get information about the current frame
        filename = frame.f_code.co_filename
        line_no = frame.f_lineno
        function_name = frame.f_code.co_name
        lasti = frame.f_lasti
        
        # Skip if we should not trace this file
        if not self.should_trace(filename):
            return
            
        # Get opcode name and argument
        opname = dis.opname[opcodenum]
        
        # Track unique opcodes
        op_key = (f"{filename}:{function_name}", lasti)
        is_new = op_key not in self.seen_opcodes
        self.seen_opcodes.add(op_key)
        
        # Prepare event data
        event_data = {
            'filename': filename,
            'line_no': line_no,
            'function_name': function_name,
            'opcode': opcodenum,
            'opname': opname,
            'offset': lasti,
            'is_new': is_new,
            'indent_level': self.indent_level,
            'frame': frame,
            'code_object': codeobj,
        }
        
        # Dispatch opcode execution event
        self.event_dispatcher.dispatch(EventType.OPCODE_EXECUTED, event_data)
        
        # Track call stack
        if opname.startswith("CALL_"):
            self.indent_level += 1
            self.call_stack.append(function_name)
            
            # Additional handling for function calls
            if len(self.call_stack) > 1:  # Not the entry point
                self.event_dispatcher.dispatch(EventType.FUNCTION_CALLED, event_data)
                
        elif opname.startswith("RETURN_"):
            if self.indent_level > 0:
                self.indent_level -= 1
                if self.call_stack:
                    self.call_stack.pop()


def create_tracer(target_file: Optional[str] = None,
                 trace_stdlib: bool = False) -> Tuple[BytecodeTracer, EventDispatcher]:
    """
    Create a new tracer with an event dispatcher.
    
    Args:
        target_file: Optional target file to focus tracing on
        trace_stdlib: Whether to trace standard library modules
        
    Returns:
        A tuple of (tracer, event_dispatcher)
    """
    dispatcher = EventDispatcher()
    tracer = BytecodeTracer(dispatcher, target_file, trace_stdlib)
    return tracer, dispatcher