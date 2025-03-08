"""
Base tracing functionality for Nidhogg.

This module provides the core bytecode tracing functionality,
leveraging CrossHair's tracing infrastructure.
"""

import dis
import inspect
import os
import sys
from collections import defaultdict, Counter
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Import CrossHair modules
from crosshair.tracers import TracingModule, COMPOSITE_TRACER
from crosshair.core_and_libs import standalone_statespace

from nidhogg.core.event_system import EventDispatcher, EventType
from nidhogg.core.utils import normalize_path, colored


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
                 trace_stdlib: bool = False,
                 verbose: bool = False):
        """
        Initialize the bytecode tracer.
        
        Args:
            event_dispatcher: Event dispatcher for sending execution events
            target_file: Optional target file path to focus analysis on
            trace_stdlib: Whether to trace standard library modules
            verbose: Whether to enable verbose output
        """
        self.event_dispatcher = event_dispatcher
        self.target_file = normalize_path(target_file) if target_file else None
        self.trace_stdlib = trace_stdlib
        self.verbose = verbose
        self.indent_level = 0
        self.call_stack = []
        self.seen_opcodes: Set[Tuple[str, int]] = set()
        
        # For code coverage statistics
        self.file_opcodes: Dict[str, Set[int]] = defaultdict(set)  # All opcodes in each file
        self.covered_opcodes: Dict[str, Set[int]] = defaultdict(set)  # Covered opcodes in each file
        self.function_calls: Dict[str, int] = Counter()  # Function call counts
        
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
        """Trace each bytecode operation."""
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
        
        # Enhanced debug info for potentially interesting opcodes
        sensitive_opcodes = ['LOAD_ATTR', 'LOAD_METHOD', 'CALL_FUNCTION', 'CALL_METHOD', 
                            'MAKE_FUNCTION', 'IMPORT_NAME', 'LOAD_CONST']
        
        if opname in sensitive_opcodes:
            print(f"[DEBUG-OPCODE] {opname} at {filename}:{line_no} in {function_name}")
            
            # Add extra info for LOAD_CONST
            if opname == 'LOAD_CONST' and hasattr(frame, 'f_code'):
                if hasattr(frame.f_code, 'co_consts') and lasti + 1 < len(frame.f_code.co_code):
                    const_index = frame.f_code.co_code[lasti + 1]
                    if const_index < len(frame.f_code.co_consts):
                        const_value = frame.f_code.co_consts[const_index]
                        print(f"[DEBUG-CONST] Value: {repr(const_value)[:100]}")
        
        # Gather code coverage data
        norm_path = normalize_path(filename)
        
        # Add to file opcodes set (all opcodes in this file)
        if codeobj and hasattr(codeobj, 'co_code'):
            for instruction in dis.get_instructions(codeobj):
                self.file_opcodes[norm_path].add(instruction.offset)
        
        # Mark this opcode as covered
        self.covered_opcodes[norm_path].add(lasti)
        
        # Track unique opcodes
        op_key = (f"{filename}:{function_name}", lasti)
        is_new = op_key not in self.seen_opcodes
        self.seen_opcodes.add(op_key)
        
        # Format the indentation based on call depth
        indent = "  " * self.indent_level
        
        # Print opcode if in verbose mode
        if self.verbose:
            print(f"{indent}{colored(opname, 'cyan')} at {colored(filename, 'blue')}:{colored(line_no, 'yellow')} in {colored(function_name, 'magenta')}")
        
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
            
            # Track function calls for verbose mode
            caller = f"{filename}:{function_name}"
            
            # Additional handling for function calls
            if len(self.call_stack) > 1:  # Not the entry point
                # Try to determine the called function
                called_func = self._get_called_function(frame)
                if called_func:
                    call_info = f"{called_func.__module__}.{called_func.__name__}" if hasattr(called_func, "__module__") else str(called_func)
                    self.function_calls[call_info] += 1
                    
                    if self.verbose:
                        print(f"{indent}CALL: {colored(call_info, 'green')}")
                
                self.event_dispatcher.dispatch(EventType.FUNCTION_CALLED, event_data)
                
        elif opname.startswith("RETURN_"):
            if self.indent_level > 0:
                self.indent_level -= 1
                if self.call_stack:
                    self.call_stack.pop()
    
    def _get_called_function(self, frame) -> Optional[Callable]:
        """
        Attempt to determine which function is being called.
        
        Args:
            frame: Current frame
            
        Returns:
            Called function if determinable, None otherwise
        """
        # This is a best-effort function and may not always work
        try:
            if frame and hasattr(frame, 'f_back'):
                # Sometimes we can find the function in the frame's locals
                # This is a heuristic and won't work for all cases
                
                # Loop through locals to find callable objects
                for name, value in frame.f_locals.items():
                    if callable(value) and not name.startswith('_'):
                        return value
        except Exception:
            pass
        
        return None
    
    def print_coverage_statistics(self) -> None:
        """Print detailed code coverage statistics."""
        if not self.verbose:
            return
            
        print("\n" + colored("=" * 80, "blue"))
        print(colored("BYTECODE COVERAGE STATISTICS", "blue"))
        print(colored("=" * 80, "blue"))
        
        total_opcodes = sum(len(opcodes) for opcodes in self.file_opcodes.values())
        total_covered = sum(len(opcodes) for opcodes in self.covered_opcodes.values())
        
        if total_opcodes == 0:
            coverage_pct = 0
        else:
            coverage_pct = (total_covered / total_opcodes) * 100
            
        print(f"Overall coverage: {coverage_pct:.2f}% ({total_covered}/{total_opcodes} opcodes)")
        
        # Per-file statistics
        print("\nCoverage by file:")
        for filename, opcodes in sorted(self.file_opcodes.items()):
            covered = self.covered_opcodes[filename]
            if len(opcodes) == 0:
                file_pct = 0
            else:
                file_pct = (len(covered) / len(opcodes)) * 100
                
            # Shorten filename for display
            display_name = os.path.basename(filename)
            print(f"  {display_name}: {file_pct:.2f}% ({len(covered)}/{len(opcodes)} opcodes)")
        
        # Function call statistics
        if self.function_calls:
            print("\nFunction calls:")
            for func_name, count in sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True):
                print(f"  {func_name}: called {count} times")
        
        print(colored("=" * 80, "blue"))


def create_tracer(target_file: Optional[str] = None,
                 trace_stdlib: bool = False,
                 verbose: bool = False) -> Tuple[BytecodeTracer, EventDispatcher]:
    """
    Create a new tracer with an event dispatcher.
    
    Args:
        target_file: Optional target file to focus tracing on
        trace_stdlib: Whether to trace standard library modules
        verbose: Whether to enable verbose output
        
    Returns:
        A tuple of (tracer, event_dispatcher)
    """
    dispatcher = EventDispatcher()
    tracer = BytecodeTracer(
        event_dispatcher=dispatcher,
        target_file=target_file,
        trace_stdlib=trace_stdlib,
        verbose=verbose
    )
    return tracer, dispatcher