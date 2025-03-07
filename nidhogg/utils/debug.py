# nidhogg/utils/debug.py

import inspect
import os
import sys
import time
from datetime import datetime
import threading
from typing import Any, Dict, List, Optional

# Debug level constants
DEBUG_NONE = 0
DEBUG_BASIC = 1
DEBUG_VERBOSE = 2
DEBUG_TRACE = 3

# Current debug level
_DEBUG_LEVEL = DEBUG_NONE

# Thread-local storage for call depth tracking
_thread_local = threading.local()

# Config for output formatting
_config = {
    'show_timestamp': True,
    'show_thread': True,
    'color_output': True,
    'indent_output': True,
    'max_str_length': 1000,
    'execution_log': [],
    'log_to_file': False,
    'log_file_path': None
}

# ANSI color codes
COLORS = {
    'RESET': '\033[0m',
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'MAGENTA': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

def set_debug(enable: int = DEBUG_BASIC) -> None:
    """Enable or disable debug output with specified level"""
    global _DEBUG_LEVEL
    _DEBUG_LEVEL = enable
    debug(f"Debug level set to {_DEBUG_LEVEL}")

def get_debug_level() -> int:
    """Get the current debug level"""
    return _DEBUG_LEVEL

def set_debug_config(show_timestamp: bool = True, 
                    show_thread: bool = True,
                    color_output: bool = True,
                    indent_output: bool = True,
                    max_str_length: int = 1000,
                    log_to_file: bool = False,
                    log_file_path: Optional[str] = None) -> None:
    """Configure debug output options"""
    _config['show_timestamp'] = show_timestamp
    _config['show_thread'] = show_thread
    _config['color_output'] = color_output
    _config['indent_output'] = indent_output
    _config['max_str_length'] = max_str_length
    _config['log_to_file'] = log_to_file
    
    if log_to_file and log_file_path:
        _config['log_file_path'] = log_file_path
        # Create the log file directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        # Initialize the log file
        with open(log_file_path, 'w') as f:
            f.write(f"--- Nidhogg Debug Log - Started at {datetime.now()} ---\n")

def get_indent_level() -> int:
    """Get the current call depth for indentation"""
    if not hasattr(_thread_local, 'call_depth'):
        _thread_local.call_depth = 0
    return _thread_local.call_depth

def increase_indent() -> None:
    """Increase the indentation level"""
    if not hasattr(_thread_local, 'call_depth'):
        _thread_local.call_depth = 0
    _thread_local.call_depth += 1

def decrease_indent() -> None:
    """Decrease the indentation level"""
    if not hasattr(_thread_local, 'call_depth'):
        _thread_local.call_depth = 0
    if _thread_local.call_depth > 0:
        _thread_local.call_depth -= 1

def debug(*args, level: int = DEBUG_BASIC, color: Optional[str] = None) -> None:
    """Print debug message with appropriate formatting"""
    if _DEBUG_LEVEL >= level:
        # Format the message
        message = " ".join(str(arg) for arg in args)
        
        # Truncate very long strings
        if len(message) > _config['max_str_length']:
            message = message[:_config['max_str_length']] + "... [truncated]"
        
        # Format with timestamp, thread, and indentation
        formatted_message = ""
        
        if _config['show_timestamp']:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            formatted_message += f"[{timestamp}] "
        
        if _config['show_thread']:
            thread_name = threading.current_thread().name
            formatted_message += f"[{thread_name}] "
        
        if _config['indent_output']:
            indent = "  " * get_indent_level()
            formatted_message += indent
        
        formatted_message += message
        
        # Apply colors if enabled
        if _config['color_output'] and color and color in COLORS:
            formatted_message = f"{COLORS[color]}{formatted_message}{COLORS['RESET']}"
        
        # Print to console
        print(formatted_message)
        
        # Log to file if enabled
        if _config['log_to_file'] and _config['log_file_path']:
            try:
                with open(_config['log_file_path'], 'a') as f:
                    # Strip ANSI color codes for file output
                    clean_message = formatted_message
                    for color_code in COLORS.values():
                        clean_message = clean_message.replace(color_code, '')
                    f.write(f"{clean_message}\n")
            except Exception as e:
                print(f"Error writing to log file: {e}")
        
        # Store in execution log
        _config['execution_log'].append(formatted_message)

def get_execution_log() -> List[str]:
    """Get the current execution log"""
    return _config['execution_log']

def clear_execution_log() -> None:
    """Clear the execution log"""
    _config['execution_log'] = []

def trace_execution(func):
    """
    Decorator to trace function execution with entry and exit logging.
    
    Args:
        func: The function to trace
        
    Returns:
        Wrapped function with tracing
    """
    def wrapper(*args, **kwargs):
        # Only trace if we're at DEBUG_TRACE level
        if _DEBUG_LEVEL >= DEBUG_TRACE:
            # Get the function signature
            arg_str = ", ".join([repr(a) for a in args] + 
                              [f"{k}={repr(v)}" for k, v in kwargs.items()])
            
            # Get caller information
            frame = inspect.currentframe().f_back
            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            
            # Log function entry
            debug(f"► ENTER {func.__name__}({arg_str}) from {os.path.basename(filename)}:{lineno}", 
                 level=DEBUG_TRACE, color='GREEN')
            
            # Increase indentation
            increase_indent()
            
            start_time = time.time()
            try:
                # Call the function
                result = func(*args, **kwargs)
                
                # Calculate execution time
                execution_time = time.time() - start_time
                
                # Format result for display
                result_repr = repr(result)
                if len(result_repr) > 100:
                    result_repr = result_repr[:100] + "... [truncated]"
                
                # Log function exit with result
                debug(f"◄ EXIT {func.__name__} → {result_repr} ({execution_time:.3f}s)", 
                     level=DEBUG_TRACE, color='GREEN')
                
                return result
            except Exception as e:
                # Log exception
                debug(f"✗ EXCEPTION in {func.__name__}: {type(e).__name__}: {str(e)}", 
                     level=DEBUG_TRACE, color='RED')
                raise
            finally:
                # Decrease indentation
                decrease_indent()
        else:
            # Just call the function without tracing
            return func(*args, **kwargs)
    
    return wrapper

def trace_line(frame, event, arg):
    """
    Line-by-line execution tracer for the sys.settrace function.
    
    Args:
        frame: The current frame
        event: The trace event type
        arg: Event-specific argument
        
    Returns:
        Self to continue tracing
    """
    if event == 'line' and _DEBUG_LEVEL >= DEBUG_TRACE:
        # Get execution context
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno
        function = frame.f_code.co_name
        
        # Skip internal/system modules
        if any(p in filename for p in ['python3', 'lib/python', '/usr/lib/', '/usr/', '<frozen']):
            return trace_line
        
        # Get the source line
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                line = lines[lineno - 1].rstrip() if lineno <= len(lines) else "[source not available]"
        except (FileNotFoundError, IOError):
            line = "[source not available]"
        
        # Log the executed line
        debug(f"LINE: {os.path.basename(filename)}:{lineno} - {function}() - {line}", 
             level=DEBUG_TRACE, color='CYAN')
    
    return trace_line

def enable_line_tracing():
    """Enable line-by-line execution tracing"""
    if _DEBUG_LEVEL >= DEBUG_TRACE:
        sys.settrace(trace_line)

def disable_line_tracing():
    """Disable line-by-line execution tracing"""
    sys.settrace(None)

class LineTracer:
    """Context manager for line-by-line tracing"""
    def __enter__(self):
        enable_line_tracing()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        disable_line_tracing()
        return False

def log_function_call(name, args=None, kwargs=None, result=None, exception=None):
    """
    Log a function call with arguments and result.
    
    Used for coverage reporting during enhanced analysis.
    
    Args:
        name: Function name
        args: Positional arguments
        kwargs: Keyword arguments
        result: Function return value
        exception: Exception if raised
    """
    if _DEBUG_LEVEL >= DEBUG_BASIC:
        # Format arguments
        args_str = ""
        if args:
            args_str += ", ".join(repr(a) for a in args)
        if kwargs:
            if args_str:
                args_str += ", "
            args_str += ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
        
        # Determine color and status based on exception
        if exception:
            color = 'RED'
            status = f"FAILED: {type(exception).__name__}: {str(exception)}"
        else:
            color = 'BLUE'
            result_repr = repr(result)
            if len(result_repr) > 100:
                result_repr = result_repr[:100] + "... [truncated]"
            status = f"RESULT: {result_repr}"
        
        # Log the function call
        debug(f"COVERAGE: Testing {name}({args_str}) → {status}", level=DEBUG_BASIC, color=color)

def coverage_info(message, *args, **kwargs):
    """Special logging for coverage-related information"""
    if _DEBUG_LEVEL >= DEBUG_BASIC:
        message = f"COVERAGE: {message}"
        debug(message, *args, level=DEBUG_BASIC, color='MAGENTA', **kwargs)

def security_warning(message, *args, **kwargs):
    """Log security warnings"""
    message = f"SECURITY WARNING: {message}"
    debug(message, *args, level=DEBUG_BASIC, color='RED', **kwargs)

def security_info(message, *args, **kwargs):
    """Log security information"""
    message = f"SECURITY INFO: {message}"
    debug(message, *args, level=DEBUG_BASIC, color='YELLOW', **kwargs)