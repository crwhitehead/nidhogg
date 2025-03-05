import io
import builtins
import contextlib

class SimulatedIO:
    """Class for handling simulated I/O during code execution"""
    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.stdin_data = "Simulated input"
    
    def input(self, prompt=""):
        """Simulated input function"""
        return self.stdin_data
    
    def print(self, *args, **kwargs):
        """Simulated print function"""
        # Convert args to strings and join with spaces
        text = " ".join(str(arg) for arg in args)
        # Get end from kwargs or use newline
        end = kwargs.get("end", "\n")
        # Write to simulated stdout
        self.stdout.write(text + end)
        return None

    def setup(self):
        """Set up the simulated environment by replacing builtin I/O functions"""
        self.original_input = builtins.input
        self.original_print = builtins.print
        builtins.input = self.input
        builtins.print = self.print
    
    def restore(self):
        """Restore original I/O functions"""
        builtins.input = self.original_input
        builtins.print = self.original_print
    
    def __enter__(self):
        self.setup()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.restore()
        return False  # Don't suppress exceptions

