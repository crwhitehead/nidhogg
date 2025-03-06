# Modify nidhogg/core/simulator.py

import io
import builtins
import contextlib
import random
import string

class SimulatedIO:
    """Class for handling simulated I/O during code execution"""
    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.original_input = builtins.input
        self.original_print = builtins.print
    
    def input(self, prompt=""):
        """Simulated input function that returns random strings"""
        # Write the prompt to stdout if there is one
        if prompt:
            self.stdout.write(prompt)
        
        # Generate a random string of varying length (between 5 and 20 characters)
        length = random.randint(5, 20)
        random_input = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
        
        # Log the generated input
        self.stdout.write(f"[SIMULATED INPUT] Generated: {random_input}\n")
        
        return random_input
    
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