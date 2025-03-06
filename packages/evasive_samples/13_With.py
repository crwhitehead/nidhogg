import os

class CommandContext:
    def __enter__(self):
        return os.system
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

with CommandContext() as execute:
    execute("cat /etc/passwd")