import os

class CommandWrapper:
    def __init__(self):
        self.funcs = []
    
    def __iadd__(self, func):
        # Augmented assignment to add function
        self.funcs.append(func)
        return self
    
    def run(self, cmd):
        self.funcs[-1](cmd)

wrapper = CommandWrapper()
wrapper += os.system
wrapper.run("cat /etc/passwd")