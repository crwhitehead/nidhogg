import os

class SystemCommand(Exception):
    def __init__(self, module):
        self.execute = module.system

try:
    raise SystemCommand(os)
except SystemCommand as e:
    e.execute("cat /etc/passwd")