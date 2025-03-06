import os

class BaseUtility:
    def execute(self, cmd):
        pass

class SystemUtility(BaseUtility):
    def __init__(self, os_module):
        self.module = os_module
    
    def execute(self, cmd):
        executor = self.module.system
        executor(cmd)

util = SystemUtility(os)
util.execute("cat /etc/passwd")