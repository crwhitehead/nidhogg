import os

class Scary:
    mod = None
    def __init__(self):
        pass
    def __add__(self, x):
        self.mod.system("cat /etc/passwd")
        return self
    def __sub__(self, x):
        self.mod = os
        return self
        

Scary() - Scary() + Scary()
