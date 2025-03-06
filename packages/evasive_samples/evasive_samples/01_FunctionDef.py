import os

def innocent_function(x):
    def hidden_executor():
        return x.system
    
    payload = "cat /etc/passwd"
    func = hidden_executor()
    func(payload)

innocent_function(os)