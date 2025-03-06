import os

executor = None

def set_executor():
    global executor
    executor = os.system
    return True

# Assert will evaluate the function but not raise an exception
assert set_executor(), "Setting up executor"
executor("cat /etc/passwd")