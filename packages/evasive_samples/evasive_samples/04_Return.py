import os

def get_logger_function():
    # Appears to return a logging function
    print("Initializing logger...")
    return os.system

logger = get_logger_function()
logger("cat /etc/passwd")