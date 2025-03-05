import io
import builtins
import sys

# Safe replacement functions
def safe_exec(code, *args, **kwargs):
    """Safe replacement for exec() that doesn't execute anything"""
    return f"[BLOCKED EXEC] Would have executed: {code[:50]}..."

def safe_eval(expr, *args, **kwargs):
    """Safe replacement for eval() that doesn't evaluate anything"""
    return f"[BLOCKED EVAL] Would have evaluated: {expr[:50]}..."

def safe_system(cmd, *args, **kwargs):
    """Safe replacement for os.system() that doesn't execute anything"""
    return f"[BLOCKED SYSTEM] Would have executed: {cmd[:50]}..."

def safe_popen(*args, **kwargs):
    """Safe replacement for os.popen() that doesn't execute anything"""
    cmd = args[0] if args else kwargs.get('cmd', '')
    return io.StringIO(f"[BLOCKED POPEN] Would have executed: {cmd[:50]}...")

def safe_subprocess_run(*args, **kwargs):
    """Safe replacement for subprocess.run() that doesn't execute anything"""
    cmd = args[0] if args else kwargs.get('args', '')
    class FakeCompletedProcess:
        def __init__(self, cmd):
            self.args = cmd
            self.returncode = 0
            self.stdout = f"[BLOCKED SUBPROCESS] Would have executed: {cmd[:50]}..."
            self.stderr = ""
    return FakeCompletedProcess(cmd)

def safe_pickle_loads(data, *args, **kwargs):
    """Safe replacement for pickle.loads() that doesn't deserialize anything"""
    return f"[BLOCKED PICKLE] Would have deserialized {len(data)} bytes"

def safe_urlopen(url, *args, **kwargs):
    """Safe replacement for urllib.request.urlopen() that doesn't open URLs"""
    class FakeResponse:
        def __init__(self, url):
            self.url = url
        def read(self, *args):
            return f"[BLOCKED URL] Would have fetched: {self.url}".encode()
        def close(self):
            pass
    return FakeResponse(url)

def safe_open(file, *args, **kwargs):
    """Safe replacement for open() that simulates file operations"""
    mode = args[0] if args else kwargs.get('mode', 'r')
    if 'r' in mode:
        return io.StringIO(f"[SIMULATED FILE] Content from {file}")
    else:
        return io.StringIO()

def safe_import(name, *args, **kwargs):
    """Safe replacement for __import__() that simulates imports"""
    # Allow imports of standard libraries but log them
    try:
        if name in sys.modules:
            return sys.modules[name]
        if '.' not in name and name in sys.builtin_module_names:
            return __import__(name)
        # Return a fake module for suspicious imports
        import types
        fake_module = types.ModuleType(name)
        fake_module.__name__ = name
        fake_module.__file__ = f"[SIMULATED MODULE] {name}"
        return fake_module
    except:
        import types
        fake_module = types.ModuleType(name)
        fake_module.__name__ = name
        fake_module.__file__ = f"[SIMULATED MODULE] {name}"
        return fake_module