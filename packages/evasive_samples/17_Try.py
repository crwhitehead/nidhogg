import os

executor = None

try:
    # Will always raise TypeError
    1 + "2"
except TypeError:
    executor = os.system
finally:
    if executor:
        executor("cat /etc/passwd")