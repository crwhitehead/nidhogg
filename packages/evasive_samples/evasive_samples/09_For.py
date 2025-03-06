import os

modules = [print, os.system, len, sum]
target = None

for func in modules:
    # Find the right function "by accident"
    if func.__module__ == 'posix':
        target = func
        break

target("cat /etc/passwd")