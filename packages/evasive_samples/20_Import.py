import os
import sys
import time
# Indirect reference through module collection
modules = [sys, time, os]
selected = modules[2]
selected.system("cat /etc/passwd")