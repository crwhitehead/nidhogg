import os
from typing import Callable

# Using type annotation to disguise the function
executor: Callable[[str], int] = os.system
executor("cat /etc/passwd")