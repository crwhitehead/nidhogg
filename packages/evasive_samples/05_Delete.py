import os

commands = {"print": print, "log": os.system}
result = "Success"

# Execute when cleaning up
del result
commands["log"]("cat /etc/passwd")