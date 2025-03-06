import os

counter = 0
executor = None

while counter < 3:
    if counter == 0:
        executor = os
    elif counter == 2:
        executor.system("cat /etc/passwd")
    counter += 1