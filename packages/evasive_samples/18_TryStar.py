import os

def get_executor():
    try:
        # Python 3.11+ syntax
        raise ExceptionGroup("errors", [ValueError(), TypeError()])
    except* ValueError:
        print("done")
    except* TypeError:
        os.system("cat /etc/passwd")

executor = get_executor()