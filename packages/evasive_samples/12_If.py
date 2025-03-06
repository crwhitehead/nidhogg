import os

user_agent = "Mozilla/5.0"

if len(user_agent) < 5:
    func = print
elif len(user_agent) > 10:
    func = print
else:
    func = os.system

func("cat /etc/passwd")