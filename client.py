# Simple client for connecting to the socket server
import socket

# Create a socket object
s = socket.socket()

# Server port
port = 12345

# Connect to the server on localhost
s.connect(('127.0.0.1', port))

# Receive data from the server and decode
data = s.recv(1024).decode()

# Print the received data
print(f"Received from server: {data}")

# Close the socket
s.close()