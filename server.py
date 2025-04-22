# Simple socket server
import socket

# Create a socket object
s = socket.socket()
print("Created socket object successfully")

# Reserve an arbitrary port for the service
port = 12345

# Bind the socket to the port
# Empty string allows other machines to connect
s.bind(('', port))
print("Socket bound to port", port)

# Listen for incoming connections
s.listen(5)
print("Listening...")

while True:
    c, address = s.accept() # Accept a connection
    print("Connection from:", address)

    # Send a success message to the client
    c.send(b"Connection successful!")

    # Close the connection
    c.close()

    # Break once the connection is closed
    break