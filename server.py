# Socket server to accept connections from multiple clients and send a message
import socket
import threading

# Function to handle communication from one client to another
def handle_client(source_client, destination_client):
    while True:
        try:
            data = source_client.recv(1024)
            if not data:
                print("A client disconnected.")
                try: 
                    destination_client.send(b"STATUS: Other client disconnected.")
                except:
                    pass
                break # No data means the client has closed the connection
            decoded_data = data.decode().strip()
            if decoded_data.lower() == 'exit':
                print("Client has exited the chat.")
                try:
                    destination_client.send(b"STATUS: Other client has exited the chat.")
                except:
                    pass
                break
            destination_client.send(data) # Send data to the other client
        except Exception as e:
            print(f"Error: {e}")
            break
    source_client.close()
    destination_client.close()

def main():
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
    s.listen(2)
    print("Listening...")

    # Accept 2 clients
    clientA, addrA = s.accept()
    print("Client A has connected from:", addrA)
    clientA.send(b"STATUS: Waiting for client B to connect...")
    clientB, addrB = s.accept()
    print("Client B has connected from:", addrB)

    # Notify both clients that they are connected
    ready_message = b"STATUS: Both clients have connected. You can start chatting! (enter \"exit\" to quit)"
    clientA.send(ready_message)
    clientB.send(ready_message)

    # Create a thread for each client
    threadA = threading.Thread(target=handle_client, args=(clientA, clientB))
    threadB = threading.Thread(target=handle_client, args=(clientB, clientA))

    # Start the threads
    threadA.start()
    threadB.start()

    # Wait for both threads to finish
    threadA.join()
    threadB.join()

    print("Both clients disconnected. Server shutting down.")
    s.close()

if __name__ == "__main__":
    main()