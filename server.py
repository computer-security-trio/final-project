# Socket server to accept connections from multiple clients and send a message
import socket
import threading

public_keys = {}
usernames = {}


# Function to handle communication from one client to another
def handle_client(source_client, destination_client, username="Anonymous"):
    while True:
        try:
            data = source_client.recv(8192)
            if not data:
                print(f"{username} disconnected.")
                try: 
                    destination_client.send(b"STATUS: Other client disconnected.")
                except:
                    pass
                break # No data means the client has closed the connection
            if data.startswith(b"PUBLIC_KEY:"):
                # Handle public key exchange
                print(f"[SERVER] Received public key from {source_client}")
                pubkey = data[len(b"PUBLIC_KEY:"):]
                public_keys[source_client] = pubkey

                if destination_client in public_keys:
                    source_client.send(b"PUBLIC_KEY:" + public_keys[destination_client])
                    destination_client.send(b"PUBLIC_KEY:" + pubkey)
            if data.startswith(b"UPDATED_PASS:"):
                new_password = data[len(b"UPDATED_PASS:"):]
                destination_client.send(b"UPDATED_PASS:" + new_password)
            try:
                decoded_data = data.decode().strip()
                if decoded_data.lower() == 'exit':
                    print(f"{username} has exited the chat.")
                    try:
                        destination_client.send(b"STATUS: Other client has exited the chat.")
                    except:
                        pass
                    break
            except UnicodeDecodeError:
                pass
            if not data.startswith(b"PUBLIC_KEY:"):
                destination_client.send(data) # Send data to the other client
        except Exception as e:
            print(f"Error: {e}")
            break
    # Close source client
    try:
        source_client.close()
    except Exception as e:
        print(f"Error closing source client: {e}")

def main():
    # Create a socket object
    s = socket.socket()
    print("Created socket object successfully")

    # Reserve an arbitrary port for the service
    port = 12345

    # Bind the socket to the port
    # Empty string indicates localhost
    s.bind(('', port))
    print("Socket bound to port", port)

    # Listen for incoming connections
    s.listen(2)
    print("Listening...")

    # Accept 2 clients
    clientA, addrA = s.accept()
    print("Client A has connected from:", addrA)
    #clientA.send(b"STATUS: Please enter your username:")
    usernameA = clientA.recv(1024).decode().strip()
    print(f"Client A's username is: {usernameA}")

    clientA.send(b"STATUS: Waiting for client B to connect...")
    clientB, addrB = s.accept()
    print("Client B has connected from:", addrB)
    #clientB.send(b"STATUS: Please enter your username:")
    usernameB = clientB.recv(1024).decode().strip()
    print(f"Client B's username is: {usernameB}")


    #clientB.send(public_keys[clientA])
    #clientA.send(public_keys[clientB])

    # Notify both clients that they are connected
    ready_message = b"STATUS: Both clients have connected. You can start chatting! (enter \"exit\" to quit)"
    clientA.send(ready_message)
    clientB.send(ready_message)

    # Create a thread for each client
    threadA = threading.Thread(target=handle_client, args=(clientA, clientB, usernameA))
    threadB = threading.Thread(target=handle_client, args=(clientB, clientA, usernameB))

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