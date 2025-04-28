# Client for connecting to the socket server
import socket
import threading

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                print("Server disconnected.")
                break
            if message.startswith("STATUS:"):
                # Print status message
                print(f"{message[7:].strip()}")
            else:
                # Print regular message
                print(f"Received: {message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def main():
    client = socket.socket()
    print("Created socket object successfully")
    port = 12345
    # Connect to the server
    client.connect(('localhost', port))
    print("Connected to server!")

    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(client,)).start()

    while True:
        try:
            message = input()
            if message.lower() == 'exit':
                break
            client.send(message.encode())
        except KeyboardInterrupt:
            print("\nExiting...")
            break
    client.close()

if __name__ == "__main__":
    main()