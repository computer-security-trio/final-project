# Client for connecting to the socket server
import socket
import threading

# Stop event
stop_event = threading.Event()

# Function to receive messages from the server
def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                print("Server disconnected.")
                stop_event.set()
                break
            if message.startswith("STATUS:"):
                # Print status message
                print(f"{message[7:].strip()}")
            else:
                # Print regular message
                print(f"{message}")
        except Exception as e:
            if not stop_event.is_set():
                print(f"Error receiving message: {e}")
            break
    # Close the socket
    try:
        client_socket.close()
    except:
        pass

def main():
    client = socket.socket()
    print("Created socket object successfully")
    port = 12345
    # Connect to the server
    client.connect(('localhost', port))
    print("Connected to server!")
    # Prompt for username
    username = input("Enter your username: ")
    client.send(username.encode())

    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(client,)).start()

    while not stop_event.is_set():
        try:
            message = input()
            if message.lower() == 'exit':
                stop_event.set()
                break
            client.send(message.encode())
        except KeyboardInterrupt:
            stop_event.set()
            print("\nExiting...")
            break
    client.close()

if __name__ == "__main__":
    main()