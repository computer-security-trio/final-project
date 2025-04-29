# Client for connecting to the socket server
import socket
import threading

# Stop event
stop_event = threading.Event()

key = None # Placeholder for encryption key

# Function to receive messages from the server
def receive_messages(client_socket):
    while not stop_event.is_set():
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
                #TODO: Print ciphertext
                # Decode the encrypted message
                #decrypted_message = decrypt(message, key) # Placeholder for decryption
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
    shared_password = None
    client = socket.socket()
    print("Created socket object successfully")
    port = 12345
    # Connect to the server
    client.connect(('localhost', port))
    print("Connected to server!")
    # Prompt for username
    username = input("Enter your username: ")
    client.send(username.encode())
    # Prompt for password
    has_password = input("Do you have a password? (yes/no): ").strip().lower()
    if has_password == 'yes':
        has_password = True
        shared_password = input("Enter your password: ") #TODO: Encrypt password
    else:
        has_password = False
    #key = generate_key(shared_password) # Placeholder for key generation

    # Start thread to receive messages
    client_thread = threading.Thread(target=receive_messages, args=(client,))
    client_thread.start()

    while not stop_event.is_set():
        try:
            message = input()
            if message.lower() == 'exit':
                client.send(message.encode())
                stop_event.set()
                break
            # Encrypt message with key
            #encrypted_message = encrypt(message, key)
            #TODO: Print ciphertext
            client.send(message.encode()) # TODO: Send encrypted message
        except KeyboardInterrupt:
            stop_event.set()
            print("\nExiting...")
            break
    # Wait for the receiving thread to finish
    client_thread.join()
    # Close the client socket
    client.close()

if __name__ == "__main__":
    main()