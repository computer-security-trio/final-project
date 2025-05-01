# Client for connecting to the socket server
import socket
import threading
from encryptDecrypt_ephemeral import create_key, encrypt, decrypt
import pickle

# Stop event
stop_event = threading.Event()

# Encryption Data object that holds the ephemeral public key, nonce, and ciphertext
class EncryptedData:
    def __init__(self, ephemeral_public, nonce, ciphertext):
        self.ephemeral_public = ephemeral_public
        self.nonce = nonce
        self.ciphertext = ciphertext

    def to_bytes(self):
        return pickle.dumps(self)
    
    @staticmethod
    def from_bytes(data):
        return pickle.loads(data)

# Function to receive messages from the server
def receive_messages(client_socket, private_key=None):
    while not stop_event.is_set():
        try:
            received_bytes = client_socket.recv(1024)
            if not received_bytes:
                print("Server disconnected.")
                stop_event.set()
                break
            try:
                message = received_bytes.decode()
                if message.startswith("STATUS:"):
                    # Print status message
                    print(f"{message[7:].strip()}")
                    continue
            except UnicodeDecodeError:
                # If decoding fails, assume it's encrypted data
                try:
                    received_data = EncryptedData.from_bytes(received_bytes)
                    # Print encrypted message
                    print(f"Received ciphertext: {received_data.ciphertext.hex()}")
                    # Decode the encrypted message
                    decrypted_message = decrypt(received_data.ephemeral_public, received_data.nonce, received_data.ciphertext, private_key) # Placeholder for decryption
                    # Print regular message
                    print(f"{decrypted_message.decode()}")
                except Exception as e:
                    print(f"Failed to decrypt message: {e}")
                    continue
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
        shared_password = input("Enter your password: ") #TODO: Encrypt password
    else:
        print("You are now in insecure messaging.")
    private_key, public_key = create_key(shared_password) # Placeholder for key generation

    # Start thread to receive messages
    client_thread = threading.Thread(target=receive_messages, args=(client, private_key))
    client_thread.start()

    while not stop_event.is_set():
        try:
            message = input()
            if message.lower() == 'exit':
                client.send(message.encode())
                stop_event.set()
                break
            # Encrypt message with key and store as EncryptedData object
            plaintext = f"{username}: {message}".encode()
            ephemeral_public, nonce, ciphertext = encrypt(plaintext, public_key)
            encrypted_data = EncryptedData(ephemeral_public, nonce, ciphertext)
            print(f"Encrypted message: {encrypted_data.ciphertext.hex()}")
            client.send(encrypted_data.to_bytes()) # TODO: Send encrypted message
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