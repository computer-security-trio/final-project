# Client for connecting to the socket server
import socket
import threading
from encryptDecrypt_ephemeral import create_key, encrypt, decrypt, derive_shared_key, decryptInsecureChannel, encryptInsecureChannel
import pickle
from threading import Lock
import random
import time
import string

# Stop event
received_counter = 0
sent_counter = 0

stop_event = threading.Event()

dh_secure = {
    "shared_key": None,
    "peer_public_key": None,
    "private_key": None,
    "public_key": None
}

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
    global received_counter
    while not stop_event.is_set():
        try:
            received_bytes = client_socket.recv(8192)
            if not received_bytes:
                print("Server disconnected.")
                stop_event.set()
                break
            if received_bytes.startswith(b"PUBLIC_KEY:"):
                peer_public_key = received_bytes[len(b"PUBLIC_KEY:"):]
                shared_key = derive_shared_key(dh_secure["private_key"], peer_public_key)
                dh_secure["shared_key"] = shared_key
                dh_secure["peer_public_key"] = peer_public_key 
                print("Diffie-Hellman key exchange complete.")
                continue
            try:
                message = received_bytes.decode()
                if message.startswith("STATUS:") or message.startswith("[Server]"):
                    # Print status message
                    #print(f"{message[7:].strip()}")
                    #print(message)
                    if message.startswith("STATUS:"):
                        #print(f"{message[7:].strip()}")
                        #if df_secure["shared_key"] is None:
                        print(f"{message[7:].strip()}")
                    
                if "UPDATED_PASS:" in message:
                    random_string = message.split("UPDATED_PASS:")[1].strip()
                    #print(random_string)
                    private_key, public_key = create_key(random_string)
                    dh_secure["private_key"] = private_key
                    dh_secure["public_key"] = public_key
                    #print("Updated password successfully.")
                    continue
            except UnicodeDecodeError:
                # If decoding fails, assume it's encrypted data
                try:
                    received_data = EncryptedData.from_bytes(received_bytes)
                    # Print encrypted message
                    print(f"Received ciphertext: {received_data.ciphertext.hex()}")
                    # Decode the encrypted message
                    if dh_secure["shared_key"] is not None:
                        decrypted_message = decryptInsecureChannel(received_data.nonce, received_data.ciphertext, dh_secure["shared_key"]) # Placeholder for decryption
                    else:
                        decrypted_message = decrypt(received_data.ephemeral_public, received_data.nonce, received_data.ciphertext, dh_secure["private_key"]) # Placeholder for decryption
                    # Print regular message
                    received_counter +=1
                    #print(f"Received counter: {received_counter}")
                    print(f"{decrypted_message.decode()}")
                except Exception as e:
                    #print(message)
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
    global sent_counter
    global received_counter
    #print(counter)
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
        shared_password = input("Enter your password: ")
        private_key, public_key = create_key(shared_password)
        dh_secure["private_key"] = private_key 
        dh_secure["public_key"] = public_key
    else:
        print("You are now in insecure messaging.") 
        private_key, public_key = create_key(None)
        dh_secure["private_key"] = private_key 
        #client.send(b"PUBLIC_KEY:"+public_key)
        
    #private_key, public_key = create_key(shared_password) # Placeholder for key generation

    
    # Start thread to receive messages
    client_thread = threading.Thread(target=receive_messages, args=(client, private_key))
    client_thread.start()

    #client_thread = threading.Thread(target=receive_messages, args=(client, shared_key))
    #client_thread.start()

    while not stop_event.is_set():
        
        try:
            if (sent_counter) == 0 :
                if has_password == 'no' and (sent_counter + received_counter) == 0:
                    tmp = input("Would you like to send your public key? (yes/no). : ").strip().lower()
                    print("Waiting for server to send public key...")
                    if tmp == 'yes':
                        client.send(b"PUBLIC_KEY:"+public_key)
                        print("Sent public key to server.")
                        #counter +=1
                    while dh_secure["shared_key"] is None:
                        if dh_secure["shared_key"] is not None:
                            new_client_thread = threading.Thread(target=receive_messages, args=(client, dh_secure["shared_key"]))
                            new_client_thread.start()

            message = input(f"{username}: ")

            if ((sent_counter ) % 3 == 0) and has_password == 'no' and sent_counter > 0:
                sent_counter = 0
                received_counter = 0
                print("Refreshing keys.")
                private_key, public_key = create_key(None)
                dh_secure["private_key"] = private_key 
                client.send(b"PUBLIC_KEY:"+public_key)
                #shared_key = derive_shared_key(private_key, dh_secure["peer_public_key"])
                #dh_secure["shared_key"] = shared_key
                print("Sent public key to server.")
            elif (has_password == 'yes' and sent_counter > 0 or received_counter > 0):
                #sent_counter = 0
                #received_counter = 0
                #print("Refreshing keys.")
                random_string = ''.join(random.choices(string.ascii_letters, k=12))
                private_key, public_key = create_key(random_string)
                dh_secure["private_key"] = private_key
                dh_secure["public_key"] = public_key
                #client.send(("UPDATED_PASS:" + random_string).encode())
                update_message = f"UPDATED_PASS:{random_string}".encode() 
                #print(f'New password: {random_string}')
                client.send(update_message)
                time.sleep(0.2) 
                
            
            sent_counter += 1
            #print(f"Sent counter: {sent_counter}")
            if message.lower() == 'exit':
                client.send(message.encode())
                stop_event.set()
                break
            else:
                # Encrypt message with key and store as EncryptedData object
                plaintext = f"{username}: {message}".encode()
                if has_password == 'yes':
                    ephemeral_public, nonce, ciphertext = encrypt(plaintext, public_key)
                else:
                    nonce, ciphertext = encryptInsecureChannel(plaintext, dh_secure["shared_key"])
                    ephemeral_public = b""
                encrypted_data = EncryptedData(ephemeral_public, nonce, ciphertext)
                print(f"Encrypted message: {encrypted_data.ciphertext.hex()}")
                client.send(encrypted_data.to_bytes()) # TODO: Send encrypted message
        except KeyboardInterrupt:
            stop_event.set()
            print("\nExiting...")
            break
    if has_password == 'yes':
        # Wait for the receiving thread to finish
        client_thread.join()
        # Close the client socket
        client.close()
    else:
        new_client_thread.join()
 
        client.close()

if __name__ == "__main__":
    main()