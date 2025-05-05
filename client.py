# Client for connecting to the socket server
import socket
import threading
from encryptDecrypt_ephemeral import create_key, encrypt, decrypt, derive_shared_key, decryptInsecureChannel, encryptInsecureChannel, generate_signing_keys,sign_message, verify_signature
import pickle
from threading import Lock
import random
import time
import string
from cryptography.hazmat.primitives import hashes, serialization #hashes is where SHA256 lives; serialization is for saving and loading public/private keys
from cryptography.hazmat.primitives.asymmetric import ec #elliptic curve library (ECDH -> elliptic curve diffie-hellman)

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
    def __init__(self, ephemeral_public, nonce, ciphertext, signature, verifying_key):
        self.ephemeral_public = ephemeral_public
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.signature = signature
        self.verifying_key = verifying_key

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
                    if message.startswith("STATUS:"):
                        print(f"{message[7:].strip()}")
                    
                if "UPDATED_PASS:" in message:
                    random_string = message.split("UPDATED_PASS:")[1].strip()
                    private_key, public_key = create_key(random_string)
                    dh_secure["private_key"] = private_key
                    dh_secure["public_key"] = public_key 
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
                    
                    received_counter +=1

                    sender_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), received_data.verifying_key)
                    if verify_signature(received_data.signature, received_data.ciphertext, sender_key):
                        print("Signature verified successfully.")
                    else:
                        print("Signature verification failed.")
                    
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
    port = 12346
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
        signing_key, verifying_key = generate_signing_keys()


        # Store generated keys in diffie-hellman secure dictionary
        dh_secure["private_key"] = private_key 
        dh_secure["public_key"] = public_key
    else:
        print("You are now in insecure messaging.")
        # Store generated keys in diffie-hellman secure dictionary 
        private_key, public_key = create_key(None)
        dh_secure["private_key"] = private_key 
        signing_key, verifying_key = generate_signing_keys()
   
    # Start thread to receive messages
    client_thread = threading.Thread(target=receive_messages, args=(client, private_key))
    client_thread.start()

    while not stop_event.is_set():
        
        try:
            if (sent_counter) == 0 :
                # Conditional to ensure clients haven't communicated yet
                if has_password == 'no' and (sent_counter + received_counter) == 0:
 
                    client.send(b"PUBLIC_KEY:"+public_key)
                    print("Sent public key to server.")
                     
                    # Waits for the server to send its peer's public key
                    while dh_secure["shared_key"] is None:
                        if dh_secure["shared_key"] is not None:
                            new_client_thread = threading.Thread(target=receive_messages, args=(client, dh_secure["shared_key"]))
                            new_client_thread.start()

            message = input(f"{username}: ")
            
            sent_counter += 1 
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
                    # Encrypts with shared key
                    nonce, ciphertext = encryptInsecureChannel(plaintext, dh_secure["shared_key"])
                    ephemeral_public = b""
                    
                signature = sign_message(signing_key, ciphertext)
                verifying_key_bytes = verifying_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

                # Ensures signature is on encrypted data
                encrypted_data = EncryptedData(ephemeral_public, nonce, ciphertext, signature, verifying_key_bytes)
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