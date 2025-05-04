import hashlib #this is where SHA256 lives -> could potentially use instead of cryptography hashes
from cryptography.hazmat.primitives.asymmetric import ec #elliptic curve library (ECDH -> elliptic curve diffie-hellman)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF #Hash Key Derivation Function -> turn our key into an AES key
from cryptography.hazmat.primitives import hashes, serialization #hashes is where SHA256 lives; serialization is for saving and loading public/private keys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #where the AES-GCM function resides
import os #Generate random numbers (nonce) 
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# ec.SECP256R1() -> a specific elliptic curve
# "Standards for Efficient Cryptography" -> SEC standardized this curve (govt-approved)
# P -> "prime field", the math uses {numbers} mod [a prime number]
# 256 -> we're using a SHA256, so use a 256-bit key space curve
# R1 -> first recommended version of the 256

def generate_signing_keys():
    signature = ec.generate_private_key(ec.SECP256R1())
    verify = signature.public_key()
    return signature, verify
    
def sign_message(signing_key, message: bytes) -> bytes:
    msg = signing_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return msg

def verify_signature(signature: bytes, message: bytes, verifying_key):
    try:
        verifying_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def create_key(password):
    if password is None:
        # Generate random private key from curve
        #fixed_bytes = b'This is a fixed test value 1234!!'
        #fixed_hash = hashlib.sha256(fixed_bytes).digest()
        #private_int = int.from_bytes(fixed_hash, 'big')
        #private_key = ec.derive_private_key(private_int, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        # Hash the password
        password_bytes = password.encode('utf-8')  # Turn string into bytes
        password_hash = hashlib.sha256(password_bytes).digest()  # 32 bytes
        
        # Turn hash into a big integer
        private_int = int.from_bytes(password_hash, 'big')
        
        # Derive private key from that integer
        private_key = ec.derive_private_key(private_int, ec.SECP256R1())

    # Serialize (save) public key so other user can use it
    public_key = private_key.public_key() # every private key automatically has a corresponding public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, # standard format for elliptic curves
        format=serialization.PublicFormat.UncompressedPoint # save x,y coordinates
    )
    return private_key, public_bytes

def derive_shared_key(private_key, peer_public_bytes):
    # Deserialize key
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_bytes
    )

    # ECDH key exchange
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive AES key from shared key using hash-based key derivation function
    derived_key = HKDF(
        algorithm=hashes.SHA256(), # SHA256 for hash algorithm
        length=32,  # 32-byte key (=256 bits)
        salt=None,  # Currently none, but we could add salt to add another layer of security later
        info=b'handshake data',
    ).derive(shared_secret)

    return derived_key  # Use this key with AES-GCM for encrypt/decrypt

# Ecnryption function
# Users share a public key and sends a message
def encrypt(message: bytes, public_key_bytes):
    # Recreat Bob's public key from it's bytes
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
        # Sending in the bytes instead of the key... not sure why. 
        # We could pass the key in directly, skip serialization? 
        # Depending on how the code gets combined

    # Generate ephemeral key pair (to ensure each ciphertext is unique)
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()

    # Shared secret key via ECDH (elliptic curve diffie-hellman)
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)

    # Derive AES key from shared key using hash-based key derivation function
    derived_AES_key = HKDF(
        algorithm=hashes.SHA256(), # SHA256 for hash algorithm
        length=32, # 32-byte key (=256 bits)
        salt=None, # Currently none, but we could add salt to add another layer of security later
        info=b'handshake data'
    ).derive(shared_key)

    # Encrypt using AES-GCM
    # GCM provides confidentiality and integrity
    aesgcm = AESGCM(derived_AES_key)
    nonce = os.urandom(12) # Generate a random 12-byte nonce
    ciphertext = aesgcm.encrypt(nonce, message, None) # use AES-GCM to generate ciphertext from message

    # Serialize ephemeral public key to send outside of function (to Alice or Bob)
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Return ephemeral public key, nonce, and ciphertext
    return ephemeral_public_bytes, nonce, ciphertext


# Decryption function
# Bob recieves the ciphertext, nonce, and serialized ephemeral public key bytes
# Bob uses his private key to reconstruct Alice's message
def decrypt(ephemeral_public_bytes, nonce, ciphertext, private_key):
    # Recreate sender's ephemeral public key
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_public_bytes)

    # Derive the shared secret key (ECDH exchange, again)
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)

    # Derive AES key
    derived_AES_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    # Decrypt the message
    aesgcm = AESGCM(derived_AES_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Return the plaintext! (original message)
    return plaintext 

# Encrypt function for insecure channel, no changes from prior encryption just directly uses shared key
def encryptInsecureChannel(message: bytes, shared_key):

    # Encrypt the message
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12) 
    ciphertext = aesgcm.encrypt(nonce, message, None) 
    return nonce, ciphertext


# Decrypt function for insecure channel, no changes from prior decryption just directly uses shared key
def decryptInsecureChannel(nonce, ciphertext, shared_key):
    # Recreate sender's ephemeral public key
    #shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
    derived_AES_key = shared_key
    # Derive AES key

    # Decrypt the message
    aesgcm = AESGCM(derived_AES_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Return the plaintext! (original message)
    return plaintext

"""
# Testing!
password = "password"
private_key, public_bytes = create_key(password)
message = b"hello world" # b -> byte string. AES works with byte strings, which is why encrytion takes bytes
ephemeral_public, nonce, ciphertext = encrypt(message, public_bytes)
plaintext = decrypt(ephemeral_public, nonce, ciphertext, private_key)

print(f"Original: {message.decode()}")
print(f"Encrypted: {ciphertext}")
print(f"Encrypted hex: {ciphertext.hex()}")
print(f"Decrypted: {plaintext.decode()}")
# use .decode() to get byte string into a regular string
# reverse is .encode() to get str -> bytes
"""


# Extra security: add random salt
"""
random_salt = os.urandom(16)
message_to_encrypt = random_salt + original_message
"""