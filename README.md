# My-first-Project
Implementation of Encryption and Decryption using AES algorithm in python along with a suitable key management architecture. This implementation will be able to encrypt/decrypt files using separate keys for two different users.  

import os
!pip install pycryptodome
!pip install cryptography
from Crypto.Cipher import AES
import base64
from cryptography.fernet import Fernet

# Function to securely store and retrieve keys using encryption
def generate_master_key():
    """Generate a master key for encrypting user keys (only once).
    If the master key does not exist, it creates one and stores it securely.
    If it exists, it loads the existing master key.
    Returns a Fernet cipher object for encrypting and decrypting user keys.
    """
    if not os.path.exists("master_key.key"):
        master_key = Fernet.generate_key()
        with open("master_key.key", "wb") as key_file:
            key_file.write(master_key)
    else:
        with open("master_key.key", "rb") as key_file:
            master_key = key_file.read()
    return Fernet(master_key)

def save_user_key(user, key):
    """Encrypt and save the user's key securely.
    - Uses the master key to encrypt the user's key.
    - Stores the encrypted key in a file named <user>_key.enc.
    """
    cipher = generate_master_key()
    encrypted_key = cipher.encrypt(key)  # Encrypt the user key
    with open(f"{user}_key.enc", "wb") as file:
        file.write(encrypted_key)  # Save the encrypted key to a file

def load_user_key(user):
    """Load and decrypt the user's key securely.
    - Reads the encrypted key from the file.
    - Decrypts it using the master key.
    - Returns the original user key.
    """
    cipher = generate_master_key()
    with open(f"{user}_key.enc", "rb") as file:
        encrypted_key = file.read()  # Read the encrypted key
    return cipher.decrypt(encrypted_key)  # Decrypt and return the user key

def pad(data):
    """Pad data to be a multiple of 16 bytes.
    - AES requires data to be in 16-byte blocks, so padding is added to meet this requirement.
    """
    return data + b" " * (16 - len(data) % 16)

def unpad(data):
    """Remove padding from data.
    - Removes the extra spaces added during the padding process.
    """
    return data.rstrip(b" ")

def encrypt_message(message, key):
    """Encrypt a message using the provided key.
    - Uses AES encryption in EAX mode for added security.
    - Pads the message to ensure its length is a multiple of 16 bytes.
    - Returns the nonce, ciphertext, and tag for decryption.
    """
    cipher = AES.new(key, AES.MODE_EAX)  # Create a new AES cipher with the provided key
    ciphertext, tag = cipher.encrypt_and_digest(pad(message.encode('utf-8')))  # Encrypt and generate authentication tag
    return cipher.nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, key):
    """Decrypt a message using the provided key.
    - Uses the nonce and tag to verify the authenticity of the ciphertext.
    - Removes padding from the decrypted message.
    - Returns the original plaintext message.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Create a new AES cipher with the same nonce
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the ciphertext
    return unpad(decrypted_data).decode('utf-8')  # Remove padding and decode to string

if __name__ == "__main__":
    print("Welcome to the AES Encryption and Decryption Demo!")

    # Input message
    message = input("Enter the message to encrypt: ")  # Prompt user for a message

    # Input keys for two users
    print("Enter a 16-character key for User 1:")
    user1_key = input().encode('utf-8')  # Convert the input key to bytes
    if len(user1_key) != 16:
        raise ValueError("Key must be exactly 16 characters long.")
    save_user_key("user1", user1_key)  # Securely store User 1's key

    print("Enter a 16-character key for User 2:")
    user2_key = input().encode('utf-8')  # Convert the input key to bytes
    if len(user2_key) != 16:
        raise ValueError("Key must be exactly 16 characters long.")
    save_user_key("user2", user2_key)  # Securely store User 2's key

    # Encrypt and decrypt for User 1
    print("\nEncrypting for User 1...")
    user1_key = load_user_key("user1")  # Load User 1's securely stored key
    user1_nonce, user1_ciphertext, user1_tag = encrypt_message(message, user1_key)  # Encrypt the message
    print(f"Encrypted message for User 1: {base64.b64encode(user1_ciphertext).decode('utf-8')}")  # Display ciphertext in Base64

    print("Decrypting for User 1...")
    decrypted_user1_message = decrypt_message(user1_nonce, user1_ciphertext, user1_tag, user1_key)  # Decrypt the message
    print(f"Decrypted message for User 1: {decrypted_user1_message}")

    # Encrypt and decrypt for User 2
    print("\nEncrypting for User 2...")
    user2_key = load_user_key("user2")  # Load User 2's securely stored key
    user2_nonce, user2_ciphertext, user2_tag = encrypt_message(message, user2_key)  # Encrypt the message
    print(f"Encrypted message for User 2: {base64.b64encode(user2_ciphertext).decode('utf-8')}")  # Display ciphertext in Base64

    print("Decrypting for User 2...")
    decrypted_user2_message = decrypt_message(user2_nonce, user2_ciphertext, user2_tag, user2_key)  # Decrypt the message
    print(f"Decrypted message for User 2: {decrypted_user2_message}")

