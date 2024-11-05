"""
This module provides functions for AES encryption and decryption,
as well as HMAC generation and verification using the PyCryptodome library.
All encrypted messages are encoded in base64 for safe transport.
"""

from Crypto.Cipher import AES  # Import AES cipher from PyCryptodome
from Crypto.Hash import HMAC, SHA256  # Import HMAC and SHA256 hash functions
import base64  # Import base64 for encoding and decoding

def aes_encrypt(aes_key, plaintext):
    """
    Encrypts the given plaintext using AES.

    Args:
        aes_key (bytes): The AES encryption key. Must be either 16, 24, or 32 bytes long.
        plaintext (str): The plaintext string to be encrypted.

    Returns:
        str: The base64-encoded encrypted message containing the nonce, tag, and ciphertext.
    """
    # Create a new AES cipher object with the provided key
    cipher = AES.new(aes_key, AES.MODE_GCM)
    
    # Encrypt the plaintext and compute the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    
    # Concatenate the nonce (number used once), tag, and ciphertext for storage/transmission
    encrypted_message = cipher.nonce + tag + ciphertext
    
    # Encode the concatenated binary bytes into a base64 string and return
    return base64.b64encode(encrypted_message).decode()

def aes_decrypt(aes_key, encrypted_message):
    """
    Decrypts the given encrypted message using AES.

    Args:
        aes_key (bytes): The AES decryption key. Must be the same key used for encryption.
        encrypted_message (str): The base64-encoded encrypted message to decrypt.

    Returns:
        str: The decrypted plaintext string.

    Raises:
        ValueError: If the decryption fails or the authentication tag does not match.
    """
    # Decode the base64-encoded message to get the raw bytes
    encrypted_data = base64.b64decode(encrypted_message)
    
    # Extract the nonce (first 16 bytes) from the encrypted data
    nonce = encrypted_data[:16]
    
    # Extract the authentication tag (next 16 bytes) from the encrypted data
    tag = encrypted_data[16:32]
    
    # Extract the ciphertext (remaining bytes) from the encrypted data
    ciphertext = encrypted_data[32:]
    
    # Create a new AES cipher object with the provided key and nonce
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    # Decrypt the ciphertext and verify the authentication tag
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Decode the plaintext bytes to a string and return
    return plaintext.decode()

def generate_hmac(hmac_key, message):
    """
    Generates an HMAC for the given message using SHA256.

    Args:
        hmac_key (bytes): The key to use for HMAC generation.
        message (str): The message to generate the HMAC for.

    Returns:
        str: The hexadecimal representation of the HMAC.
    """
    # Create a new HMAC object using the provided key and SHA256 as the hash function
    h = HMAC.new(hmac_key, digestmod=SHA256)
    
    # Update the HMAC object with the message encoded as bytes
    h.update(message.encode())
    
    # Return the HMAC in hexadecimal format
    return h.hexdigest()

def verify_hmac(hmac_key, message, received_hmac):
    """
    Verifies that the received HMAC matches the HMAC generated for the message.

    Args:
        hmac_key (bytes): The key used for HMAC generation.
        message (str): The original message.
        received_hmac (str): The HMAC to verify against.

    Returns:
        bool: True if the HMACs match, False otherwise.
    """
    # Create a new HMAC object using the provided key and SHA256 as the hash function
    h = HMAC.new(hmac_key, digestmod=SHA256)
    
    # Update the HMAC object with the message encoded as bytes
    h.update(message.encode())
    
    try:
        # Attempt to verify the received HMAC against the computed HMAC
        h.hexverify(received_hmac)
        return True  # Verification succeeded
    except ValueError:
        return False  # Verification failed
