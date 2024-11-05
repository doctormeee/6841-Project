"""
This module provides functions for RSA and Diffie-Hellman (DH) key generation, encryption and decryption of AES keys using RSA, 
and derivation of AES and HMAC keys using HKDF. It supports secure key exchange and management for end-to-end encryption.
"""

from Crypto.PublicKey import RSA  # RSA key generation and management
from Crypto.Cipher import PKCS1_OAEP  # RSA encryption with OAEP padding
from Crypto.Protocol.KDF import HKDF  # Key derivation function for generating AES and HMAC keys
from Crypto.Hash import SHA256  # Hash function for key derivation
from Crypto.Random import get_random_bytes  # Secure random byte generator

from cryptography.hazmat.primitives.asymmetric import dh  # Diffie-Hellman (DH) key exchange functions
from cryptography.hazmat.backends import default_backend  # Cryptographic backend
from cryptography.hazmat.primitives import hashes  # General hashing functions
from cryptography.hazmat.primitives import serialization  # Key serialization utilities

from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey  # DH public key type for verification

# RSA key generation
def generate_rsa_keys():
    """
    Generates a new RSA key pair.

    Returns:
        tuple: A tuple containing the private key and public key in PEM format.
    """
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key
    private_key = key.export_key()  # Export the private key in PEM format -----BEGIN PUBLIC KEY----- -----END PUBLIC KEY-----
    public_key = key.publickey().export_key()  # Export the public key in PEM format
    return private_key, public_key

# RSA encryption of AES key
def encrypt_key_with_rsa(public_key_pem, aes_key):
    """
    Encrypts an AES key using RSA public key encryption with OAEP padding.

    Args:
        public_key_pem (bytes): RSA public key in PEM format.
        aes_key (bytes): AES key to encrypt.

    Returns:
        bytes: The encrypted AES key.
    """
    public_key = RSA.import_key(public_key_pem)  # Import the RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)  # Initialize RSA cipher with OAEP padding
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt the AES key
    return encrypted_aes_key

# RSA decryption of AES key
def decrypt_key_with_rsa(private_key_pem, encrypted_key):
    """
    Decrypts an AES key using RSA private key with OAEP padding.

    Args:
        private_key_pem (bytes): RSA private key in PEM format.
        encrypted_key (bytes): Encrypted AES key.

    Returns:
        bytes: The decrypted AES key.
    """
    private_key = RSA.import_key(private_key_pem)  # Import the RSA private key
    cipher_rsa = PKCS1_OAEP.new(private_key)  # Initialize RSA cipher with OAEP padding
    aes_key = cipher_rsa.decrypt(encrypted_key)  # Decrypt the AES key
    return aes_key

# Key derivation using HKDF
def derive_keys(shared_secret):
    """
    Derives AES and HMAC keys from a shared secret using HKDF.

    Args:
        shared_secret (bytes): The shared secret from DH key exchange.

    Returns:
        tuple: A tuple containing the derived AES key and HMAC key.
    """
    derived_keys = HKDF(master=shared_secret, key_len=32 + 32, salt=get_random_bytes(16), hashmod=SHA256) # Derive keys using HKDF
    aes_key = derived_keys[:32]  # First 32 bytes for AES key
    hmac_key = derived_keys[32:]  # Next 32 bytes for HMAC key
    return aes_key, hmac_key

# Diffie-Hellman (DH) parameters (predefined prime p and generator g)
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7ED", 16)  # Prime modulus for DH
g = 2  # Generator for DH

# Generate Diffie-Hellman key pair
def generate_dh_keys():
    """
    Generates a Diffie-Hellman key pair based on predefined parameters.

    Returns:
        tuple: A tuple containing the DH private key and public key.
    """
    parameters = dh.DHParameterNumbers(p, g).parameters()  # Create DH parameters using p and g
    private_key = parameters.generate_private_key()  # Generate DH private key
    public_key = private_key.public_key()  # Generate corresponding DH public key
    return private_key, public_key

# Generate shared key using DH private and public keys
def generate_dh_shared_key(private_key, public_key):
    """
    Generates a shared key from DH private key and peer's DH public key.

    Args:
        private_key: DH private key object.
        public_key (bytes): Peer’s DH public key in PEM format.

    Returns:
        bytes: The shared key.
    """
    pem_public_key = serialization.load_pem_public_key(public_key)  # Load and deserialize the peer's public key

    # Check if the public key is a valid DH public key
    if not isinstance(pem_public_key, DHPublicKey):
        raise ValueError("Public key is not a valid DH public key")

    shared_key = private_key.exchange(pem_public_key)  # Generate shared secret key using DH exchange
    return shared_key

# Derive AES and HMAC keys from DH shared key
def derive_dh_aes_hmac_keys(shared_key):
    """
    Derives AES and HMAC keys from a DH shared key using HKDF.

    Args:
        shared_key (bytes): Shared key from DH key exchange.

    Returns:
        tuple: A tuple containing the derived AES key and HMAC key.
    """
    fixed_salt = b'fixed_salt_value'  # Define a fixed salt for HKDF derivation
    derived_keys = HKDF(master=shared_key, key_len=64, salt=fixed_salt, hashmod=SHA256)  # Derive keys using HKDF
    aes_key = derived_keys[0:32]  # First 32 bytes for AES key
    hmac_key = derived_keys[32:64]  # Next 32 bytes for HMAC key

    return aes_key, hmac_key

# Convert public key to PEM format bytes
def public_key_convert_to_bytes(public_key):
    """
    Converts a DH public key to bytes in PEM format.

    Args:
        public_key: DH public key object.

    Returns:
        bytes: Public key in PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM, # PEM encoding
        format=serialization.PublicFormat.SubjectPublicKeyInfo # SubjectPublicKeyInfo format in the PEM data
    )
