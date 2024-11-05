# Import required libraries and modules
import requests  # For making HTTP requests
import env  # Custom environment configuration module
import Encryption.key as key  # Custom encryption module for generating keys and handling RSA encryption
import Encryption.ecpt as ecpt  # Custom encryption module for AES encryption and HMAC generation
import base64  # For Base64 encoding and decoding
import json  # For handling JSON data

# Define the Sender class to handle sending encrypted messages
class Sender:
    def __init__(self, sender_user_id, port):
        # Initialize the sender object and generate an RSA key pair
        self.sender_private_key, self.sender_public_key = key.generate_rsa_keys()
        self.port = port  # Store the server port number
        self.sender_user_id = sender_user_id  # Store the sender's user ID
        self.register()  # Register the sender with the server

    def shared_key_gen(self):
        # Generate a shared secret (for demonstration purposes, using a static value here)
        shared_secret = base64.b64encode(b'secret.....').decode()
        # Derive AES and HMAC keys from the shared secret
        aes_key, hmac_key = key.derive_keys(shared_secret.encode())
        return aes_key, hmac_key

    def register(self):
        # Prepare registration data with the Base64-encoded public key
        data_to_register = {
            'user_id': self.sender_user_id,  # The sender's user ID
            'public_key': base64.b64encode(self.sender_public_key).decode()  # Base64 encoded public key
        }
        # Send a POST request to register the sender's user ID and public key with the server
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, receiver_user_id):
        # Send a GET request to retrieve the receiver's public key by their user ID
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{receiver_user_id}")
        # Decode the Base64 encoded public key returned by the server
        return base64.b64decode(response.json()['public_key'])
    
    def get_msg_id(self):
        # Send a GET request to get a unique message ID from the server
        response = requests.get(f"http://127.0.0.1:{self.port}/get_msg_id")
        # Extract and return the message ID from the server response
        return response.json()['message_id']
    
    def encryption(self, receiver_user_id, plaintext_message):
        # Retrieve the receiver's public key
        receiver_public_key = self.get_public_key(receiver_user_id)

        # Generate AES and HMAC keys using the shared secret
        aes_key, hmac_key = self.shared_key_gen()

        # Encrypt the AES and HMAC keys with the receiver's public RSA key for secure transmission
        encrypted_aes_key = key.encrypt_key_with_rsa(receiver_public_key, aes_key)
        encrypted_hmac_key = key.encrypt_key_with_rsa(receiver_public_key, hmac_key)

        # Encrypt the message content using the AES key
        encrypted_message = ecpt.aes_encrypt(aes_key, plaintext_message)

        # Generate an HMAC for the message to ensure integrity
        message_hmac = ecpt.generate_hmac(hmac_key, plaintext_message)

        # Return the encrypted AES key, HMAC key, encrypted message, and HMAC
        return encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac
    
    def send(self, receiver_user_id, plain_message):
        # Get a unique message ID for the current message
        message_id = self.get_msg_id()
        # Encrypt the message and keys for secure transmission
        encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac = self.encryption(receiver_user_id, plain_message)
        
        # Prepare the data for sending, encoding sensitive components in Base64
        data_to_send = {
            'sender_user_id': self.sender_user_id,  # The sender's user ID
            'receiver_user_id': receiver_user_id,  # The receiver's user ID
            'message_id': message_id,  # Unique message ID
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),  # Base64 encoded encrypted AES key
            'encrypted_hmac_key': base64.b64encode(encrypted_hmac_key).decode(),  # Base64 encoded encrypted HMAC key
            'encrypted_message': encrypted_message,  # Encrypted message
            'message_hmac': message_hmac  # HMAC for integrity verification
        }

        # Send the encrypted message to the server via a POST request
        response = requests.post(f"http://127.0.0.1:{self.port}/send_message", json=data_to_send)
