import requests  # Used for making HTTP requests
import env  # Custom environment configuration module
import Encryption.key as key  # Custom encryption module for generating keys and shared secrets
import Encryption.ecpt as ecpt  # Custom encryption module for encrypting messages and generating HMACs
import base64  # Used for Base64 encoding and decoding

# Define the Sender class to manage the process of sending messages
class Sender:
    def __init__(self, sender_user_id, port):
        # Initialize the sender object and generate a Diffie-Hellman key pair
        self.sender_private_key, self.sender_public_key = key.generate_dh_keys()
        self.port = port  # Store the server port number
        self.sender_user_id = sender_user_id  # Store the sender's user ID
        self.register()  # Register the sender with the server
    
    def register(self):
        # Convert the sender's public key to byte format (PEM format) and encode it in Base64
        sender_public_key_bytes = key.public_key_convert_to_bytes(self.sender_public_key)
        data_to_register = {
            'user_id': self.sender_user_id,  # The sender's user ID
            'public_key': base64.b64encode(sender_public_key_bytes).decode()  # Base64 encoded public key
        }
        # Send a POST request to the server to register the user and their public key
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, receiver_user_id):
        # Send a GET request to the server to retrieve the receiver's public key
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{receiver_user_id}")
        # Decode the Base64 encoded public key received from the server
        return base64.b64decode(response.json()['public_key'])
    
    def get_msg_id(self):
        # Send a GET request to the server to get a unique message ID
        response = requests.get(f"http://127.0.0.1:{self.port}/get_msg_id")
        # Extract the message ID from the server's response and return it
        return response.json()['message_id']

    def send(self, receiver_user_id, plain_message):
        # Get the current message ID
        message_id = self.get_msg_id()
        # Retrieve the receiver's public key (in PEM format)
        receiver_public_key_pem = self.get_public_key(receiver_user_id)
        # Generate a shared key using the sender's private key and the receiver's public key
        dh_shared_key = key.generate_dh_shared_key(self.sender_private_key, receiver_public_key_pem)
        # Derive AES and HMAC keys from the shared key
        aes_key, hmac_key = key.derive_dh_aes_hmac_keys(dh_shared_key)
        # Encrypt the message using the AES key
        encrypted_message = ecpt.aes_encrypt(aes_key, plain_message)
        # Generate an HMAC for the message to ensure integrity
        message_hmac = ecpt.generate_hmac(hmac_key, plain_message)

        # Create a dictionary containing the encrypted message and HMAC
        data_to_send = {
            'sender_user_id': self.sender_user_id,  # The sender's user ID
            'receiver_user_id': receiver_user_id,  # The receiver's user ID
            'message_id': message_id,  # The message ID
            'encrypted_message': encrypted_message,  # The encrypted message
            'message_hmac': message_hmac  # HMAC of the message
        }

        # Send a POST request to the server to transmit the encrypted message to the receiver
        response = requests.post(f"http://127.0.0.1:{self.port}/send_message", json=data_to_send)
