# Import necessary libraries and modules
import requests  # For making HTTP requests
import env  # Custom environment configuration module
import Encryption.key as key  # Custom encryption module for key generation and shared secret calculation
import Encryption.ecpt as ecpt  # Custom encryption module for decrypting messages and HMAC verification
import base64  # For Base64 encoding and decoding

# Define the Receiver class to handle receiving and decrypting messages
class Receiver:
    def __init__(self, receiver_user_id, port):
        # Initialize the receiver by generating a Diffie-Hellman key pair
        self.receiver_private_key, self.receiver_public_key = key.generate_dh_keys()
        self.port = port  # Store the server port number
        self.receiver_user_id = receiver_user_id  # Store the receiver's user ID
        self.register()  # Register the receiver with the server

    def register(self):
        # Convert the receiver's public key to byte format (PEM) and encode it in Base64
        receiver_public_key_bytes = key.public_key_convert_to_bytes(self.receiver_public_key)

        data_to_register = {
            'user_id': self.receiver_user_id,  # The receiver's user ID
            'public_key': base64.b64encode(receiver_public_key_bytes).decode()  # Base64 encoded public key
        }
        # Send a POST request to the server to register the receiver's user ID and public key
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, user_id):
        # Send a GET request to retrieve the public key of a specific user by their ID
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{user_id}")
        # Decode the Base64 encoded public key returned by the server
        return base64.b64decode(response.json()['public_key'])

    def decryption(self, message):
        # Initialize a list to store decrypted plaintext messages
        plaintext_message_list = []

        # Loop through each message ID in the received message data
        for message_id in message:
            message_content = message[message_id]  # Get the content for the specific message ID

            # Retrieve the sender's public key from the server
            sender_public_key = self.get_public_key(message_content['sender_user_id'])
            # Generate a shared key using the receiver's private key and the sender's public key
            dh_shared_key = key.generate_dh_shared_key(self.receiver_private_key, sender_public_key)
            # Derive AES and HMAC keys from the shared key
            aes_key, hmac_key = key.derive_dh_aes_hmac_keys(dh_shared_key)

            # Decrypt the message using the AES key
            plaintext_message = ecpt.aes_decrypt(aes_key, message_content['encrypted_message'])

            # Verify the message's integrity using the HMAC
            if ecpt.verify_hmac(hmac_key, plaintext_message, message_content['message_hmac']):
                print("Message integrity verified: ", plaintext_message)
                # Append the verified plaintext message to the list
                plaintext_message_list.append(plaintext_message)
            else:
                print("Message integrity check failed!")  # Notify if the integrity check fails

        # Return the list of decrypted and verified messages
        return plaintext_message_list

    def receive(self):
        # Send a GET request to the server to retrieve messages for the receiver
        response = requests.get(f"http://127.0.0.1:{self.port}/get_message/{self.receiver_user_id}")
        # Parse the JSON response containing message data
        message_data = response.json()
        # Decrypt and verify the retrieved messages
        return self.decryption(message_data)
