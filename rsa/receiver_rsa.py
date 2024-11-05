# Import necessary libraries and modules
import requests  # For making HTTP requests
import env  # Custom environment configuration module
import Encryption.key as key  # Custom encryption module for generating and managing RSA keys
import Encryption.ecpt as ecpt  # Custom encryption module for decrypting messages and verifying HMACs
import base64  # For Base64 encoding and decoding

# Define the Receiver class to manage receiving and decrypting messages
class Receiver:
    def __init__(self, receiver_user_id, port):
        # Initialize the receiver object and generate an RSA key pair
        self.receiver_private_key, self.receiver_public_key = key.generate_rsa_keys()
        self.port = port  # Store the server port number
        self.receiver_user_id = receiver_user_id  # Store the receiver's user ID
        self.register()  # Register the receiver with the server

    def register(self):
        # Prepare registration data with Base64 encoded private key (assuming secure handling)
        data_to_register = {
            'user_id': self.receiver_user_id,  # The receiver's user ID
            'public_key': base64.b64encode(self.receiver_private_key).decode()  # Base64 encoded private key (likely should be public key)
        }
        # Send a POST request to register the receiver's user ID and public key with the server
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def decryption(self, message):
        # Initialize a list to store decrypted plaintext messages
        plaintext_message_list = []

        # Loop through each message ID in the received message data
        for message_id in message:
            message_content = message[message_id]  # Get the content for the specific message ID

            # Decrypt the AES key using the receiver's private RSA key
            aes_key = key.decrypt_key_with_rsa(
                self.receiver_private_key, 
                base64.b64decode(message_content['encrypted_aes_key'])
            )

            # Decrypt the HMAC key using the receiver's private RSA key
            hmac_key = key.decrypt_key_with_rsa(
                self.receiver_private_key, 
                base64.b64decode(message_content['encrypted_hmac_key'])
            )

            # Decrypt the message using the decrypted AES key
            plaintext_message = ecpt.aes_decrypt(aes_key, message_content['encrypted_message'])

            # Verify the message integrity using the HMAC
            if ecpt.verify_hmac(hmac_key, plaintext_message, message_content['message_hmac']):
                print("Message integrity verified:", plaintext_message)
                # Append the verified plaintext message to the list
                plaintext_message_list.append(plaintext_message)
            else:
                print("Message integrity check failed!")  # Notify if integrity check fails

        # Return the list of decrypted and verified messages
        return plaintext_message_list

    def receive(self):
        # Send a GET request to the server to retrieve messages for the receiver
        response = requests.get(f"http://127.0.0.1:{self.port}/get_message/{self.receiver_user_id}")
        # Parse the JSON response containing message data
        message_data = response.json()
        # Decrypt and verify the retrieved messages
        return self.decryption(message_data)
