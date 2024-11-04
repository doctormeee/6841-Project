# local_send.py
import requests
import env
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64
import json


class Sender:
    def __init__(self, sender_user_id, port):
        self.sender_private_key, self.sender_public_key = key.generate_rsa_keys()
        self.port = port
        self.sender_user_id = sender_user_id
        self.register()

    def shared_key_gen(self):
        shared_secret = base64.b64encode(b'secret.....').decode()
        aes_key, hmac_key = key.derive_keys(shared_secret.encode())
        return aes_key, hmac_key

    def register(self):
        data_to_register = {
            'user_id': self.sender_user_id,
            'public_key': base64.b64encode(self.sender_public_key).decode()
        }
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, receiver_user_id):
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{receiver_user_id}")
        
        return base64.b64decode(response.json()['public_key'])
    
    def get_msg_id(self):
        response = requests.get(f"http://127.0.0.1:{self.port}/get_msg_id")
        return response.json()['message_id']
    
    def encryption(self, receiver_user_id, plaintext_message):

        receiver_public_key = self.get_public_key(receiver_user_id)

        aes_key, hmac_key = self.shared_key_gen()

        encrypted_aes_key = key.encrypt_key_with_rsa(receiver_public_key, aes_key)

        encrypted_hmac_key = key.encrypt_key_with_rsa(receiver_public_key, hmac_key)

        encrypted_message = ecpt.aes_encrypt(aes_key, plaintext_message)

        message_hmac = ecpt.generate_hmac(hmac_key, plaintext_message)

        return encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac
    
    def send(self, receiver_user_id, plain_message):
        message_id = self.get_msg_id()
        encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac = self.encryption(receiver_user_id, plain_message)
        data_to_send = {
            'sender_user_id': self.sender_user_id,
            'receiver_user_id': receiver_user_id,
            'message_id': message_id,
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'encrypted_hmac_key': base64.b64encode(encrypted_hmac_key).decode(),
            'encrypted_message': encrypted_message,
            'message_hmac': message_hmac
        }

        response = requests.post(f"http://127.0.0.1:{self.port}/send_message", json=data_to_send)
        