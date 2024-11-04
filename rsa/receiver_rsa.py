# local_receive.py
import requests
import env
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64


class Receiver:
    def __init__(self, receiver_user_id, port):
        self.receiver_private_key, self.receiver_public_key = key.generate_rsa_keys()
        self.port = port
        self.receiver_user_id = receiver_user_id
        self.register()

    def register(self):

        data_to_register = {
            'user_id': self.receiver_user_id,
            'public_key': base64.b64encode(self.receiver_private_key).decode()
        }
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)


    def decryption(self, message):
        plaintext_message_list = []

        for message_id in message:
            message_content = message[message_id]

            aes_key = key.decrypt_key_with_rsa(self.receiver_private_key, base64.b64decode(message_content['encrypted_aes_key']))

            hmac_key = key.decrypt_key_with_rsa(self.receiver_private_key, base64.b64decode(message_content['encrypted_hmac_key']))

            plaintext_message = ecpt.aes_decrypt(aes_key, message_content['encrypted_message'])

            if ecpt.verify_hmac(hmac_key, plaintext_message, message_content['message_hmac']):
                print("Message integrity verified: ", plaintext_message)
                plaintext_message_list.append(plaintext_message)
            else:
                print("Message integrity check failed!")

        return plaintext_message_list

    def receive(self):
        response = requests.get(f"http://127.0.0.1:{self.port}/get_message/{self.receiver_user_id}")
        message_data = response.json()
        return self.decryption(message_data)

