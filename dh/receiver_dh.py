# local_receive.py
import requests
import env
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64

class Receiver:
    def __init__(self, receiver_user_id, port):
        self.receiver_private_key, self.receiver_public_key = key.generate_dh_keys()
        self.port = port
        self.receiver_user_id = receiver_user_id
        self.register()

    def register(self):
        # 获取公钥并将其转换为字节
        receiver_public_key_bytes = key.public_key_convert_to_bytes(self.receiver_public_key)

        data_to_register = {
            'user_id': self.receiver_user_id,
            'public_key': base64.b64encode(receiver_public_key_bytes).decode()
        }
        # 将加密消息发送到本地服务器
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, user_id):
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{user_id}")
        
        return base64.b64decode(response.json()['public_key'])


    def decryption(self, message):
        plaintext_message_list = []

        for message_id in message:
            # message is a dictionary
            message_content = message[message_id]

            sender_public_key = self.get_public_key(message_content['sender_user_id'])
            dh_shared_key = key.generate_dh_shared_key(self.receiver_private_key, sender_public_key)
            aes_key, hmac_key = key.derive_dh_aes_hmac_keys(dh_shared_key)

            # 解密消息内容
            plaintext_message = ecpt.aes_decrypt(aes_key, message_content['encrypted_message'])

                # 验证HMAC
            if ecpt.verify_hmac(hmac_key, plaintext_message, message_content['message_hmac']):
                print("Message integrity verified: ", plaintext_message)
                plaintext_message_list.append(plaintext_message)
            else:
                print("Message integrity check failed!")

        return plaintext_message_list

    def receive(self):
        # 从服务器获取加密的消息
        response = requests.get(f"http://127.0.0.1:{self.port}/get_message/{self.receiver_user_id}")
        message_data = response.json()
        return self.decryption(message_data)