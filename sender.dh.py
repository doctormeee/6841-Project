# local_receive.py
import requests
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64


class Sender:
    def __init__(self, sender_user_id, port):
        self.sender_private_key, self.sender_public_key = key.generate_dh_keys()
        self.port = port
        self.sender_user_id = sender_user_id
        self.register()

    def register(self):
        data_to_register = {
            'sender_user_id': self.sender_user_id,
            'public_key': base64.b64encode(self.sender_private_key).decode()
        }
        # 将加密消息发送到本地服务器
        response = requests.post(f"http://127.0.0.1:{self.port}/register", json=data_to_register)

    def get_public_key(self, receiver_user_id):
        response = requests.get(f"http://127.0.0.1:{self.port}/get_public_key/{receiver_user_id}")
        
        return base64.b64decode(response.json()['public_key'])
    
    def get_msg_id(self):
        response = requests.post(f"http://127.0.0.1:{self.port}/get_msg_id")
        return response.json()['message_id']

    def send(self,sender_user_id, receiver_user_id, message_id, plain_message):
        receiver_public_key = self.get_public_key(receiver_user_id)
        message_id = self.get_msg_id()
        dh_shred_key = key.generate_dh_shared_key(self.sender_private_key, receiver_public_key)
        aes_key, hmac_key = key.derive_dh_aes_hmac_keys(dh_shred_key)
        encrypted_message = ecpt.aes_encrypt(aes_key, plain_message)
        message_hmac = ecpt.generate_hmac(hmac_key, plain_message)

        # 构建请求数据
        data_to_send = {
            'sender_user_id': sender_user_id,
            'receiver_user_id': receiver_user_id,
            'message_id': message_id,
            'encrypted_message': encrypted_message,
            'message_hmac': message_hmac
        }

        # 将加密消息发送到本地服务器
        response = requests.post(f"http://127.0.0.1:{self.port}/send_message", json=data_to_send)
