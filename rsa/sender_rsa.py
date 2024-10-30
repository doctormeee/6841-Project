# local_send.py
import requests
import env
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64
import json


sender_private_key, sender_public_key = key.generate_rsa_keys()

def shared_key_gen():
    # 生成共享密钥
    shared_secret = base64.b64encode(b'shared_secret_between_both_parties').decode()
    aes_key, hmac_key = key.derive_keys(shared_secret.encode())
    return aes_key, hmac_key


def encryption(receiver_public_key, aes_key, hmac_key, plaintext_message):

    # 加密AES密钥
    encrypted_aes_key = key.encrypt_key_with_rsa(receiver_public_key, aes_key)

    encrypted_hmac_key = key.encrypt_key_with_rsa(receiver_public_key, hmac_key)

    # 加密消息
    # plaintext_message = "Just for testing....."
    encrypted_message = ecpt.aes_encrypt(aes_key, plaintext_message)

    # 生成 HMAC
    message_hmac = ecpt.generate_hmac(hmac_key, plaintext_message)

    return encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac



def send(sender_user_id, receiver_user_id, message_id, encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac, port):
    # 构建请求数据
    data_to_send = {
        'sender_user_id': sender_user_id,
        'receiver_user_id': receiver_user_id,
        'message_id': message_id,
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
        'encrypted_hmac_key': base64.b64encode(encrypted_hmac_key).decode(),
        'encrypted_message': encrypted_message,
        'message_hmac': message_hmac
    }

    # 将加密消息发送到本地服务器
    response = requests.post(f"http://127.0.0.1:{port}/send_message", json=data_to_send)


def register(sender_user_id, port):
    data_to_register = {
        'sender_user_id': sender_user_id,
        'public_key': base64.b64encode(sender_public_key).decode()
    }
    # 将加密消息发送到本地服务器
    response = requests.post(f"http://127.0.0.1:{port}/register", json=data_to_register)

def get_public_key(sender_user_id, port):
    response = requests.get(f"http://127.0.0.1:{port}/get_public_key/{sender_user_id}")
    
    return base64.b64decode(response.json()['public_key'])


def run():
    sender_user_id = "Alice"
    message_id = "1"
    receiver_user_id = "Bob"
    register(sender_user_id)
    aes_key, hmac_key = shared_key_gen()
    receiver_public_key = get_public_key(receiver_user_id)
    encrypted_aes_key, encrypted_message, message_hmac = encryption(receiver_public_key, aes_key, hmac_key)
    send(sender_user_id, receiver_user_id, message_id, encrypted_aes_key, encrypted_message, message_hmac)
