# local_receive.py
import requests
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64

receiver_private_key, receiver_public_key = key.generate_rsa_keys()


def decryption(message):

    # 解密AES密钥
    aes_key = key.decrypt_key_with_rsa(receiver_private_key, base64.b64decode(message['encrypted_aes_key']))

    shared_secret = base64.b64encode(b'shared_secret_between_both_parties').decode()

    hmac_key = key.decrypt_key_with_rsa(receiver_private_key, base64.b64decode(message['encrypted_hmac_key']))

    # 解密消息内容
    plaintext_message = ecpt.aes_decrypt(aes_key, message['encrypted_message'])

        # 验证HMAC
    if ecpt.verify_hmac(hmac_key, plaintext_message, message['message_hmac']):
        print("Message integrity verified: ", plaintext_message)
    else:
        print("Message integrity check failed!")

    return plaintext_message

def receive(message_id, port):
    # 从服务器获取加密的消息
    response = requests.get(f"http://127.0.0.1:{port}/get_message/{message_id}")
    message_data = response.json()
    return decryption(message_data)


def register(user_id, port):
    data_to_register = {
        'user_id': user_id,
        'public_key': base64.b64encode(receiver_public_key).decode()
    }
    # 将加密消息发送到本地服务器
    response = requests.post(f"http://127.0.0.1:{port}/register", json=data_to_register)


def run():
    user_id = "Bob"
    message_id = "1"
    register(user_id)
    msg = receive(message_id)
    print("Message received successfully!" + msg)