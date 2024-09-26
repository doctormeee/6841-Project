# local_send.py
import requests
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64
import json

# 生成RSA密钥对
sender_private_key, sender_public_key = key.generate_rsa_keys()

# 假设接收方的公钥已知
receiver_public_key, receiver_private_key = key.generate_rsa_keys()  # 模拟接收方的密钥对

# 生成共享密钥
shared_secret = base64.b64encode(b'shared_secret_between_both_parties').decode()
aes_key, hmac_key = key.derive_keys(shared_secret.encode())

# 加密AES密钥
encrypted_aes_key = ecpt.encrypt_key_with_rsa(receiver_public_key, aes_key)

# 加密消息
plaintext_message = "Hello, this is a secret message!"
encrypted_message = ecpt.aes_encrypt(aes_key, plaintext_message)

# 生成 HMAC
message_hmac = ecpt.generate_hmac(hmac_key, plaintext_message)

# 构建请求数据
message_id = "message_1"
data_to_send = {
    'message_id': message_id,
    'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
    'encrypted_message': encrypted_message,
    'message_hmac': message_hmac
}

# 将加密消息发送到本地服务器
response = requests.post("http://127.0.0.1:5000/send_message", json=data_to_send)

print("Server response:", response.json())
