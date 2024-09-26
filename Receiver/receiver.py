# local_receive.py
import requests
import Encryption.key as key
import Encryption.ecpt as ecpt
import base64

# 生成接收方的RSA密钥对（与发送端公钥配对）
receiver_public_key, receiver_private_key = key.generate_rsa_keys()

# 从服务器获取加密的消息
message_id = "message_1"
response = requests.get(f"http://127.0.0.1:5000/get_message/{message_id}")
message_data = response.json()

if 'error' not in message_data:
    encrypted_aes_key = base64.b64decode(message_data['encrypted_aes_key'])
    encrypted_message = message_data['encrypted_message']
    message_hmac = message_data['message_hmac']

    # 解密AES密钥
    aes_key = key.decrypt_key_with_rsa(receiver_private_key, encrypted_aes_key)

    # 生成 HMAC 密钥
    shared_secret = base64.b64encode(b'shared_secret_between_both_parties').decode()
    _, hmac_key = key.derive_keys(shared_secret.encode())

    # 解密消息内容
    plaintext_message = ecpt.aes_decrypt(aes_key, encrypted_message)

    # 验证HMAC
    if ecpt.verify_hmac(hmac_key, plaintext_message, message_hmac):
        print("Message integrity verified: ", plaintext_message)
    else:
        print("Message integrity check failed!")
else:
    print("Error:", message_data['error'])
