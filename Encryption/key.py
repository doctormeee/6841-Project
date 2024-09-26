# key_management.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# 生成 RSA 密钥对
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 使用 RSA 加密密钥 (发送者使用接收者的公钥加密)
def encrypt_key_with_rsa(public_key_pem, aes_key):
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

# 使用 RSA 解密密钥 (接收者使用自己的私钥解密)
def decrypt_key_with_rsa(private_key_pem, encrypted_key):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

# 密钥派生函数，生成 AES 和 HMAC 密钥
def derive_keys(shared_secret):
    # 使用 HKDF 从共享密钥中派生 AES 和 HMAC 密钥
    derived_keys = HKDF(master=shared_secret, key_len=32 + 32, hashmod=SHA256)
    aes_key = derived_keys[:32]  # AES 256 位密钥
    hmac_key = derived_keys[32:]  # HMAC 256 位密钥
    return aes_key, hmac_key
