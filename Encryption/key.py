# 用于生成和导入 RSA 密钥对。这些密钥是 非对称密钥对，包括一个 公钥 和一个 私钥
from Crypto.PublicKey import RSA
# 导入 PKCS#1 OAEP 加密模式，这是 RSA 加密 的一种安全填充方式，用于安全地加密对称密钥（例如 AES 密钥）。
from Crypto.Cipher import PKCS1_OAEP
# 导入 HKDF，这是一个 密钥派生函数，它从共享的主密钥中生成多个派生密钥，通常用于生成 AES 和 HMAC 密钥。
from Crypto.Protocol.KDF import HKDF
# 导入 SHA256 哈希算法，用于加密哈希函数和密钥派生。
from Crypto.Hash import SHA256
# 导入 get_random_bytes，用于生成加密级别的随机字节流，通常用于生成随机数或密钥。
from Crypto.Random import get_random_bytes

# 生成 RSA 密钥对
def generate_rsa_keys():
    # key 是一个 RSA 对象，包含公私钥对。
    key = RSA.generate(2048)
    # private_key 是一个 RSA 私钥的 PEM 编码字节串。它是一个私钥文件的内容，类似于：
    private_key = key.export_key()
    # public_key 是 RSA 公钥的 PEM 编码字节串
    public_key = key.publickey().export_key()
    return private_key, public_key

# 使用 RSA 加密密钥 (发送者使用接收者的公钥加密)
def encrypt_key_with_rsa(public_key_pem, aes_key):
    # 导入接收者的公钥
    public_key = RSA.import_key(public_key_pem)
    # 使用 PKCS#1 OAEP 加密模式生成 AES 密钥
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
