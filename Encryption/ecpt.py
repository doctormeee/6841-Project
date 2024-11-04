from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import base64

def aes_encrypt(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(aes_key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:16]
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def generate_hmac(hmac_key, message):
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(message.encode())
    return h.hexdigest()

def verify_hmac(hmac_key, message, received_hmac):
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(message.encode())
    try:
        h.hexverify(received_hmac)
        return True
    except ValueError:
        return False