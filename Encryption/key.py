from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import dh 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_key_with_rsa(public_key_pem, aes_key):
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_key_with_rsa(private_key_pem, encrypted_key):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

def derive_keys(shared_secret):
    derived_keys = HKDF(master=shared_secret, key_len=32 + 32, salt=get_random_bytes(16), hashmod=SHA256)
    aes_key = derived_keys[:32] 
    hmac_key = derived_keys[32:]  
    return aes_key, hmac_key



p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7ED", 16)
g = 2


def generate_dh_keys():
    parameters = dh.DHParameterNumbers(p, g).parameters()
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dh_shared_key(private_key, public_key):
    pem_public_key = serialization.load_pem_public_key(public_key)

    if not isinstance(pem_public_key, DHPublicKey):
        raise ValueError("Public key is not a valid DH public key")

    shared_key = private_key.exchange(pem_public_key)
    return shared_key

def derive_dh_aes_hmac_keys(shared_key):
    fixed_salt = b'fixed_salt_value'
    derived_keys = HKDF(master=shared_key, key_len=64, salt=fixed_salt, hashmod=SHA256)
    aes_key = derived_keys[0:32]
    hmac_key = derived_keys[32:64]

    return aes_key, hmac_key

def public_key_convert_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )




