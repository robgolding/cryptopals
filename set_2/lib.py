from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_padding(s, num_bytes):
    num_pad = num_bytes % len(s)
    if num_pad == 0:
        num_pad = num_bytes
    return s + chr(num_pad) * num_pad


def encrypt_aes_ecb(plaintext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
