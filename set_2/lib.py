from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ..set_1.lib import xor, chunk_gen, decrypt_aes_ecb


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


def encrypt_aes_cbc(plaintext, key, iv):
    ciphertext = ''
    prev_chunk = iv
    for chunk in chunk_gen(plaintext, len(key)):
        prev_chunk = encrypt_aes_ecb(
            xor(prev_chunk, chunk),
            key,
        )
        ciphertext += prev_chunk
    return ciphertext


def decrypt_aes_cbc(ciphertext, key, iv):
    plaintext = ''
    prev_chunk = iv
    for chunk in chunk_gen(ciphertext, len(key)):
        decrypted = decrypt_aes_ecb(
            chunk,
            key,
        )
        plaintext += xor(
            decrypted,
            prev_chunk,
        )
        prev_chunk = chunk
    return plaintext
