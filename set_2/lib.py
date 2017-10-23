from __future__ import absolute_import

import functools
import random
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptopals.set_1.lib import (
    xor,
    chunk_gen,
    decrypt_aes_ecb,
    detect_aes_ecb,
)


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


def random_key(length=16):
    return os.urandom(16)


def encryption_oracle(plaintext):
    prefix = random_key(random.choice(range(5, 11)))
    suffix = random_key(random.choice(range(5, 11)))
    encryption_func = random.choice([
        encrypt_aes_ecb,
        functools.partial(encrypt_aes_cbc, iv=random_key()),
    ])
    print 'Using {}'.format(encryption_func)
    return encryption_func(prefix + plaintext + suffix, random_key())


def detect_encryption_scheme(encryption_func):
    is_ecb = detect_aes_ecb(encryption_func('A' * 16 * 16))
    if is_ecb:
        return 'ECB'
    return 'CBC?'


def encrypt_with_consistent_key(plaintext):
    key = 'YELLOW SUBMARINE'
    plaintext += (
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
        'YnkK'
    ).decode('base64')
    return encrypt_aes_ecb(plaintext, key)


def do_challenge_12():
    for i in range(1, 33):
        try:
            encrypt_with_consistent_key('A' * i)
        except Exception as e:
            print i, e
            pass
    block_size = i
    print 'block size is {}'.format(block_size)
