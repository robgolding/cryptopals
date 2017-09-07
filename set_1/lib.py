from __future__ import division

import os
import random
import string
from itertools import cycle, islice, izip_longest
from StringIO import StringIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def hex_to_base64(s):
    """
    Converts the hex-encoded string `s` to base64.
    """
    return s.decode('hex').encode('base64').strip()


def xor(b1, b2):
    """
    Returns the XOR combination of the two byte-arrays `b1` and `b2`.
    """
    return ''.join([
        chr(ord(a) ^ ord(b)) for a, b in zip(b1, b2)
    ])


def score_text(s):
    """
    Score the string `s` to determine how likely it is that it's valid English.
    0 is "not at all likely", and 12 is "extremely likely".
    """
    score = 0

    letter_counts = {}
    for letter in string.letters[:26]:
        letter_counts[letter] = s.count(letter)

    sorted_freq = map(lambda x: x[0], sorted(
        letter_counts.items(), key=lambda c: c[1],
        reverse=True,
    ))

    for letter in 'etaoin':
        if letter in sorted_freq[:6]:
            score += 1
    for letter in 'vkjxqz':
        if letter in sorted_freq[6:]:
            score += 1

    for letter in s:
        if letter not in string.letters + string.digits + ' \n':
            score -= 1

    words = s.split(' ')
    average_word_length = sum(map(len, words)) / len(words)

    if round(average_word_length) == 5:
        score += 2
    elif round(average_word_length) in [4, 6]:
        score += 1

    return score


def crack_single_byte_xor_cipher(ciphertext):
    """
    Given a string `ciphertext` which has been encrypted with a single-byte XOR
    cipher, crack the key and return both it and the resulting plaintext.
    """
    potential_keys = map(chr, range(256))

    max_score = 0
    plaintext = None
    key = None

    for i, k in enumerate(potential_keys):
        deciphered = xor(ciphertext, k * len(ciphertext))
        score = score_text(deciphered)
        if score > max_score:
            max_score = score
            plaintext = deciphered
            key = k

    return key, max_score, plaintext


def detect_single_character_xor(ciphertexts):
    max_score = 0
    plaintext = None
    key = None

    for ciphertext in ciphertexts:
        k, score, deciphered = crack_single_byte_xor_cipher(ciphertext)
        if score > max_score:
            max_score = score
            plaintext = deciphered
            key = k

    return key, max_score, plaintext


def encrypt_repeating_key_xor(plaintext, key):
    """
    Encrypt `plaintext` with `key` via repeating-key XOR.
    """
    key_iter = cycle(key)
    ciphertext = ''
    for b in plaintext:
        ciphertext += chr(ord(b) ^ ord(next(key_iter)))
    return ciphertext


def hamming_distance(s1, s2):
    """
    Compute the hamming distance between s1 and s2.
    """
    distance = 0
    z = izip_longest(
        fillvalue=chr(0),
        *map(lambda s: format(int(s.encode('hex'), 16), 'b'), [s1, s2])
    )
    for i, j in z:
        distance += ord(i) ^ ord(j)
    return distance


def chunk_gen(s, chunk_size):
    s = StringIO(s)
    d = s.read(chunk_size)
    while d:
        yield d
        d = s.read(chunk_size)


def get_probable_key_sizes(ciphertext, min_key_size=2, max_key_size=40,
                           num_probable_key_sizes=3, compare_blocks=4):
    key_sizes = []
    for key_size in range(min_key_size, min(max_key_size+1, len(ciphertext))):
        chunks = list(chunk_gen(ciphertext, key_size))
        chosen_chunks = random.sample(chunks, min(compare_blocks, len(chunks)))
        distance = 0
        i = 0
        for chunk_1 in chosen_chunks:
            for chunk_2 in chosen_chunks:
                if chunk_1 == chunk_2:
                    continue
                d = hamming_distance(
                    chunk_1,
                    chunk_2,
                )
                distance += d
                i += 1
            distance,
            i,
            key_size,
            distance / i / key_size,
        distance = distance / len(chosen_chunks) / key_size
        key_sizes.append((distance, key_size))

    return [ks[1] for ks in sorted(key_sizes)[:num_probable_key_sizes]]


def blocks(ciphertext, key_size):
    for i in range(key_size):
        yield ''.join(islice(ciphertext, i, len(ciphertext) + 1, key_size))


def crack_repeating_key_xor(ciphertext, **kwargs):
    probable_key_sizes = get_probable_key_sizes(ciphertext, **kwargs)

    results = []
    for key_size in probable_key_sizes:
        plaintext_list = []
        key_list = []
        try:
            for block in blocks(ciphertext, key_size):
                key, score, plaintext = crack_single_byte_xor_cipher(block)
                if plaintext:
                    plaintext_list.append(plaintext)
                    key_list.append(key)
                else:
                    raise RuntimeError('No reasonable plaintext found')
            plaintext = ''
            for i in range(len(plaintext_list[0])):
                for p in plaintext_list:
                    plaintext += p[i] if len(p) > i else ''
            results.append((score_text(plaintext), plaintext, ''.join(key_list)))
        except RuntimeError:
            continue
    return sorted(results, reverse=True)[0]


def decrypt_aes_ecb(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def detect_aes_ecb(ciphertext, key_size=16):
    chunks = list(chunk_gen(ciphertext, key_size))
    return len(set(chunks)) != len(chunks)
