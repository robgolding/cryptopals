import binascii
import string


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
        if letter not in string.letters:
            score -= 1

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
