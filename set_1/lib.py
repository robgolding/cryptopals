import binascii


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
