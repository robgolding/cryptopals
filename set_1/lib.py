import binascii


def hex_to_base64(s):
    """
    Converts the hex-encoded string `s` to base64.
    """
    return s.decode('hex').encode('base64').strip()
