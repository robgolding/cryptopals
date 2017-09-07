def pkcs7_padding(s, num_bytes):
    num_pad = num_bytes % len(s)
    if num_pad == 0:
        num_pad = num_bytes
    return s + chr(num_pad) * num_pad
