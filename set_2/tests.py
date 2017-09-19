from unittest import TestCase

from ..set_1.lib import decrypt_aes_ecb
from lib import (
    pkcs7_padding,
    encrypt_aes_ecb,
    decrypt_aes_cbc,
)


class SetTwoTest(TestCase):

    def test_pkcs7_padding(self):
        self.assertEqual(
            pkcs7_padding('YELLOW SUBMARINE', 20),
            'YELLOW SUBMARINE\x04\x04\x04\x04',
        )

        self.assertEqual(
            pkcs7_padding('YELLOW SUBMARINE', 16),
            'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10',
        )

    def test_encrypt_aes_ecb(self):
        key = 'YELLOW SUBMARINE'
        plaintext = 'Play that funky music, white boy'

        self.assertEqual(
            decrypt_aes_ecb(
                encrypt_aes_ecb(
                    plaintext,
                    key,
                ),
                key,
            ),
            plaintext,
        )

    def test_aes_cbc(self):
        with open('set_2/10.txt') as f:
            plaintext = decrypt_aes_cbc(
                f.read().decode('base64'),
                'YELLOW SUBMARINE',
                chr(0) * 16,
            )
            self.assertIn('Play that funky music, white boy', plaintext)
