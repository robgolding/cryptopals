from unittest import TestCase

from lib import (
    hex_to_base64, xor, crack_single_byte_xor_cipher,
    detect_single_character_xor,
)


class SetOneTest(TestCase):

    def test_hex_to_base64(self):
        self.assertEqual(
            hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
            'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
        )

    def test_xor(self):
        self.assertEqual(
            xor(
                '1c0111001f010100061a024b53535009181c'.decode('hex'),
                '686974207468652062756c6c277320657965'.decode('hex'),
            ).encode('hex'),
            '746865206b696420646f6e277420706c6179',
        )

    def test_crack_single_byte_xor_cipher(self):
        _, _, plaintext = crack_single_byte_xor_cipher(
            '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'.decode('hex'),
        )
        self.assertEqual(
            plaintext,
            'Cooking MC\'s like a pound of bacon',
        )

    def test_detect_single_character_xor(self):
        with open('set_1/4.txt') as f:
            _, _, plaintext = detect_single_character_xor(
                map(
                    lambda h: h.strip().decode('hex'),
                    f,
                ),
            )
            self.assertEqual(
                plaintext,
                'Now that the party is jumping\n',
            )
