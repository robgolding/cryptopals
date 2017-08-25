from unittest import TestCase

from lib import hex_to_base64, xor


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
