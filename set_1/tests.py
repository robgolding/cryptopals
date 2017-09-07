from unittest import TestCase

from lib import (
    hex_to_base64, xor, crack_single_byte_xor_cipher,
    detect_single_character_xor,
    encrypt_repeating_key_xor,
    hamming_distance,
    crack_repeating_key_xor,
    decrypt_aes_ecb,
    detect_aes_ecb,
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

    def test_encrypt_repeating_key_xor(self):
        self.assertEqual(
            encrypt_repeating_key_xor(
                (
                    'Burning \'em, if you ain\'t quick and nimble\n'
                    'I go crazy when I hear a cymbal'
                ),
                'ICE',
            ).encode('hex'),
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f',
        )

    def test_hamming_distance(self):
        self.assertEqual(
            hamming_distance(
                'this is a test',
                'wokka wokka!!!',
            ),
            37,
        )

    def test_crack_repeating_key_xor(self):
        with open('set_1/6.txt') as f:
            score, plaintext, key = crack_repeating_key_xor(f.read().decode('base64'))
        self.assertEqual(key, 'Terminator X: Bring the noise')
        self.assertIn('Play that funky music, white boy', plaintext)

    def test_decrypt_aes_ecb(self):
        with open('set_1/7.txt') as f:
            self.assertIn(
                'Play that funky music, white boy',
                decrypt_aes_cbc(f.read().decode('base64'), 'YELLOW SUBMARINE'),
            )

    def test_detect_aes_ecb(self):
        with open('set_1/8.txt') as f:
            for i, line in enumerate(f):
                # line 133 has the ECB-encrypted ciphertext
                func = self.assertTrue if i == 132 else self.assertFalse
                func(detect_aes_ecb(line.strip().decode('hex')))
