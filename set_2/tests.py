from unittest import TestCase

from lib import (
    pkcs7_padding,
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
