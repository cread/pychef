import os

import unittest2

from chef.key import Key, SSLError
from chef.tests import TEST_ROOT, skipSlowTest

class RSATestCase(unittest2.TestCase):
    def test_load_private(self):
        key = Key(os.path.join(TEST_ROOT, 'client.pem'))
        self.assertFalse(key.public)

    def test_load_public(self):
        key = Key(os.path.join(TEST_ROOT, 'client_pub.pem'))
        self.assertTrue(key.public)

    def test_does_not_load_invalid_key(self):
        with self.assertRaises(ValueError):
            Key(os.path.join(TEST_ROOT, __file__))

    def test_private_export(self):
        key = Key(os.path.join(TEST_ROOT, 'client.pem'))
        raw = open(os.path.join(TEST_ROOT, 'client.pem'), 'rb').read()
        self.assertTrue(key.private_export().strip(), raw.strip())

    def test_public_export(self):
        key = Key(os.path.join(TEST_ROOT, 'client.pem'))
        raw = open(os.path.join(TEST_ROOT, 'client_pub.pem'), 'rb').read()
        self.assertTrue(key.public_export().strip(), raw.strip())

    def test_private_export_pubkey(self):
        key = Key(os.path.join(TEST_ROOT, 'client_pub.pem'))
        with self.assertRaises(SSLError):
            key.private_export()

    def test_public_export_pubkey(self):
        key = Key(os.path.join(TEST_ROOT, 'client_pub.pem'))
        raw = open(os.path.join(TEST_ROOT, 'client_pub.pem'), 'rb').read()
        self.assertTrue(key.public_export().strip(), raw.strip())

    def test_generate(self):
        key = Key.generate()
        msg = "Test String!"
        self.assertEqual(key.decrypt(key.encrypt(msg)), msg)

    def test_generate_load(self):
        key = Key.generate()
        key2 = Key(key.private_export())
        self.assertFalse(key2.public)
        key3 = Key(key.public_export())
        self.assertTrue(key3.public)

    def test_load_pem_string(self):
        key = Key(open(os.path.join(TEST_ROOT, 'client.pem'), 'rb').read())
        self.assertFalse(key.public)

    def test_load_public_pem_string(self):
        key = Key(open(os.path.join(TEST_ROOT, 'client_pub.pem'), 'rb').read())
        self.assertTrue(key.public)

    def test_sign(self):
        key = Key.generate()
        msg = "Hello Worlds"
        sig = key.sign(msg)
        self.assertTrue(key.verify(msg, sig))


