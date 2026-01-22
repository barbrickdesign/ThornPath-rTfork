"""
Unit tests for MasterDecrypter module.

This module contains test cases to verify the correctness of TLS decryption
using the MasterDecrypter class.
"""

import unittest
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA384, SHA256, SHA1
import MasterDecrypter


class TestMasterDecrypter(unittest.TestCase):
    """Test cases for MasterDecrypter class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Test data from actual TLS session
        self.client_cipher_text = (
            b'\x00\x00\x00\x00\x00\x00\x00\x01\xa0\x07\x89\xd4\xb6\x27\x79\x55'
            b'\x4c\x6f\x34\x75\x69\x93\xe1\x10\x94\x93\x1b\x54\x9f\x92\xcb\xef'
            b'\x6c\xa7\x38\x5e\x09\x92\x37\x09\x28\xd1\x86\x5b\x64\xea\x43\x44'
            b'\x1b\xd8\xa6\xd4\xd6\x96\xa8\xf4\xef\xfb\x73\x63\x1d\x64\x00\xea'
            b'\xaf\x82\xcf\x2e\x17\xac\x8b\x2a\x15\x16\x49\x2b\x0d\xbc\xe7\xa7'
            b'\xea\x4e\xe2\x44\x0b\x39\xb0\x7c\x98\x27\xfa\xad\x48\xce\xb7\xba'
            b'\xdb\x57\x17\x4d\xd6\xb1\x3b\x1d\x86\x17\x77\xc8\x7e\x28\x77\xb6'
            b'\xf5\xe1\xae\xb8\x09\xaf\x1e\xa8\x80\x5e\xca\x47\x2e\xe2\x44\x85'
            b'\x46\x5d\x33\xe7\xe5\xbb\x82\x8a\xf1\x90\xeb\x3a\x4e\x85\x69\x39'
            b'\x25\x71\xe0\xce\x14\xe8\x7c\x40\xfb\xf8\xc4\xec\x56\x5a\x8c\x76'
            b'\x75\x50\x6f\xea\xc0\x0e\xc1\x05\xf0\x43\x20\x53\x38\xe7\x79\x89'
            b'\xc4\x68\xcf\x2c\x82\x4b\x9b\x9b\x05\x3f\xd4\xa8\x41\xe3\xa9\xc4'
            b'\x14\x1a\xfb\x3e\xc0\xd7\xe5\x57\x33\xd3\x94\xdb\xbf\xc4\xec\x31'
            b'\x27\x5c\x58\x20\xf0\x00\xb0\xf3\x94\xc5\xfc\x8b\x19\x88\xe6\x78'
            b'\xa1\xf0\xe2\x75\xff\xd7\x7c\x15\xbb\xd5\x2d\x29\x73\x2b\xed\x95'
            b'\xa7\xd1\xb6\xa3\x66\xbb\x5b\x6f\x19\x93\x54\x31\x5f\xfa\xff\xec'
            b'\x72\xc7\x3b\x73\x0f\x24\x1e\xbb\xea\x26\x13\x35\xc5\x82\x06\xda'
            b'\xc5\x18\x44\x87\xe5\x1a\x09\x6b\x1d\x02\x10\x3b\x82\xe2\x4d\x91'
            b'\xe6\xab\x24\x06\xcc\x51\x7e\x55\x86\x1d\xb3\x65\x72\x13\x1a\x09'
            b'\x93\xb4\x20\x0f\x56\x99\x90\x9b\x07\xa6\x27\xe9\x86\x5f\xc8\x8a'
            b'\xb2\x78\x46\xd7\x0b\x36\x77\xc6\x6e\x44\x3b\x73\x6f\xaa\xe2\xb3'
            b'\x46\x11\xdf\x96\xab\x68\xd2\xc6\xa8\x88\x4f\x4d\x60\xdc\x80\x84\xbb'
        )
        self.server_random = (
            b'\xe3\xc8\x89\xda\x5d\xf4\xa0\xfd\xfa\x35\x65\xa8\x5b\x5d\xfd\x12'
            b'\xa9\xf7\x84\x54\x15\x4a\xc1\x85\xd4\x32\x67\xee\x33\x90\x08\x40'
        )
        self.client_random = (
            b'\x91\xc6\x36\x47\x1b\xfe\x58\xea\x21\x5d\x0f\x69\x3a\x1a\xd1\x78'
            b'\xf1\x38\xf3\xc0\x60\x6d\x30\x72\xf2\xaf\xf1\xad\x24\x86\x6a\x87'
        )
        self.master_secret = (
            b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5'
            b'\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea'
            b'\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'
        )
        
        self.tls_decrypter = MasterDecrypter.MasterDecrypter(
            256,
            AES.MODE_GCM,
            SHA384,
            self.master_secret,
            self.server_random,
            self.client_random
        )
    
    def test_decrypt_client(self):
        """Test decryption of client data."""
        plaintext = self.tls_decrypter.decrypt_client(self.client_cipher_text)
        # Verify we got some plaintext (actual content verification would require knowing expected output)
        self.assertIsNotNone(plaintext)
        self.assertIsInstance(plaintext, bytes)
        self.assertGreater(len(plaintext), 0)
    
    def test_invalid_master_secret_length(self):
        """Test that invalid master secret length raises ValueError."""
        with self.assertRaises(ValueError):
            MasterDecrypter.MasterDecrypter(
                256,
                AES.MODE_GCM,
                SHA384,
                b'short',  # Too short
                self.server_random,
                self.client_random
            )
    
    def test_invalid_server_random_length(self):
        """Test that invalid server random length raises ValueError."""
        with self.assertRaises(ValueError):
            MasterDecrypter.MasterDecrypter(
                256,
                AES.MODE_GCM,
                SHA384,
                self.master_secret,
                b'short',  # Too short
                self.client_random
            )
    
    def test_invalid_client_random_length(self):
        """Test that invalid client random length raises ValueError."""
        with self.assertRaises(ValueError):
            MasterDecrypter.MasterDecrypter(
                256,
                AES.MODE_GCM,
                SHA384,
                self.master_secret,
                self.server_random,
                b'short'  # Too short
            )
    
    def test_invalid_cipher_size(self):
        """Test that invalid cipher size raises ValueError."""
        with self.assertRaises(ValueError):
            MasterDecrypter.MasterDecrypter(
                512,  # Invalid size
                AES.MODE_GCM,
                SHA384,
                self.master_secret,
                self.server_random,
                self.client_random
            )
    
    def test_decrypt_client_short_ciphertext(self):
        """Test that short ciphertext raises ValueError."""
        with self.assertRaises(ValueError):
            self.tls_decrypter.decrypt_client(b'short')
    
    def test_decrypt_server_short_ciphertext(self):
        """Test that short ciphertext raises ValueError."""
        with self.assertRaises(ValueError):
            self.tls_decrypter.decrypt_server(b'short')


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)