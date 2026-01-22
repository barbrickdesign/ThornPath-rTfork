#!/usr/bin/env python3
"""
Validation script to test enhanced functionality without external dependencies.

This script validates:
1. MasterDecrypter imports and basic validation works
2. Type hints are present
3. Docstrings are comprehensive
4. Error handling works correctly
"""

import sys
import inspect
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA384, SHA256, SHA1, SHA224, SHA512
import MasterDecrypter


def test_docstrings():
    """Test that all functions and classes have docstrings."""
    print("Testing docstrings...")
    
    # Check module docstring
    assert MasterDecrypter.__doc__ is not None, "Module missing docstring"
    print("✓ Module has docstring")
    
    # Check class docstring
    assert MasterDecrypter.MasterDecrypter.__doc__ is not None, "MasterDecrypter class missing docstring"
    print("✓ MasterDecrypter class has docstring")
    
    # Check method docstrings
    methods = ['__init__', 'decrypt_client', 'decrypt_server', '_HMAC_hash', '_P_hash', '_PRF', '_get_keys']
    for method_name in methods:
        method = getattr(MasterDecrypter.MasterDecrypter, method_name)
        assert method.__doc__ is not None, f"Method {method_name} missing docstring"
        print(f"✓ Method {method_name} has docstring")
    
    print("✓ All docstrings present\n")


def test_type_hints():
    """Test that functions have type hints."""
    print("Testing type hints...")
    
    # Check __init__ signature
    sig = inspect.signature(MasterDecrypter.MasterDecrypter.__init__)
    params = sig.parameters
    
    # Check that key parameters have type hints
    assert 'cipher_size' in params, "cipher_size parameter missing"
    assert params['cipher_size'].annotation != inspect.Parameter.empty, "cipher_size missing type hint"
    print("✓ Type hints present on __init__")
    
    # Check decrypt_client
    sig = inspect.signature(MasterDecrypter.MasterDecrypter.decrypt_client)
    assert sig.return_annotation != inspect.Signature.empty, "decrypt_client missing return type"
    print("✓ Type hints present on decrypt_client")
    
    print("✓ Type hints validated\n")


def test_validation():
    """Test input validation."""
    print("Testing input validation...")
    
    valid_master_secret = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'
    valid_server_random = b'\xe3\xc8\x89\xda\x5d\xf4\xa0\xfd\xfa\x35\x65\xa8\x5b\x5d\xfd\x12\xa9\xf7\x84\x54\x15\x4a\xc1\x85\xd4\x32\x67\xee\x33\x90\x08\x40'
    valid_client_random = b'\x91\xc6\x36\x47\x1b\xfe\x58\xea\x21\x5d\x0f\x69\x3a\x1a\xd1\x78\xf1\x38\xf3\xc0\x60\x6d\x30\x72\xf2\xaf\xf1\xad\x24\x86\x6a\x87'
    
    # Test invalid master secret length
    try:
        MasterDecrypter.MasterDecrypter(
            256, AES.MODE_GCM, SHA384,
            b'short', valid_server_random, valid_client_random
        )
        assert False, "Should have raised ValueError for short master_secret"
    except ValueError as e:
        assert "master_secret" in str(e).lower()
        print("✓ Validates master_secret length")
    
    # Test invalid server random length
    try:
        MasterDecrypter.MasterDecrypter(
            256, AES.MODE_GCM, SHA384,
            valid_master_secret, b'short', valid_client_random
        )
        assert False, "Should have raised ValueError for short server_random"
    except ValueError as e:
        assert "server_random" in str(e).lower()
        print("✓ Validates server_random length")
    
    # Test invalid client random length
    try:
        MasterDecrypter.MasterDecrypter(
            256, AES.MODE_GCM, SHA384,
            valid_master_secret, valid_server_random, b'short'
        )
        assert False, "Should have raised ValueError for short client_random"
    except ValueError as e:
        assert "client_random" in str(e).lower()
        print("✓ Validates client_random length")
    
    # Test invalid cipher size
    try:
        MasterDecrypter.MasterDecrypter(
            512, AES.MODE_GCM, SHA384,
            valid_master_secret, valid_server_random, valid_client_random
        )
        assert False, "Should have raised ValueError for invalid cipher_size"
    except ValueError as e:
        assert "cipher_size" in str(e).lower()
        print("✓ Validates cipher_size")
    
    # Test valid initialization
    decrypter = MasterDecrypter.MasterDecrypter(
        256, AES.MODE_GCM, SHA384,
        valid_master_secret, valid_server_random, valid_client_random
    )
    print("✓ Valid initialization works")
    
    # Test short ciphertext validation
    try:
        decrypter.decrypt_client(b'short')
        assert False, "Should have raised ValueError for short ciphertext"
    except ValueError as e:
        assert "too short" in str(e).lower()
        print("✓ Validates ciphertext length in decrypt_client")
    
    try:
        decrypter.decrypt_server(b'short')
        assert False, "Should have raised ValueError for short ciphertext"
    except ValueError as e:
        assert "too short" in str(e).lower()
        print("✓ Validates ciphertext length in decrypt_server")
    
    print("✓ All validation tests passed\n")


def test_basic_functionality():
    """Test basic decryption functionality."""
    print("Testing basic functionality...")
    
    # Use test data from the original testMasterDecrypter.py
    client_cipher_text = (
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
    server_random = b'\xe3\xc8\x89\xda\x5d\xf4\xa0\xfd\xfa\x35\x65\xa8\x5b\x5d\xfd\x12\xa9\xf7\x84\x54\x15\x4a\xc1\x85\xd4\x32\x67\xee\x33\x90\x08\x40'
    client_random = b'\x91\xc6\x36\x47\x1b\xfe\x58\xea\x21\x5d\x0f\x69\x3a\x1a\xd1\x78\xf1\x38\xf3\xc0\x60\x6d\x30\x72\xf2\xaf\xf1\xad\x24\x86\x6a\x87'
    master_secret = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'
    
    decrypter = MasterDecrypter.MasterDecrypter(
        256, AES.MODE_GCM, SHA384,
        master_secret, server_random, client_random
    )
    
    # Test decryption (just verify it runs without errors)
    plaintext = decrypter.decrypt_client(client_cipher_text)
    assert isinstance(plaintext, bytes), "Decryption should return bytes"
    assert len(plaintext) > 0, "Decryption should return non-empty result"
    print("✓ Basic decryption works")
    
    print("✓ All functionality tests passed\n")


def main():
    """Run all validation tests."""
    print("=" * 60)
    print("Validating Enhanced Scripts")
    print("=" * 60 + "\n")
    
    try:
        test_docstrings()
        test_type_hints()
        test_validation()
        test_basic_functionality()
        
        print("=" * 60)
        print("✓ ALL VALIDATION TESTS PASSED")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n✗ VALIDATION FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
