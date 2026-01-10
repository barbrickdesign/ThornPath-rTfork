"""
TLS Master Secret Decrypter Module.

This module provides functionality to decrypt TLS traffic using master secrets
and cryptographic parameters extracted from TLS handshakes.
"""

from typing import Optional
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC

MAX_KEY_MATERIAL_LENGTH = 128


class MasterDecrypter:
    """
    Decrypts TLS traffic using master secret and handshake parameters.
    
    This class implements the TLS PRF (Pseudo-Random Function) and key derivation
    process to decrypt TLS application data.
    """

    def __init__(self, cipher_size: int, cipher_mode: int, cipher_hash, 
                 master_secret: bytes, server_random: bytes, client_random: bytes):
        """
        Initialize the TLS Master Decrypter.
        
        Args:
            cipher_size: Size of the cipher in bits (e.g., 128, 256)
            cipher_mode: AES cipher mode (e.g., AES.MODE_GCM, AES.MODE_CBC)
            cipher_hash: Hash algorithm module (e.g., Hash.SHA256, Hash.SHA384)
            master_secret: The TLS master secret (48 bytes)
            server_random: Server random value from handshake (32 bytes)
            client_random: Client random value from handshake (32 bytes)
            
        Raises:
            ValueError: If input parameters are invalid
        """
        # Validate inputs
        if not isinstance(master_secret, bytes) or len(master_secret) != 48:
            raise ValueError("master_secret must be 48 bytes")
        if not isinstance(server_random, bytes) or len(server_random) != 32:
            raise ValueError("server_random must be 32 bytes")
        if not isinstance(client_random, bytes) or len(client_random) != 32:
            raise ValueError("client_random must be 32 bytes")
        if cipher_size not in [128, 256]:
            raise ValueError("cipher_size must be 128 or 256")
            
        self.cipher_size = cipher_size
        self.cipher_mode = cipher_mode
        self.cipher_hash = cipher_hash
        self.master_secret = master_secret
        self.server_random = server_random
        self.client_random = client_random
        self.key_size = int(cipher_size / 8)
        self.IV_size = 4  # TODO: This changes based on cipher mode (e.g., GCM, CBC, etc.)
        self.nonce_size = 8  # TODO: Only relevant in GCM mode, but is this constant for all GCM configurations?
        self.mac_size = 16  # TODO: is this guaranteed to always be the same across all cipher suites?

    class _OrderedKeyMaterial:
        """Internal class to store ordered key material from PRF."""
        
        def __init__(self):
            """Initialize all key material fields to empty bytes."""
            self.client_write_MAC_key = b''
            self.server_write_MAC_key = b''
            self.client_write_key = b''
            self.server_write_key = b''
            self.client_write_IV = b''
            self.server_write_IV = b''

    def decrypt_client(self, ciphertext: bytes) -> bytes:
        """
        Decrypt client-to-server TLS application data.
        
        Args:
            ciphertext: Encrypted application data from client
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            ValueError: If ciphertext is too short or invalid
        """
        if len(ciphertext) < self.nonce_size + self.mac_size:
            raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes")
            
        key_material = self._PRF(self.master_secret, b'key expansion', self.server_random + self.client_random)
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:self.nonce_size]
        mac = ciphertext[-1 * self.mac_size:]
        ciphertext_only = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.client_write_key, self.cipher_mode, ordered_keys.client_write_IV + nonce)
        return aes_decrypter.decrypt(ciphertext_only)

    def decrypt_server(self, ciphertext: bytes) -> bytes:
        """
        Decrypt server-to-client TLS application data.
        
        Args:
            ciphertext: Encrypted application data from server
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            ValueError: If ciphertext is too short or invalid
        """
        if len(ciphertext) < self.nonce_size + self.mac_size:
            raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes")
            
        key_material = self._PRF(self.master_secret, b'key expansion', self.server_random + self.client_random)
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:self.nonce_size]
        mac = ciphertext[-1 * self.mac_size:]
        ciphertext_only = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.server_write_key, self.cipher_mode, ordered_keys.server_write_IV + nonce)
        return aes_decrypter.decrypt(ciphertext_only)

    def _HMAC_hash(self, secret: bytes, seed: bytes) -> bytes:
        """
        Compute HMAC hash using the configured hash algorithm.
        
        Args:
            secret: Secret key for HMAC
            seed: Data to hash
            
        Returns:
            HMAC digest bytes
        """
        return HMAC.new(secret, seed, self.cipher_hash).digest()

    def _P_hash(self, secret: bytes, seed: bytes) -> bytes:
        """
        TLS P_hash function for PRF.
        
        Implements the TLS P_hash function which is defined as:
        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) +
                               HMAC_hash(secret, A(3) + seed) + ...
        where A(i) = HMAC_hash(secret, A(i-1)) and A(0) = seed
        
        Args:
            secret: Secret key
            seed: Seed value
            
        Returns:
            Generated pseudo-random bytes
        """
        res = b''
        A_i = [seed]

        while len(res) < MAX_KEY_MATERIAL_LENGTH:
            A_i.append(self._HMAC_hash(secret, A_i[-1]))  # A_i = HMAC_hash(secret, A_(i-1))

            # P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
            res += self._HMAC_hash(secret, A_i[-1] + seed)

        return res

    def _PRF(self, secret: bytes, label: bytes, seed: bytes) -> bytes:
        """
        TLS Pseudo-Random Function (PRF).
        
        The PRF is used for key derivation in TLS.
        
        Args:
            secret: Secret key (typically master secret)
            label: ASCII label for key expansion
            seed: Seed value (typically server_random + client_random)
            
        Returns:
            Pseudo-random output bytes
        """
        return self._P_hash(secret, label + seed)

    def _get_keys(self, key_material: bytes) -> _OrderedKeyMaterial:
        """
        Extract ordered keys from key material.
        
        Parses the key material generated by PRF into individual keys for
        encryption and MAC. Currently optimized for GCM mode.
        
        Args:
            key_material: Raw key material from PRF
            
        Returns:
            OrderedKeyMaterial object with parsed keys
            
        Note:
            TODO: General cleanup and make this work for more than just GCM mode
        """
        ret = self._OrderedKeyMaterial()
        ret.client_write_MAC_key = b''
        ret.server_write_MAC_key = b''

        ret.client_write_key = key_material[0:self.key_size]
        ret.server_write_key = key_material[self.key_size: 2 * self.key_size]
        ret.client_write_IV = key_material[2 * self.key_size: 2 * self.key_size + self.IV_size]
        ret.server_write_IV = key_material[2 * self.key_size + self.IV_size:2 * self.key_size + 2 * self.IV_size]

        return ret