"""
TLS Traffic PCAP Parser and Decrypter.

This script parses a PCAP file containing TLS traffic, extracts handshake
information, and decrypts application data using a provided master secret.

Usage:
    python parsePcap.py <pcap_file> [--master-secret <hex_string>]
    python parsePcap.py --help

Assumptions:
- PCAP contains only one TCP stream
- Symmetric algorithm is AES
"""

import sys
import argparse
import logging
from typing import List, Tuple, Optional, Any


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# TLS content types
CONTENT_APPLICATION_DATA = b'\x17'
CONTENT_HANDSHAKE = b'\x16'
HANDSHAKE_CLIENT_HELLO = b'\x01'
HANDSHAKE_SERVER_HELLO = b'\x02'

# Default master secret (for backward compatibility)
DEFAULT_MASTER_SECRET = b'\xd2\x76\x4f\x01\x83\x60\xd6\xc1\x29\x3c\x56\x76\xe2\x06\xad\xe5\x8b\x31\xfc\x56\x77\xde\xef\x2a\xee\xda\xb0\xf7\x28\x7d\x87\xea\x43\xb5\xc6\xd9\x9c\xd8\xc9\x01\x39\xb0\x7a\xbe\x6a\xe4\x99\xbc'


def cs_name_to_values(ciphersuite_name: str) -> Tuple[str, int, int, Any]:
    """
    Parse cipher suite name to extract cryptographic parameters.
    
    Args:
        ciphersuite_name: Full cipher suite name from TLS handshake
        
    Returns:
        Tuple of (encryption_algorithm, key_size, cipher_mode, hash_algorithm)
        
    Raises:
        ValueError: If cipher suite format is invalid or hash is unsupported
    """
    # Import here to allow --help without dependencies
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA384, SHA256, SHA1, SHA224, SHA512
    
    try:
        symmetric_part = ciphersuite_name.split('WITH_')[1]
    except IndexError:
        raise ValueError(f"Invalid cipher suite format: {ciphersuite_name}")

    parts = symmetric_part.split('_')
    if len(parts) < 4:
        raise ValueError(f"Invalid cipher suite format: {ciphersuite_name}")
        
    enc_algo = parts[0]
    size_raw = parts[1]
    mode_raw = parts[2]
    hash_raw = parts[3]
    
    try:
        size = int(size_raw)
    except ValueError:
        raise ValueError(f"Invalid key size: {size_raw}")
        
    try:
        mode = getattr(AES, f'MODE_{mode_raw}')
    except AttributeError:
        raise ValueError(f"Unsupported cipher mode: {mode_raw}")
    
    hash_str = hash_raw.split()[0]

    hash_map = {
        'SHA384': SHA384,
        'SHA256': SHA256,
        'SHA1': SHA1,
        'SHA224': SHA224,
        'SHA512': SHA512,
    }
    
    hash_algo = hash_map.get(hash_str)
    if hash_algo is None:
        raise ValueError(f'Unsupported hash: {hash_str}')

    return enc_algo, size, mode, hash_algo


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Parse and decrypt TLS traffic from PCAP file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcap --master-secret d2764f018360d6c1293c5676e206ade5...
  %(prog)s capture.pcap --verbose
        """
    )
    
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file containing TLS traffic'
    )
    
    parser.add_argument(
        '--master-secret',
        type=str,
        help='Master secret as hex string (48 bytes = 96 hex chars)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def hex_to_bytes(hex_string: str) -> bytes:
    """
    Convert hex string to bytes.
    
    Args:
        hex_string: Hex string (with or without spaces/colons)
        
    Returns:
        Bytes object
        
    Raises:
        ValueError: If hex string is invalid
    """
    # Remove common separators
    hex_clean = hex_string.replace(' ', '').replace(':', '').replace('-', '')
    
    try:
        return bytes.fromhex(hex_clean)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")


def main():
    """Main entry point for the script."""
    args = parse_args()
    
    # Import dependencies here to allow --help to work without them installed
    try:
        import pyshark
        import MasterDecrypter
    except ImportError as e:
        logger.error(f"Missing required dependency: {e}")
        logger.error("Please install dependencies: pip3 install -r requirements.txt")
        sys.exit(1)
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Get master secret
    if args.master_secret:
        try:
            master_secret = hex_to_bytes(args.master_secret)
            if len(master_secret) != 48:
                logger.error("Master secret must be 48 bytes (96 hex characters)")
                sys.exit(1)
        except ValueError as e:
            logger.error(f"Invalid master secret: {e}")
            sys.exit(1)
    else:
        logger.warning("Using default master secret (for testing only)")
        master_secret = DEFAULT_MASTER_SECRET
    
    # Try to open PCAP file
    try:
        logger.info(f"Opening PCAP file: {args.pcap_file}")
        packets = pyshark.FileCapture(args.pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error opening PCAP file: {e}")
        sys.exit(1)
    
    # Initialize variables
    client_random = None
    server_random = None
    ciphersuite = None
    application_datas_c2s = []
    application_datas_s2c = []
    client_addr = b''
    server_addr = b''
    
    # Parse packets
    try:
        for idx, packet in enumerate(packets):
            if 'SSL' not in packet:
                logger.debug(f'Discarding non-SSL packet: #{idx}')
                continue
                
            if not hasattr(packet.ssl, 'record_content_type'):
                continue

            if hasattr(packet.ssl, 'handshake_type'):
                if (packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and
                    packet.ssl.handshake_type.binary_value == HANDSHAKE_CLIENT_HELLO):
                    client_random = packet.ssl.handshake_random.binary_value
                    client_addr = packet.ip.src_host
                    logger.info(f'Reading client hello from {client_addr} packet #{idx}')
                    logger.debug(f'Got Client Random: {client_random.hex()}')

                elif (packet.ssl.record_content_type.binary_value == CONTENT_HANDSHAKE and
                      packet.ssl.handshake_type.binary_value == HANDSHAKE_SERVER_HELLO):
                    server_random = packet.ssl.handshake_random.binary_value
                    ciphersuite = packet.ssl.handshake_ciphersuite.showname
                    server_addr = packet.ip.src_host
                    logger.info(f'Reading server hello from {server_addr} packet #{idx}')
                    logger.debug(f'Got Server Random: {server_random.hex()}')
                    logger.info(f'Got {ciphersuite}')

            elif packet.ssl.record_content_type.binary_value == CONTENT_APPLICATION_DATA:
                data_len = len(packet.ssl.app_data.binary_value)
                logger.debug(f'Reading {data_len} bytes encrypted application data from packet: #{idx}')

                if packet.ip.src_host == server_addr:
                    application_datas_s2c.append(packet.ssl.app_data.binary_value)
                elif packet.ip.src_host == client_addr:
                    application_datas_c2s.append(packet.ssl.app_data.binary_value)
                    
    except Exception as e:
        logger.error(f"Error parsing packets: {e}")
        sys.exit(1)
    finally:
        packets.close()
    
    # Validate we have all required data
    if client_random is None or server_random is None or ciphersuite is None:
        logger.error('Incomplete handshake, unable to decrypt')
        sys.exit(1)
    
    if len(application_datas_c2s) + len(application_datas_s2c) < 1:
        logger.error('No application data found to decrypt')
        sys.exit(1)
    
    logger.info(f"Found {len(application_datas_c2s)} client records and {len(application_datas_s2c)} server records")
    
    # Parse cipher suite and create decrypter
    try:
        enc_algo, size, mode, hash_algo = cs_name_to_values(ciphersuite)
        logger.debug(f"Cipher parameters: {enc_algo}, {size} bits, mode {mode}")
        decrypter = MasterDecrypter.MasterDecrypter(
            size, mode, hash_algo, master_secret, server_random, client_random
        )
    except ValueError as e:
        logger.error(f"Error parsing cipher suite: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error creating decrypter: {e}")
        sys.exit(1)
    
    # Decrypt and display results
    logger.info('=' * 60)
    logger.info('Client Records (Client → Server)')
    logger.info('=' * 60)
    for i, record in enumerate(application_datas_c2s):
        try:
            plaintext = decrypter.decrypt_client(record)
            print(f"Record {i}: {plaintext}")
        except Exception as e:
            logger.error(f"Error decrypting client record {i}: {e}")
    
    logger.info('=' * 60)
    logger.info('Server Records (Server → Client)')
    logger.info('=' * 60)
    for i, record in enumerate(application_datas_s2c):
        try:
            plaintext = decrypter.decrypt_server(record)
            # Show first 100 bytes for brevity
            print(f"Record {i}: {plaintext[:100]}{'...' if len(plaintext) > 100 else ''}")
        except Exception as e:
            logger.error(f"Error decrypting server record {i}: {e}")


if __name__ == '__main__':
    main()