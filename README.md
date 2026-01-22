# Telepath

Decrypt TLS traffic by searching for keys in memory dumps.

## Description

Telepath (ThornPath fork) is a Python-based tool for decrypting TLS traffic from PCAP files using extracted master secrets. It supports parsing TLS handshakes, extracting cryptographic parameters, and decrypting application data.

## Features

- Parse TLS handshakes from PCAP files
- Extract client/server random values and cipher suite information
- Decrypt TLS 1.2 application data using master secrets
- Support for multiple AES modes (GCM, CBC, etc.)
- Support for multiple hash algorithms (SHA256, SHA384, SHA512, etc.)
- Command-line interface with flexible options
- Comprehensive error handling and logging
- Type hints and extensive documentation

## Requirements

Python 3.7 or higher is required.

### Python Dependencies

Install required packages:

```bash
pip3 install -r requirements.txt
```

Or manually:

```bash
pip3 install pyshark pycryptodomex
```

### System Dependencies

PyShark requires tshark (part of Wireshark):

**Ubuntu/Debian:**
```bash
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download and install Wireshark from https://www.wireshark.org/

## Usage

### Basic Usage

Decrypt TLS traffic from a PCAP file (uses default master secret for testing):

```bash
python3 parsePcap.py singlestream.openmrs.org.pcap
```

### With Custom Master Secret

Provide your own master secret as a hex string:

```bash
python3 parsePcap.py capture.pcap --master-secret d2764f018360d6c1293c5676e206ade5...
```

### Verbose Mode

Enable detailed logging:

```bash
python3 parsePcap.py capture.pcap --verbose
```

### Help

Display all available options:

```bash
python3 parsePcap.py --help
```

## Module Usage

You can also use the MasterDecrypter class in your own Python scripts:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA384
import MasterDecrypter

# Initialize decrypter
decrypter = MasterDecrypter.MasterDecrypter(
    cipher_size=256,
    cipher_mode=AES.MODE_GCM,
    cipher_hash=SHA384,
    master_secret=master_secret_bytes,
    server_random=server_random_bytes,
    client_random=client_random_bytes
)

# Decrypt client data
plaintext = decrypter.decrypt_client(ciphertext)

# Decrypt server data
plaintext = decrypter.decrypt_server(ciphertext)
```

## Testing

Run the test suite:

```bash
python3 -m unittest testMasterDecrypter.py
```

Or with verbose output:

```bash
python3 testMasterDecrypter.py
```

## Project Structure

- `MasterDecrypter.py` - Core TLS decryption module implementing PRF and key derivation
- `parsePcap.py` - Command-line tool for parsing PCAP files and decrypting TLS traffic
- `testMasterDecrypter.py` - Unit tests for the MasterDecrypter module
- `requirements.txt` - Python package dependencies
- `singlestream.openmrs.org.pcap` - Sample PCAP file for testing

## Limitations

- Currently optimized for TLS 1.2 with GCM mode
- Assumes single TCP stream per PCAP file
- Requires pre-extracted master secret (from memory dumps or key logs)
- MAC validation is not currently implemented

## Security Note

This tool is intended for security research, debugging, and educational purposes only. Ensure you have proper authorization before analyzing any TLS traffic.

## License

See the original repository for license information.
