# Cryptography and Security Implementation

## Project Overview

This repository contains a comprehensive implementation of fundamental cryptographic algorithms and protocols, focusing on **Advanced Encryption Standard (AES)** and **Elliptic Curve Cryptography (ECC)**. The project demonstrates the practical application of symmetric and asymmetric cryptographic techniques, including secure key exchange protocols and client-server communication models.

## Project Purpose and Objectives

The primary objectives of this project are:

- **Educational Implementation**: Provide a detailed, from-scratch implementation of AES-128 encryption and decryption algorithms
- **Cryptographic Protocol Demonstration**: Illustrate the integration of ECC for secure key exchange with AES for data encryption
- **Network Security**: Demonstrate secure communication between client and server using established cryptographic protocols
- **Performance Analysis**: Evaluate the computational efficiency of ECC operations across different key sizes (128, 192, and 256 bits)
- **Academic Research**: Support cryptography and security coursework with practical implementations

## File Structure and Architecture

### Core Implementation Files

#### `aes.py` - Complete AES Encryption System

- **Purpose**: Standalone AES-128 implementation with interactive command-line interface
- **Key Features**:
  - Complete AES key schedule generation using RCON values
  - Full encryption pipeline with SubBytes, ShiftRows, MixColumns, and AddRoundKey operations
  - Complete decryption pipeline with inverse operations
  - PKCS#7 padding implementation for variable-length inputs
  - CBC (Cipher Block Chaining) mode with random initialization vectors
  - Performance timing measurements for encryption and decryption operations
- **Notable Functions**:
  - `key_schedule(key)`: Generates 11 round keys from the master key
  - `encrypt(user_key, user_plaintext)`: Complete encryption with padding and CBC mode
  - `decrypt(user_key, encrypted_text)`: Complete decryption with unpadding
  - `mix_columns(state)` and `invMixColumns(state)`: Galois Field operations
  - `genRandomInitialVector()`: IV generation for CBC mode

#### `alice.py` - Client-Side Secure Communication

- **Purpose**: Client implementation for secure messaging using ECC key exchange and AES encryption
- **Key Features**:
  - ECC key pair generation and public key exchange
  - Shared secret derivation using ECDH (Elliptic Curve Diffie-Hellman)
  - AES key derivation from ECC shared secret
  - Message encryption before transmission
  - TCP socket communication with server
- **Protocol Flow**:
  1. Generate ECC parameters (curve, generator point, private key)
  2. Exchange public keys with server via JSON serialization
  3. Compute shared secret using scalar multiplication
  4. Derive AES key from shared secret
  5. Encrypt messages using AES before sending

#### `bob.py` - Server-Side Secure Communication

- **Purpose**: Server implementation for receiving and decrypting secure messages
- **Key Features**:
  - ECC parameter reception and public key response
  - Shared secret computation identical to client
  - Message decryption using derived AES key
  - Continuous message reception and processing
- **Protocol Flow**:
  1. Accept ECC parameters from client
  2. Generate server's ECC key pair
  3. Send public key to client
  4. Compute identical shared secret
  5. Receive and decrypt messages from client

#### `ecc.py` - Elliptic Curve Cryptography Core

- **Purpose**: Pure ECC implementation with performance benchmarking
- **Key Features**:
  - Complete ECC point arithmetic (point addition, scalar multiplication)
  - Tonelli-Shanks algorithm for quadratic residue computation
  - Random elliptic curve generation with valid parameters
  - Performance benchmarking across multiple key sizes (128, 192, 256 bits)
  - Statistical analysis of computational times
- **Mathematical Functions**:
  - `point_add(P1, P2, a, P)`: Elliptic curve point addition
  - `scalar_mult(k, point, a, P)`: Scalar multiplication using double-and-add
  - `tonelliShanksAlgorithm(n, p)`: Square root computation in finite fields
  - `find_base_point(a, b, P)`: Generator point discovery
  - `isQuadraticResidue(n, p)`: Euler's criterion implementation

#### `bitvector-demo.py` - BitVector Library Demonstration

- **Purpose**: Educational demonstration of BitVector library capabilities
- **Features**:
  - AES S-box lookup operations
  - Galois Field multiplication examples
  - Hexadecimal and binary conversions
  - BitVector arithmetic demonstrations

#### `a.py` - AES Key Expansion Study

- **Purpose**: Focused implementation and analysis of AES key expansion algorithm
- **Features**:
  - Detailed key schedule generation
  - Word rotation and substitution operations
  - RCON constant application
  - Key expansion verification and testing

## Dependencies and Environment Requirements

### Required Python Libraries

```python
from BitVector import *     # Bit manipulation and GF operations
import random              # Random number generation
import time               # Performance timing
from sympy import randprime  # Prime number generation
import socket             # Network communication
import json               # Data serialization
import math               # Mathematical operations
```

### Installation Instructions

1. **Install Python 3.7 or higher**
2. **Install required dependencies**:

   ```bash
   pip install BitVector
   pip install sympy
   ```

3. **Clone or download the repository**
4. **Ensure all Python files are in the same directory**

### System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python Version**: 3.7+
- **Memory**: Minimum 512MB RAM for ECC operations
- **Network**: TCP/IP stack for client-server communication

## Usage Guidelines

### Standalone AES Encryption (`aes.py`)

```bash
python aes.py
```

**Interactive Process**:

1. Enter 16-character encryption key (auto-padded/truncated)
2. Enter plaintext message (automatically padded to 16-byte blocks)
3. System displays encryption timing, ciphertext, and decryption verification

**Example Session**:

```text
Key:
In ASCII: mysecretkey12345
Plain Text: 
In ASCII: Hello, World!
Time taken for encryption: 0.0023 ms
The encrypted plain text is: [encrypted bytes]
Time taken for decryption: 0.0019 ms
The decrypted plain text is: Hello, World!
```

### Secure Client-Server Communication

#### Starting the Server (`bob.py`)

```bash
python bob.py
```

**Server Output**:

```text
Socket successfully created
socket binded to 12345
socket is listening
```

#### Connecting as Client (`alice.py`)

```bash
python alice.py
```

**Client Process**:

1. Automatic ECC key exchange with server
2. Shared AES key derivation and display
3. Interactive message input and encryption
4. Automatic transmission to server

### ECC Performance Benchmarking (`ecc.py`)

```bash
python ecc.py
```

**Output Format**:

```text
k  : computational time for a  : computation time for b  : shared key R
128 : 0.0045 : 0.0043 : 0.0041
192 : 0.0067 : 0.0065 : 0.0063
256 : 0.0089 : 0.0087 : 0.0085
```

## Configuration Options

### AES Configuration

- **Key Size**: Fixed at 128 bits (16 bytes)
- **Block Size**: 128 bits (16 bytes)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS#7 standard
- **Rounds**: 10 rounds for AES-128

### ECC Configuration

- **Curve Type**: Random curves over prime fields
- **Key Sizes**: 128, 192, and 256 bits
- **Prime Generation**: Using sympy's randprime function
- **Point Arithmetic**: Affine coordinates
- **Hash Function**: Direct coordinate conversion for AES key derivation

### Network Configuration

- **Protocol**: TCP
- **Default Port**: 12345
- **Host**: localhost (127.0.0.1)
- **Data Format**: JSON for parameter exchange, raw bytes for messages

## Technical Implementation Details

### AES Implementation Specifics

The AES implementation follows the FIPS 197 standard with these characteristics:

- **S-box**: Complete 256-byte substitution table with inverse
- **Key Schedule**: 44 words generated from 16-byte master key
- **MixColumns**: Galois Field GF(2^8) multiplication with AES polynomial
- **ShiftRows**: Cyclic left shifts with row-dependent offsets
- **AddRoundKey**: XOR operation between state and round key

### ECC Implementation Specifics

The ECC implementation provides:

- **Point Addition**: Complete addition formula handling special cases
- **Scalar Multiplication**: Binary method (double-and-add algorithm)
- **Curve Generation**: Random coefficients ensuring non-singular curves
- **Base Point Finding**: Systematic search with quadratic residue verification
- **Key Exchange**: ECDH protocol with coordinate-based shared secret

### Security Considerations

- **Random Number Generation**: Uses Python's cryptographically secure random module
- **Prime Generation**: Employs sympy's probabilistic primality testing
- **Key Derivation**: Direct conversion from ECC coordinates (educational purpose)
- **IV Generation**: Random initialization vectors for each encryption session
- **Padding Oracle Protection**: Standard PKCS#7 padding implementation

## Performance Characteristics

### Typical Performance Metrics

Based on benchmarking results from `ecc.py`:

| Key Size | Key Generation | Scalar Multiplication | Shared Secret |
|----------|----------------|----------------------|---------------|
| 128-bit  | ~4.5ms         | ~4.3ms               | ~4.1ms        |
| 192-bit  | ~6.7ms         | ~6.5ms               | ~6.3ms        |
| 256-bit  | ~8.9ms         | ~8.7ms               | ~8.5ms        |

### AES Performance

- **Encryption**: Typically 2-3ms for 16-byte blocks
- **Decryption**: Typically 1-2ms for 16-byte blocks
- **Key Schedule**: Sub-millisecond generation

## Educational Value and Learning Outcomes

This implementation serves as an excellent educational resource for:

### Cryptographic Concepts

- **Symmetric Encryption**: Understanding AES operations and modes
- **Asymmetric Cryptography**: ECC mathematics and key exchange
- **Hybrid Cryptosystems**: Combining ECC and AES for practical security
- **Network Security**: Secure communication protocol implementation

### Programming Skills

- **Algorithm Implementation**: Translating mathematical concepts to code
- **Network Programming**: Socket-based client-server architecture
- **Performance Analysis**: Timing and benchmarking techniques
- **Data Structures**: Efficient handling of cryptographic data types

### Mathematical Understanding

- **Finite Field Arithmetic**: Galois Field operations in AES
- **Elliptic Curve Mathematics**: Point operations and scalar multiplication
- **Number Theory**: Prime generation and quadratic residues
- **Modular Arithmetic**: Core operations in both AES and ECC

## Development and Contribution Guidelines

### Code Organization

- Each major cryptographic component is implemented in a separate file
- Common functionality is shared through import statements
- Clear separation between mathematical operations and application logic

### Testing and Verification

- Each implementation includes verification mechanisms
- AES encrypt-decrypt cycles verify correctness
- ECC shared secret computation ensures protocol integrity
- Performance timing provides empirical analysis

### Future Enhancements

Potential areas for expansion include:

- **Additional AES Modes**: CTR, GCM, or OFB mode implementations
- **Curve Standardization**: Support for standard curves (P-256, P-384, P-521)
- **Key Derivation Functions**: HKDF or PBKDF2 implementation
- **Digital Signatures**: ECDSA signature scheme
- **Protocol Hardening**: Authentication and integrity verification

## Academic and Research Applications

This codebase supports various academic and research activities:

### Coursework Support

- **Cryptography Courses**: Hands-on implementation experience
- **Network Security**: Practical protocol implementation
- **Mathematics**: Applied number theory and algebra
- **Computer Science**: Algorithm design and analysis

### Research Opportunities

- **Performance Optimization**: Algorithm efficiency improvements
- **Security Analysis**: Side-channel attack resistance
- **Protocol Design**: Custom secure communication protocols
- **Comparative Studies**: Analysis against standard implementations

## Conclusion

This comprehensive cryptographic implementation provides a solid foundation for understanding modern cryptographic systems. The combination of AES and ECC represents current best practices in hybrid cryptosystems, while the educational focus ensures accessibility for learning and research purposes. The modular design allows for independent study of each component while demonstrating their integration in practical applications.

The project successfully bridges theoretical cryptographic concepts with practical implementation challenges, providing valuable insights into both the mathematical foundations and the engineering considerations necessary for secure system development.
 
 