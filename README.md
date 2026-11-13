# SE6003 Cryptography Project - Topic I2: RSA-OAEP

**Course**: SE6003 Cryptography (AY 2026)
**Institution**: Nanyang Technological University Singapore
**Topic**: I2 - RSA-OAEP Implementation

**Group Members**:
- Lin Pengyu (G2606203C) - *Code Implementation*
- [Name 2] ([Matriculation Number 2]) - *Report Writing*
- [Name 3] ([Matriculation Number 3]) - *Video Presentation/Testing*

---

## 1. Project Overview

This repository contains an educational, from-scratch proof-of-concept implementation of **RSAES-OAEP** (RSA Encryption Scheme with Optimal Asymmetric Encryption Padding) using SHA-2 (specifically SHA-256), following the RFC 8017 standard.

The implementation includes:
1. **Prime Generation**: Cryptographically secure prime sampling and the Miller-Rabin primality test.
2. **RSA Primitives**: Key generation, raw RSA encryption (`RSAEP`), and raw RSA decryption (`RSADP`).
3. **OAEP Padding**: `EME-OAEP-ENCODE` and `EME-OAEP-DECODE` operations, including the Mask Generation Function (`MGF1`).

---

## 2. Dependencies and Environment

- **Programming Language**: Python 3.8 or higher.
- **Third-party Libraries**: **None**. The project is implemented entirely using the Python Standard Library.
  - `hashlib` is used for SHA-256 hashing (as permitted by the course guidelines).
  - `secrets` is used for cryptographically secure random number generation (seed and prime generation).
  - `hmac` is used for constant-time comparison to prevent timing attacks.
  - `math`, `dataclasses`, `unittest`, and `time` are used for basic logic, structure, and testing.

*No external open-source cryptographic libraries (e.g., `cryptography`, `PyCryptodome`) were used for the RSA or OAEP logic.*

---

## 3. File Structure

```text
rsa_oaep_project/
├── rsa_oaep.py          # Core implementation of RSA, Miller-Rabin, and OAEP
├── test_rsa_oaep.py     # Unit tests (positive, negative, and edge cases)
├── bench.py             # Benchmark script for performance evaluation
└── README.md            # Project instructions and implementation notes
```

---

## 4. Build and Run Instructions

Because this is a pure Python 3 project, there is no compilation step required. You can run the scripts directly from your terminal.

### 4.1 Running the Unit Tests
To verify the correctness of the implementation (including round-trip correctness, tamper-rejection, and boundary tests), run:

```bash
python3 -m unittest -v test_rsa_oaep.py
```
**Expected Output**: `Ran 6 tests in ...s` followed by `OK`. The tests will automatically generate a 1024-bit RSA key to run the checks.

### 4.2 Running the Benchmarks
To measure the performance of key generation, encryption, and decryption for 1024-bit and 2048-bit keys, run:

```bash
python3 bench.py
```
**Expected Output**:
```text
RSA-1024: keygen=0.078s, encrypt=0.000436s, decrypt=0.003827s, max_msg=62B
RSA-2048: keygen=1.257s, encrypt=0.000744s, decrypt=0.018973s, max_msg=190B
```
*(Note: Performance may vary slightly depending on your hardware.)*

### 4.3 Basic Usage (API Example)
You can import the module and use it in your own Python scripts:

```python
from rsa_oaep import keygen, encrypt, decrypt, DecryptionError

# 1. Generate a 2048-bit RSA key pair
private_key = keygen(bits=2048)
public_key = private_key.public_key()

# 2. Encrypt a message (maximum 190 bytes for 2048-bit key with SHA-256)
message = b"NTU SE6003 Cryptography Project"
ciphertext = encrypt(public_key, message)

# 3. Decrypt the message
decrypted_message = decrypt(private_key, ciphertext)
print(decrypted_message) # Output: b"NTU SE6003 Cryptography Project"

# 4. Tampered ciphertext will raise a DecryptionError
bad_ciphertext = bytearray(ciphertext)
bad_ciphertext[-1] ^= 1
try:
    decrypt(private_key, bytes(bad_ciphertext))
except DecryptionError:
    print("Tampering detected! Decryption failed securely.")
```

---

## 5. Implementation Details & Originality

In accordance with the course guidelines ("*you are not allowed to simply borrow existing implementations... without adding significant values, which you must explain clearly*"), we explicitly declare the following:

### What is original (written by us):
1. **Miller-Rabin Primality Test**: Implemented from scratch, including the decomposition of \(n-1 = 2^s \cdot d\) and the witness loop.
2. **Prime Generation**: Custom logic for securely generating odd integers in the correct bit-range and filtering them through our Miller-Rabin test.
3. **MGF1 (Mask Generation Function)**: Implemented as a counter-based hash function wrapper.
4. **OAEP Encoding/Decoding**: The full Feistel-network-like padding structure (`EME-OAEP-ENCODE` and `EME-OAEP-DECODE`), including strict checks for the `lHash`, the `0x01` delimiter, and the zero-padding string (`PS`).
5. **I2OSP/OS2IP**: Custom integer-to-octet-string and octet-string-to-integer conversions with length verification.

### What is third-party/standard:
1. **SHA-256 Hash Function**: Obtained via Python's standard `hashlib` module (as explicitly permitted in the project description).
2. **Secure Randomness**: Obtained via Python's standard `secrets` module.

### Security Warning
This is a **proof-of-concept educational implementation**. It is **not constant-time** (meaning it does not defend against sophisticated timing side-channel attacks) and lacks advanced memory-clearing mechanisms. It should **never** be used to protect real-world sensitive data. For production environments, standard libraries such as OpenSSL or Python's `cryptography` package should be used.

---


