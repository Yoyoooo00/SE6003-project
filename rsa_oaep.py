# rsa_oaep.py
from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass


class OAEPError(ValueError):
    pass


class DecryptionError(Exception):
    pass


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


def i2osp(x: int, x_len: int) -> bytes:
    if x < 0:
        raise ValueError("negative integer")
    if x >= 1 << (8 * x_len):
        raise ValueError("integer too large")
    return x.to_bytes(x_len, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def _hash(hash_name: str, data: bytes) -> bytes:
    h = hashlib.new(hash_name)
    h.update(data)
    return h.digest()


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if length < 0:
        raise ValueError("negative length")
    if length > (1 << 32) * hlen:
        raise ValueError("mask too long")

    out = bytearray()
    for counter in range((length + hlen - 1) // hlen):
        out.extend(_hash(hash_name, seed + counter.to_bytes(4, "big")))
    return bytes(out[:length])


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, rounds: int = 40) -> int:
    if bits < 2:
        raise ValueError("bits too small")

    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if bits >= 3:
            candidate |= 1 << (bits - 2)  # 设置次高位，帮助 n 保持目标位长
        if is_probable_prime(candidate, rounds):
            return candidate


def keygen(bits: int = 2048, e: int = 65537, rounds: int = 40) -> PrivateKey:
    if bits < 16:
        raise ValueError("key too small")

    while True:
        p = gen_prime(bits // 2, rounds)
        q = gen_prime(bits // 2, rounds)
        if p == q:
            continue

        n = p * q
        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue

        d = pow(e, -1, phi)
        return PrivateKey(n, e, d, p, q)


def oaep_encode(message: bytes, k: int, label: bytes = b"",
                hash_name: str = "sha256") -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if k < 2 * hlen + 2:
        raise OAEPError("modulus too short for OAEP")

    mlen = len(message)
    max_len = k - 2 * hlen - 2
    if mlen > max_len:
        raise OAEPError("message too long")

    lhash = _hash(hash_name, label)
    ps = b"\x00" * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message

    seed = secrets.token_bytes(hlen)
    db_mask = mgf1(seed, k - hlen - 1, hash_name)
    masked_db = xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, hlen, hash_name)
    masked_seed = xor_bytes(seed, seed_mask)

    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, label: bytes = b"",
                hash_name: str = "sha256") -> bytes:
    hlen = hashlib.new(hash_name).digest_size
    if k < 2 * hlen + 2 or len(em) != k:
        raise DecryptionError("decryption error")

    y = em[0]
    masked_seed = em[1:1 + hlen]
    masked_db = em[1 + hlen:]

    seed_mask = mgf1(masked_db, hlen, hash_name)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - hlen - 1, hash_name)
    db = xor_bytes(masked_db, db_mask)

    lhash = _hash(hash_name, label)
    lhash2 = db[:hlen]
    rest = db[hlen:]

    sep = rest.find(b"\x01")
    bad = (y != 0) or (not hmac.compare_digest(lhash, lhash2)) or (sep < 0)
    if not bad and any(b != 0 for b in rest[:sep]):
        bad = True

    if bad:
        raise DecryptionError("decryption error")

    return rest[sep + 1:]


def rsaep(pub: PublicKey, m: int) -> int:
    if not (0 <= m < pub.n):
        raise ValueError("message representative out of range")
    return pow(m, pub.e, pub.n)


def rsadp(priv: PrivateKey, c: int) -> int:
    if not (0 <= c < priv.n):
        raise DecryptionError("decryption error")
    return pow(c, priv.d, priv.n)


def encrypt(pub: PublicKey, message: bytes, label: bytes = b"",
            hash_name: str = "sha256") -> bytes:
    k = pub.size_bytes()
    em = oaep_encode(message, k, label, hash_name)
    m = os2ip(em)
    c = rsaep(pub, m)
    return i2osp(c, k)


def decrypt(priv: PrivateKey, ciphertext: bytes, label: bytes = b"",
            hash_name: str = "sha256") -> bytes:
    k = priv.size_bytes()
    if len(ciphertext) != k:
        raise DecryptionError("decryption error")

    try:
        c = os2ip(ciphertext)
        m = rsadp(priv, c)
        em = i2osp(m, k)
        return oaep_decode(em, k, label, hash_name)
    except Exception as exc:
        raise DecryptionError("decryption error") from exc