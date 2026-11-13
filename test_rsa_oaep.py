# test_rsa_oaep.py
import unittest

from rsa_oaep import (
    DecryptionError,
    OAEPError,
    decrypt,
    encrypt,
    gen_prime,
    i2osp,
    is_probable_prime,
    keygen,
)


class TestRSAOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Unit tests use 1024-bit for speed; bench.py ​​will then test in 2048-bit.
        cls.priv = keygen(1024, rounds=20)
        cls.pub = cls.priv.public_key()

    def test_roundtrip_lengths(self):
        hlen = 32
        k = self.pub.size_bytes()
        max_len = k - 2 * hlen - 2
        for mlen in [0, 1, 2, 15, max_len // 2, max_len]:
            msg = bytes((i * 7 + 3) % 256 for i in range(mlen))
            ct = encrypt(self.pub, msg)
            self.assertEqual(decrypt(self.priv, ct), msg)

    def test_label_must_match(self):
        msg = b"hello OAEP"
        ct = encrypt(self.pub, msg, label=b"context-A")
        self.assertEqual(decrypt(self.priv, ct, label=b"context-A"), msg)
        with self.assertRaises(DecryptionError):
            decrypt(self.priv, ct, label=b"context-B")

    def test_tampered_ciphertext_rejected(self):
        ct = bytearray(encrypt(self.pub, b"secret"))
        ct[-1] ^= 1
        with self.assertRaises(DecryptionError):
            decrypt(self.priv, bytes(ct))

    def test_message_too_long(self):
        k = self.pub.size_bytes()
        max_len = k - 2 * 32 - 2
        with self.assertRaises(OAEPError):
            encrypt(self.pub, b"x" * (max_len + 1))

    def test_prime_generation(self):
        p = gen_prime(64, rounds=10)
        self.assertEqual(p.bit_length(), 64)
        self.assertTrue(is_probable_prime(p, rounds=10))

    def test_i2osp_boundary(self):
        self.assertEqual(i2osp(0, 1), b"\x00")
        self.assertEqual(i2osp(255, 1), b"\xff")
        with self.assertRaises(ValueError):
            i2osp(256, 1)


if __name__ == "__main__":
    unittest.main()