# bench.py
import time

from rsa_oaep import keygen, encrypt, decrypt


def bench(bits: int):
    t0 = time.perf_counter()
    priv = keygen(bits, rounds=40)
    t1 = time.perf_counter()
    pub = priv.public_key()

    max_len = pub.size_bytes() - 2 * 32 - 2
    msg = b"A" * min(32, max_len)

    t2 = time.perf_counter()
    ct = encrypt(pub, msg)
    t3 = time.perf_counter()
    pt = decrypt(priv, ct)
    t4 = time.perf_counter()

    assert pt == msg
    print(f"RSA-{bits}: keygen={t1-t0:.3f}s, encrypt={t3-t2:.6f}s, "
          f"decrypt={t4-t3:.6f}s, max_msg={max_len}B")


if __name__ == "__main__":
    for bits in [1024, 2048]:
        bench(bits)