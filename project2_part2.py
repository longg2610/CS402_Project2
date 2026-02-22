# project2_part2_benchmark.py
import random
import time
import csv
import statistics
import matplotlib.pyplot as plt
from typing import List

import project2_part1 as rsa  # keep RSA imported from Part 1


# =============================================================================
# AES-128 (CTR) — full implementation
# =============================================================================

S_BOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

RC = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_state(block16: bytes) -> List[List[int]]:
    if len(block16) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = block16[4 * c + r]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def xtime02(a: int) -> int:
    a &= 0xFF
    return ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0x00)


def gf_mult(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = xtime02(a)
        b >>= 1
    return res & 0xFF


def sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    for r in range(4):
        state[r] = state[r][r:] + state[r][:r]


def mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mult(0x02, s0) ^ gf_mult(0x03, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ gf_mult(0x02, s1) ^ gf_mult(0x03, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ gf_mult(0x02, s2) ^ gf_mult(0x03, s3)
        state[3][c] = gf_mult(0x03, s0) ^ s1 ^ s2 ^ gf_mult(0x02, s3)


def add_round_key(state: List[List[int]], round_key: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]


def sub_word(word: List[int]) -> List[int]:
    return [S_BOX[b] for b in word]


def key_expansion(key16: bytes) -> List[List[List[int]]]:
    if len(key16) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    w: List[List[int]] = []
    for i in range(4):
        w.append([key16[4*i], key16[4*i+1], key16[4*i+2], key16[4*i+3]])

    for i in range(4, 44):
        temp = w[i - 1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RC[i // 4]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    round_keys: List[List[List[int]]] = []
    for rnd in range(11):
        rk = [[0] * 4 for _ in range(4)]
        for c in range(4):
            word = w[4 * rnd + c]
            for r in range(4):
                rk[r][c] = word[r]
        round_keys.append(rk)

    return round_keys


def aes128_encryption_block(plaintext: bytes, round_keys: List[List[List[int]]]) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("AES block must be 16 bytes")
    if len(round_keys) != 11:
        raise ValueError("Need 11 round keys")

    state = bytes_to_state(plaintext)
    add_round_key(state, round_keys[0])

    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return state_to_bytes(state)


def aes_ctr_encrypt(plaintext: bytes, round_keys: List[List[List[int]]], iv: int = 0) -> bytes:
    out = b""
    counter = iv % (1 << 128)
    i = 0
    while i < len(plaintext):
        counter_block = counter.to_bytes(16, "big")
        keystream = aes128_encryption_block(counter_block, round_keys)
        take = min(16, len(plaintext) - i)
        out += xor_bytes(plaintext[i:i+take], keystream[:take])
        counter = (counter + 1) % (1 << 128)
        i += take
    return out


# =============================================================================
# Benchmarking: RSA vs AES (uses RSA message sizes from part1)
# =============================================================================
MESSAGE_SIZES_BITS = [1, 100, 1000, 1023, 1101, 10001, 100001, 500001, 1000001]
TRIALS = 15

def bits_to_bytes_len(bits: int) -> int:
    return (bits + 7) // 8

def median_time_ms(fn, *args) -> float:
    times = []
    for _ in range(TRIALS):
        t0 = time.perf_counter()
        fn(*args)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    return statistics.median(times)

def rsa_one_run(bit_len: int, n: int, e: int, d: int) -> None:
    # Use a random message with exact bit length
    if bit_len == 1:
        m_int = 1
    else:
        m_int = random.getrandbits(bit_len) | (1 << (bit_len - 1))

    M = rsa.to_bit_str(m_int, 512)

    if m_int < n:
        C = rsa.Enc(M, e, n)
        _ = rsa.Dec(C, d, n)
    else:
        C = rsa.BlockEnc(M, e, n)
        _ = rsa.BlockDec(C, d, n)

def aes_one_run(size_bytes: int, round_keys) -> None:
    pt = bytes(random.getrandbits(8) for _ in range(size_bytes))
    ct = aes_ctr_encrypt(pt, round_keys, iv=0)
    if len(ct) != len(pt):
        raise RuntimeError("AES CTR output length mismatch")

def main():
    random.seed(36)

    # -------- RSA keys (same primes as Part 1) --------
    p = 11768486830057115166813708216419442819789630026552521364390215824122667879499012152966055405964064840134670273335351322307427959816163285539415855392398931
    q = 10656505317395185867599269878343987961437910002658889862534577592970648171805867453126335163669579383121665841978424950866051175731196949476850342375818713
    n = p * q
    totient = (p - 1) * (q - 1)
    e = 65537

    # IMPORTANT: this assumes your Part 1 defines egcd OR you fix d there.
    # If Part 1 still imports egcd, then either:
    #   - paste egcd into Part 1, or
    #   - create egcd.py
    g, x, _ = rsa.egcd(e, totient)
    if g != 1:
        raise RuntimeError("e not invertible mod totient")
    d = x % totient

    # -------- AES key (reproducible) --------
    random.seed(1950775)
    key16 = random.getrandbits(128).to_bytes(16, "big")
    round_keys = key_expansion(key16)

    rows = []
    for bits in MESSAGE_SIZES_BITS:
        size_bytes = bits_to_bytes_len(bits)

        rsa_ms = median_time_ms(rsa_one_run, bits, n, e, d)
        aes_ms = median_time_ms(aes_one_run, size_bytes, round_keys)

        rows.append((bits, size_bytes, rsa_ms, aes_ms))
        print(f"bits={bits:>7}, bytes={size_bytes:>7} | RSA={rsa_ms:>10.3f} ms | AES={aes_ms:>10.3f} ms")

    # CSV
    with open("runtimes.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["size_bits", "size_bytes", "rsa_median_ms", "aes_median_ms"])
        w.writerows(rows)

    # Plot
    xs = [r[0] for r in rows]
    rsa_ys = [r[2] for r in rows]
    aes_ys = [r[3] for r in rows]

    plt.figure()
    plt.plot(xs, rsa_ys, marker="o", label="RSA (median)")
    plt.plot(xs, aes_ys, marker="o", label="AES-128 CTR (median)")
    plt.xlabel("Message size (bits)")
    plt.ylabel("Runtime (ms)")
    plt.title("RSA vs AES Runtime Comparison")
    plt.grid(True)
    plt.legend()

    # Uncomment if RSA dwarfs AES too hard:
    # plt.yscale("log")
    # plt.xscale("log")

    plt.savefig("rsa_vs_aes.png", dpi=200)
    print("\nSaved: runtimes.csv and rsa_vs_aes.png")

if __name__ == "__main__":
    main()