from egcd import egcd
import random
import time
import matplotlib.pyplot as plt
random.seed(36)


# pad to blksz
# Input: bit string to be padded, block size to align (512 for plaintext, 1024 for ciphertext)
# Output: 0-padded bit string
def pad(bstr, blksz):
    bstr_len = len(bstr)
    if bstr_len % blksz != 0:
        while bstr_len > 0:
            bstr_len -= blksz
        pad = abs(bstr_len)
        bstr = '0' * pad + bstr
    assert len(bstr) % blksz == 0
    return bstr

# convert an int to a string of bit, padded to multiple of blksz
# Input: integer n
# Output: n in bit representation, padded to multiple of blksz
def to_bit_str(n, blksz):
    bit_str = bin(n)[2:]
    bit_str = pad(bit_str, blksz)

    assert n == int(bit_str, 2)     # make sure int and str match
    return bit_str

# basic RSA encryption
# Input: bit string M as plaintext, public keys (e,n)
# Output: bit string C as ciphertext
def Enc(M, e, n):
    assert len(M) % 512 == 0    # 512-bit blocks plaintext
    # convert to int and do RSA ops
    M_int = int(M, 2)
    assert M_int < n            # RSA requirement: m < n
    C_int = pow(M_int, e, n)

    # convert back to bit string
    C = to_bit_str(C_int, 1024)     # 1024-bit blocks ciphertext
    return C              


# basic RSA decryption
# Input: bit string C as ciphertext, private keys (d,n)
# Output: bit string M as plaintext
def Dec(C, d, n):
    assert len(C) % 1024 == 0    # 1024-bit blocks ciphertext
    # convert to int and do RSA ops
    C_int = int(C, 2)
    M_int = pow(C_int, d, n)

    # convert back to bit string
    M = to_bit_str(M_int, 512)  # 512-bit blocks plaintext
    return M 

# block RSA encryption
# Input: bit string M as plaintext, public keys (e,n)
# Output: bit string C as ciphertext
def BlockEnc(M, e, n):
    assert len(M) % 512 == 0
    assert int(M, 2) >= n        # blocking only for messages >= n
    ciphertext = ""
    for i in range(len(M) // 512):     # RSA on each plaintext block of 512 bits
        ciphertext += Enc(M[512*i : 512*(i+1)], e, n)
    assert len(ciphertext) % 1024 == 0          # ciphertext is 1024-bit blocks
    return ciphertext

# block RSA decryption
# Input: bit string C as ciphertext, private keys (d,n)
# Output: bit string M as plaintext
def BlockDec(C, d, n):
    assert len(C) % 512 == 0
    assert int(C, 2) > n
    plaintext = ""
    for i in range(len(C) // 1024):     # RSA on each ciphertext block of 1024 bits
        plaintext += Dec(C[1024*i : 1024*(i+1)], d, n)
    assert len(plaintext) % 512 == 0        # plaintext is 512-bit blocks
    return plaintext

def RSA_test_basic(n, e, d):
    # basic Encryption/Decryption test
    for i in range(500):        # test 500 random messages from 0 to n-1
        M_int = random.randint(0, n-1)
        M = to_bit_str(M_int, 512)
        C = Enc(M, e, n)
        assert Dec(C, d, n) == M
    print("RSA correct")

def RSA_test_block(n, e, d):
    # block Encryption/Decryption test
    for i in range(500):        # test 500 random bigger messages
        block_M_int = random.randint(n, n * 100000000000000000000000000000000000000)
        block_M = to_bit_str(block_M_int, 512)
        block_C = BlockEnc(block_M, e, n)
        assert BlockDec(block_C, d, n) == block_M
    print("Block RSA correct")

def RSA_runtime_plot(n, e, d):
    messages = [
        (1 << 0),       # 1 bit
        (1 << 99),      # 100 bits
        (1 << 999),     # 1000 bits
        (1 << 1022),    # 1023 bits (largest safe power-of-two)

        # messages >= n
        # (1 << 1024),   # 1025 bits        # runtime for this is super low
        (1 << 1100),   # 1101 bits
        (1 << 10000),     # 10001 bits
        (1 << 100000),    # 100001 bits
        (1 << 500000),    # 500001 bits
        (1 << 1000000)    # 1000001 bits
    ]
    message_sizes = [1, 100, 1000, 1023, 1101, 10001, 100001, 500001, 1000001]
    times = []

    for i in range(len(message_sizes)):
        start_time = time.perf_counter()

        if messages[i] < n:
            M_int = messages[i]
            M = to_bit_str(M_int, 512)
            C = Enc(M, e, n)
            assert Dec(C, d, n) == M
        elif messages[i] >= n:
            block_M_int = messages[i]
            block_M = to_bit_str(block_M_int, 512)
            block_C = BlockEnc(block_M, e, n)
            assert BlockDec(block_C, d, n) == block_M

        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000
        times.append(elapsed_time)

    plt.figure()
    plt.plot(message_sizes, times, marker='o')
    plt.xlabel("Message Size")
    plt.ylabel("Time (ms)")
    plt.title("Runtime of different Message Sizes")
    plt.grid(True)
    plt.savefig("rsa.png")


def main():
    # 512 bit ~ 156 digit primes
    p = 11768486830057115166813708216419442819789630026552521364390215824122667879499012152966055405964064840134670273335351322307427959816163285539415855392398931
    q = 10656505317395185867599269878343987961437910002658889862534577592970648171805867453126335163669579383121665841978424950866051175731196949476850342375818713
    assert p.bit_length() == 512 
    assert q.bit_length() == 512 

    # n, Φ(n), e, d
    n = p*q
    assert n.bit_length() == 1024   # product has bit length = sum of operands' bit lengths
    totient = (p-1)*(q-1)
    e = 65537
    assert totient % e != 0         # make sure e is relatively prime to Φ(n)
    d = egcd(totient, e)[2]         # extended Euclidean algorithm to find d

    # tests
    # RSA_test_basic(n, e, d)
    # RSA_test_block(n, e, d)
    
    # benchmarks
    RSA_runtime_plot(n, e, d)

    
main()
