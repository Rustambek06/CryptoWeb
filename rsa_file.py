import os

def get_power_2_factors(n: int) -> (int, int): # type: ignore
    r = 0
    d = n
    while n > 0 and d % 2 == 0:
        d = d // 2
        r += 1
    return r, d

def miller_rabin_prime_test(n: int, k: int) -> bool:
    r, d = get_power_2_factors(n-1)
    for i in range(k):
        a = get_random_bits(n.bit_length())
        while a not in range(2, n-2+1):
            a = get_random_bits(n.bit_length())
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        n_1_found = False
        for j in range(r-1):
            x = pow(x, 2, n)
            if x == n - 1:
                n_1_found = True
                break
        if not n_1_found:
            return False
    return True

def get_random_bits(bit_length: int) -> int:
    return int.from_bytes(os.urandom((bit_length + 7) // 8), 'big')

def generate_prime_number(bit_length: int) -> int:
    low = pow(2, bit_length - 1)
    high = pow(2, bit_length) - 1
    while True:
        candidate_prime = get_random_bits(bit_length)
        while candidate_prime not in range(low, high+1) or not candidate_prime % 2:
            candidate_prime = get_random_bits(bit_length)
        k = 64
        if miller_rabin_prime_test(candidate_prime, k):
            return candidate_prime

def extended_gcd(a, b):
    if not b:
        return 1, 0

    u, v = extended_gcd(b, a % b)
    return v, u - v * (a // b)

def calculate_private_key(e: int, p: int, q: int) -> int:
    u, _ = extended_gcd(e, (p-1)*(q-1))
    return u

def rsa_encrypt(plaintext: bytes, e: int, n: int) -> int:
    p_int = int.from_bytes(plaintext, "big")
    return pow(p_int, e, n)

def rsa_decrypt(ciphertext: int, d: int, n: int) -> bytes:
    p_int = pow(ciphertext, d, n)
    return p_int.to_bytes((p_int.bit_length() + 7) // 8, 'big')
