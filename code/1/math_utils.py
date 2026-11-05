"""공통 수학 함수: 소수 판정, 모듈러 역원, RSA, Diffie-Hellman.

alice.py / bob.py 에서 다음처럼 가져다 쓴다.
    from math_utils import is_prime, is_generator, ...
모든 소수는 과제 조건대로 400~500 범위에서 고른다.
"""
import random

PRIME_MIN = 400
PRIME_MAX = 500

# ---------------------------------------------------------------------------
# 기본 정수론
# ---------------------------------------------------------------------------
def is_prime(n):
    """시행 나눗셈(trial division)으로 소수 판정. 정수가 아니면 False."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def random_prime(lo=PRIME_MIN, hi=PRIME_MAX, exclude=None):
    """[lo, hi] 범위의 임의의 소수 (exclude 와 다른 값)."""
    primes = [x for x in range(lo, hi + 1) if is_prime(x) and x != exclude]
    return random.choice(primes)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """a*x + b*y = g 를 만족하는 (g, x, y)."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a, m):
    """a^-1 mod m. 역원이 없으면 ValueError."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("{} 은(는) mod {} 에서 역원이 없음".format(a, m))
    return x % m


def prime_factors(n):
    """n 의 서로 다른 소인수 집합."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors

# ---------------------------------------------------------------------------
# RSA  (Protocol I, II)
# ---------------------------------------------------------------------------
def generate_rsa_keypair():
    """(p, q, e, d) 를 만든다. n = p*q, e = 공개키, d = 개인키."""
    p = random_prime()
    q = random_prime(exclude=p)
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randrange(3, phi)
        if gcd(e, phi) == 1:
            break
    d = mod_inverse(e, phi)
    return p, q, e, d


def verify_rsa_keypair(p, q, e, d):
    """p, q 가 소수이고 e*d ≡ 1 (mod φ(n)) 이면 True."""
    if not (is_prime(p) and is_prime(q)) or p == q:
        return False
    phi = (p - 1) * (q - 1)
    return (e * d) % phi == 1


def rsa_encrypt(m, e, n):
    return pow(m, e, n)


def rsa_decrypt(c, d, n):
    return pow(c, d, n)


def rsa_encrypt_bytes(data, e, n):
    """바이트열을 한 바이트씩 RSA 암호화 -> 정수 리스트 (encrypted_key)."""
    return [pow(b, e, n) for b in data]


def rsa_decrypt_bytes(cipher_list, d, n):
    """정수 리스트를 한 원소씩 복호화 -> bytes."""
    return bytes(pow(c, d, n) for c in cipher_list)

# ---------------------------------------------------------------------------
# Diffie-Hellman  (Protocol III, IV)
# ---------------------------------------------------------------------------
def is_generator(g, p):
    """g 가 (Z/pZ)* 의 생성원인지 판정 (p 는 소수라고 가정).

    p-1 의 모든 소인수 q 에 대해 g^((p-1)/q) mod p != 1 이면 생성원.
    """
    if not isinstance(g, int) or isinstance(g, bool) or not (2 <= g <= p - 1):
        return False
    return all(pow(g, (p - 1) // q, p) != 1 for q in prime_factors(p - 1))


def find_generator(p):
    """소수 p 의 생성원 중 하나를 임의로 고른다."""
    candidates = [g for g in range(2, p) if is_generator(g, p)]
    return random.choice(candidates)


def find_non_generator(p):
    """테스트용 (Protocol IV-II): 생성원이 아닌 g."""
    candidates = [g for g in range(2, p) if not is_generator(g, p)]
    return random.choice(candidates)


def random_non_prime(lo=PRIME_MIN, hi=PRIME_MAX):
    """테스트용 (Protocol IV-I): 범위 안의 합성수."""
    return random.choice([x for x in range(lo, hi + 1) if not is_prime(x)])


def generate_dh_params():
    """(p, g) : 400~500 사이 소수 p 와 생성원 g."""
    p = random_prime()
    return p, find_generator(p)


def generate_dh_keypair(p, g):
    """(private, public) : private ∈ [2, p-2], public = g^private mod p."""
    private = random.randint(2, p - 2)
    return private, pow(g, private, p)


def dh_shared_secret(other_public, my_private, p):
    return pow(other_public, my_private, p)


def dh_to_aes_key(shared):
    """과제 규칙: shared.to_bytes(2, 'big') 를 16번 반복 -> 32바이트 AES 키."""
    return shared.to_bytes(2, byteorder="big") * 16
