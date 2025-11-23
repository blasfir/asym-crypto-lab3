import random
import secrets
import math


def gcd(a, b):
    while b != 0:
        a, b = b, a % b  # ok
    return a


def jacobi_symbol(a, b):
    if b <= 0 or b % 2 == 0:
        raise ValueError("b має бути додатним непарним цілим числом")  # ok
    a = a % b
    result = 1

    while a != 0:
        while a % 2 == 0:
            a //= 2
            if b % 8 in (3, 5):
                result = -result

        a, b = b, a
        if a % 4 == 3 and b % 4 == 3:
            result = -result

        a %= b

    if b == 1:
        return result
    else:
        return 0


def solovay_strassen(p, k=40):
    if p < 2:
        raise ValueError("p має бути натуральним числом більше 1")  # ok
    if p == 2:
        return True
    if p % 2 == 0:
        return False

    i = 0

    while i < k:

        x = random.randint(2, p - 1)
        g = gcd(x, p)
        if g > 1:
            return False
        j_s = jacobi_symbol(x, p)
        d = pow(x, (p - 1) // 2, p)
        if j_s == -1:
            j_s = p - 1
        if d != j_s:
            return False

        i += 1

    return True


def bm_generator_bytes(p, a, n, state=None):
    if state is None:
        state = secrets.randbelow(p - 1) + 1

    out_bytes = bytearray()
    for _ in range(n):
        k = (state * 256) // (p - 1)
        out_bytes.append(k)
        state = pow(a, state, p)
    return bytes(out_bytes), state


def generate_blum_prime(bits, a=5):

    byte_len = (bits + 7) // 8

    state = secrets.randbelow(2**bits - 1) + 1

    while True:
        rand_bytes, state = bm_generator_bytes(
            p=2**bits - 5,
            a=a,
            n=byte_len,
            state=state
        )

        blum_p = int.from_bytes(rand_bytes, "big")

        blum_p |= (1 << (bits - 1))

        blum_p |= 1

        if blum_p % 4 != 3:
            continue

        if solovay_strassen(blum_p):
            return blum_p


def inv(a, m):
    a %= m
    if gcd(a, m) != 1:
        return None
    return pow(a, -1, m)


def GenerateKeyPair(bits=512):
    p = generate_blum_prime(bits)
    q = generate_blum_prime(bits)
    n = p * q
    b = random.randrange(1, n)

    return (n, b), (p, q, b)


def format_message(m, n):
    l = (n.bit_length() + 7) // 8
    if len(m) > l - 10:
        raise ValueError("Повідомлення занадто довге.")

    rand_bytes, _ = bm_generator_bytes(
        p=2**256 - 5,
        a=5,
        n=8
    )
    r = int.from_bytes(rand_bytes, "big")

    x = int.from_bytes(
        b"\x00"*(l-8) + b"\xFF" + m + r.to_bytes(8, "big"),
        "big"
    )
    return x


def Encrypt(m_bytes, n, b):
    x = format_message(m_bytes, n)

    y = (x * (x + b)) % n
    c1 = (x + b) % 2
    c2 = jacobi_symbol(x + b, n)

    return y, c1, c2


def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)


def sqrt_mod_blum(y, p, q):
    s1 = pow(y, (p + 1) // 4, p)
    s2 = pow(y, (q + 1) // 4, q)

    u, v, _ = egcd(p, q)
    roots = []
    for sign1 in (1, -1):
        for sign2 in (1, -1):
            r = (sign1 * u * p * s2 + sign2 * v * q * s1) % (p * q)
            roots.append(r)

    return roots


def Decrypt(y, c1, c2, p, q, b, n):
    Diskr = (b*b + 4*y) % n

    roots = sqrt_mod_blum(Diskr, p, q)

    inv2 = inv(2, n)

    candidates = []

    for s in roots:
        x = ((-b + s) * inv2) % n
        candidates.append(x)

    for x in candidates:
        if (x + b) % 2 == c1 and jacobi_symbol(x + b, n) == c2:

            l = (n.bit_length() + 7) // 8
            x_bytes = x.to_bytes(l, "big")

            marker_pos = x_bytes.rfind(b"\xFF", 0, l - 8)
            if marker_pos == -1:
                continue

            m_start = marker_pos + 1
            m_end = l - 8
            m_bytes = x_bytes[m_start:m_end]

            return m_bytes

    raise ValueError(
        "Не знайдено коректного x — шифротекст пошкоджений або ключі неправильні.")


def Sign(m_bytes, p, q, n):
    while True:
        l = (n.bit_length() + 7) // 8

        rand_bytes, _ = bm_generator_bytes(
            p=2**256 - 5,
            a=5,
            n=8
        )
        r = int.from_bytes(rand_bytes, "big")

        x = int.from_bytes(
            b"\x00"*(l-8) + b"\xFF" + m_bytes + r.to_bytes(8, "big"),
            "big"
        )

        if jacobi_symbol(x, p) == 1 and jacobi_symbol(x, q) == 1:
            break

    roots = sqrt_mod_blum(x, p, q)

    s = random.choice(roots)

    return s, r


def Verify(m_bytes, s, r, n):
    l = (n.bit_length() + 7) // 8

    x_expected = int.from_bytes(
        b"\x00"*(l-8) + b"\xFF" + m_bytes + r.to_bytes(8, "big"),
        "big"
    )

    x_actual = pow(s, 2, n)
    return x_actual == x_expected


public_key, private_key = GenerateKeyPair(bits=64)

n,  b = public_key
p, q, b_secret = private_key

print()
print("Відкритий ключ (n, b):")
print()
print(n, b)
print()
print("Секретний (p, q, b):")
print()
print(p, q, b_secret)

message = b"Hi"
ciphertext = Encrypt(message, n, b)
print()
print("Шифротекст (y, c1, c2):")
print()
print(ciphertext)

y, c1, c2 = ciphertext

decrypted = Decrypt(y, c1, c2, p, q, b, n)
print()
print("Розшифроване повідомлення:", decrypted)

signature_s, signature_r = Sign(message, p, q, n)
print()
print("Підпис s:")
print()
print("s =", signature_s)
print("r =", signature_r)

is_valid = Verify(message, signature_s, signature_r, n)
print()
print("Підпис коректний?", is_valid)
