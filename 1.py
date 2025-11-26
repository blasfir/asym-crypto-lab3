import random
import secrets
import math


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def jacobi_symbol(a, b):
    if b <= 0 or b % 2 == 0:
        raise ValueError("b має бути додатним непарним цілим числом")
    a %= b
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

    return result if b == 1 else 0


def solovay_strassen(p, k=40):
    if p < 2:
        raise ValueError("p має бути натуральним числом більше 1")
    if p == 2:
        return True
    if p % 2 == 0:
        return False

    for _ in range(k):
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


# -------------------------------
#     НОВА ФУНКЦІЯ РОЗПАКУВАННЯ
# -------------------------------
def decode_from_x(x, n):
    l = (n.bit_length() + 7) // 8
    x_bytes = x.to_bytes(l, "big")
    r_bytes = x_bytes[l - 8:l]   # останні 8 байтів — r

    # Шукаємо всі місця, де може бути 0xFF
    for i in range(l - 8):
        if x_bytes[i] != 0xFF:
            continue

        m_bytes = x_bytes[i+1:l-8]

        # Перевіряємо, чи цей x має правильний формат
        x_re = int.from_bytes(
            b"\x00"*(l-8) + b"\xFF" + m_bytes + r_bytes,
            "big"
        )

        if x_re == x:
            return m_bytes

    return None


# -------------------------------
#       ВИПРАВЛЕНИЙ DECRYPT
# -------------------------------
def Decrypt(y, c1, c2, p, q, b, n):
    Diskr = (b*b + 4*y) % n
    roots = sqrt_mod_blum(Diskr, p, q)
    inv2 = inv(2, n)

    for s in roots:
        x = ((-b + s) * inv2) % n
        m_bytes = decode_from_x(x, n)
        if m_bytes is not None:
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


"""public_A, private_A = GenerateKeyPair(128)
n_A, b_A = public_A
p_A, q_A, bA_secret = private_A"""
"""n_A, b_A = 58901066684138891971696524309168736993861125128992468841146511056043223388253, 10091763845116835198971492930882110254597539620667102926184254958602996067657
p_A, q_A, bA_secret = 225421953262520129214635218346707849111, 261292504264410973271035992629745671723, 10091763845116835198971492930882110254597539620667102926184254958602996067657

print("\nАбонент A\n")
print("Відкритий ключ A (n, b):")
print(n_A, b_A)
print(hex(n_A).upper(), hex(b_A).upper())

print("\nСекретний ключ A (p, q, b):")
print(p_A, q_A, bA_secret)

message_A = b"Hi"

c1 = 1
c2 = 1
y = 0X2E3BE3411B9E6AF9D2C80A25C1AFF575738CBAE667761E40B2CFB06621399B96

decrypted = Decrypt(y, c1, c2, p_A, q_A, b_A, n_A)
print()
print("Розшифроване повідомлення:", decrypted)"""

n, b = 0XD7D6838FEEA0D726545FDF291033A7A1, 0XEE74055912B63D3B8F2544CC663E374

m_bytes = b"Hi"

enc = Encrypt(m_bytes, n, b)
y_A, c1_A, c2_A = enc
print()
print(hex(y_A).upper())
print(c1_A)
print(c2_A)
