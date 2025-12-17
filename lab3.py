import secrets


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def egcd(a, b):
    if b == 0:
        return 1, 0, a
    x, y, g = egcd(b, a % b)
    return y, x - (a // b) * y, g


def inv(a, m):
    a %= m
    if gcd(a, m) != 1:
        return None
    return pow(a, -1, m)


def jacobi_symbol(a, n):
    if n <= 0 or n % 2 == 0:
        raise ValueError("n має бути додатним непарним цілим числом")
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if (a % 4 == 3) and (n % 4 == 3):
            result = -result
        a %= n
    return result if n == 1 else 0


def solovay_strassen(p, k=40):
    if p < 2:
        return False
    if p in (2, 3):
        return True
    if p % 2 == 0:
        return False
    for _ in range(k):
        a = secrets.randbelow(p - 3) + 2
        g = gcd(a, p)
        if g > 1:
            return False

        j = jacobi_symbol(a, p)
        if j == 0:
            return False

        d = pow(a, (p - 1) // 2, p)
        if j == -1:
            j = p - 1

        if d != j:
            return False
    return True


def generate_blum_prime(bits):
    if bits < 32:
        raise ValueError("Вхідне значення занадто мале")
    while True:
        result = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if result % 4 != 3:
            continue
        if solovay_strassen(result):
            return result


def generate_keypair(bits=256):
    p = generate_blum_prime(bits // 2)
    q = generate_blum_prime(bits // 2)
    while q == p:
        q = generate_blum_prime(bits // 2)
    n = p * q
    b = secrets.randbelow(n)
    return n, b, p, q


def byte_len(x):
    return (x.bit_length() + 7) // 8


def format_message(m, n):
    L = byte_len(n)
    block_len = L - 1
    if len(m) > block_len - 9:
        raise ValueError("Повідомлення задовге")
    a = secrets.token_bytes(8)
    zeros = b"\x00" * (block_len - 1 - len(m) - 8)
    b = b"\xFF" + zeros + m + a
    x = int.from_bytes(b, "big")
    return x % n if x >= n else x


def inv_format_message(x):
    b = x.to_bytes(byte_len(x) or 1, "big")
    if b[:1] == b"\xFF" and len(b) > 9:
        return b[1:-8].lstrip(b"\x00")
    return bytes(ch for ch in b if 32 <= ch <= 126)


def sqrt_mod_blum(y, p, q, n):
    sp = pow(y, (p + 1) // 4, p)
    sq = pow(y, (q + 1) // 4, q)
    alpha, beta, g = egcd(p, q)
    if g != 1:
        raise ValueError("p і q не є взаємнопростими")
    roots = []
    for a in (sp, (-sp) % p):
        for b in (sq, (-sq) % q):
            r = (a * (beta * q) + b * (alpha * p)) % n
            roots.append(r)
    return roots


def calculate_hb(b, n):
    inv2 = inv(2, n)
    if inv2 is None:
        raise ValueError("n має бути додатним непарним цілим числом")
    return (b * inv2) % n


def jacob(v, n):
    return 1 if jacobi_symbol(v, n) == 1 else 0


def Encrypt(x, n, b):
    y = (x * ((x + b) % n)) % n
    t = (x + calculate_hb(b, n)) % n
    parity = t & 1
    jac = jacob(t, n)
    return y, parity, jac


def Decrypt(y, parity, jacobi, n, b, p, q):
    hb = calculate_hb(b, n)
    disc = (y + (hb * hb) % n) % n
    for t in sqrt_mod_blum(disc, p, q, n):
        x = (t - hb) % n
        if ((t & 1) == (parity & 1)) and (jacob(t, n) == jacobi):
            return x
    return None


def Sign(m_bytes, n, p, q):
    while True:
        x = format_message(m_bytes, n)
        if jacobi_symbol(x, p) != 1 or jacobi_symbol(x, q) != 1:
            continue
        return secrets.choice(sqrt_mod_blum(x, p, q, n)), x


def Verify(sig, x, n):
    return pow(sig, 2, n) == (x if x < n else x % n)


def read_hex_int(text):
    while True:
        hex = input(text).strip()
        try:
            return int(hex, 16) if hex else 0
        except ValueError:
            print("Невірний формат")


def read_hex_bytes_or_text(text):
    raw = input(text)
    s = raw.strip()
    if (s and len(s) % 2 == 0 and all(ch in "0123456789ABCDEF" for ch in s)):
        return bytes.fromhex(s)
    return s.encode("utf-8")


def encrypt_for_site():
    print()
    n = read_hex_int("Введи N: ")
    b = read_hex_int("Введи B: ")

    m_bytes = read_hex_bytes_or_text("Введи повідомлення: ")

    x = format_message(m_bytes, n)
    y, parity, jac_flag = Encrypt(x, n, b)
    y1 = format(y, 'X').upper()

    print("\nЗашифроване повідомлення: ", y1)
    print("Parity: ", int(parity))
    print("Jacobi Symbol: ", int(jac_flag))


def keygen_and_decrypt_for_site(bits=256):
    n, b, p, q = generate_keypair(bits)
    n1 = format(n, 'X').upper()
    b1 = format(b, 'X').upper()

    print()
    print("N: ", n1)
    print("B: ", b1)

    y = read_hex_int("Введи зашифроване повідомлення: ")
    parity = int(input("Введи Parity: ").strip())
    jac = int(input("Введи Jacobi Symbol: ").strip())
    x = Decrypt(y, parity, jac, n, b, p, q)
    if x is None:
        print("\nНе вдалося знайти коректний корінь")
        return

    inv_form_x = inv_format_message(x)
    x1 = inv_form_x.hex().upper()
    x2 = inv_form_x.decode("utf-8")

    print("\nРозшифроване повідомлення (байти): ", x1)
    print("Розшифроване повідомлення (текст): ", x2)


def keygen_and_sign_for_site(bits=256):
    n, b, p, q = generate_keypair(bits)
    n_hex = format(n, "X").upper()

    print()
    m_bytes = read_hex_bytes_or_text("Введи повідомлення: ")
    sig, x = Sign(m_bytes, n, p, q)
    sig_hex = format(sig, "X").upper()

    print("Sign: ", sig_hex)
    print("N: ", n_hex)


def verify_for_site():
    print()

    n = read_hex_int("Введи N: ")
    m_bytes = read_hex_bytes_or_text("Введи повідомлення: ")
    sig = read_hex_int("Введи Sign: ")

    x = pow(sig, 2, n)
    inv_form_x = inv_format_message(x)

    ok = inv_form_x == m_bytes

    print()
    if ok:
        print("Підпис вірний")
    else:
        print("Підпис не вірний")


def to_upper_hex(hex):
    hex = hex.strip()
    if hex.startswith(("0x", "0X")):
        hex = hex[2:]
    return hex.replace(" ", "").replace("_", "").upper()


def attack():
    print()
    n = read_hex_int("Введи N: ")

    tries = 0

    while True:
        tries += 1

        t = secrets.randbelow(n - 3) + 2
        y = pow(t, 2, n)
        y1 = format(y, 'X').upper()

        print("Y: ", y1)

        pl_mi_t = input("Введи відповідь сервера: ").strip()
        if not pl_mi_t:
            print("Зупинено.")
            return

        z = int(to_upper_hex(pl_mi_t), 16) % n

        t_pl = t % n
        t_mi = (-t) % n
        if z == t_pl or z == t_mi:
            print("Тривіальний корінь (±t). Пробуємо далі…")
            continue

        g1 = gcd(t - z, n)
        g2 = gcd(t + z, n)

        p = None
        if 1 < g1 < n:
            p = g1
        elif 1 < g2 < n:
            p = g2

        if p is None:
            print(
                "Не вдалося витягнути нетривіальний дільник з цієї відповіді. Пробуємо далі…")
            continue

        q = n // p
        print("\nУспіх, ключ зламано.")
        print(f"Спроба: {tries}")
        p1 = format(p, 'X').upper()
        q1 = format(q, 'X').upper()
        print("P: ", p1)
        print("Q: ", q1)
        return


def rabin1(bits=256):
    nA, bA, pA, qA = generate_keypair(bits)
    nB, bB, pB, qB = generate_keypair(bits)

    print("\nАбонент A")
    print("p_A:", format(pA, "X"))
    print("q_A:", format(qA, "X"))
    print("n_A:", format(nA, "X"))
    print("b_A:", format(bA, "X"))

    print("\nАбонент B")
    print("p_B:", format(pB, "X"))
    print("q_B:", format(qB, "X"))
    print("n_B:", format(nB, "X"))
    print("b_B:", format(bB, "X"))

    msg_A_to_B = b"Hi from A"
    print("\n[A → B]")
    print("Відкритий текст (HEX):", msg_A_to_B.hex().upper())
    print("Відкритий текст (TEXT):", msg_A_to_B.decode())

    x = format_message(msg_A_to_B, nB)
    y, parity, jac = Encrypt(x, nB, bB)

    print("Шифротекст:", format(y, "X"))
    print("Parity:", parity)
    print("Jacobi:", jac)

    x_dec = Decrypt(y, parity, jac, nB, bB, pB, qB)
    if x_dec is None:
        print("Розшифрування не вдалося")
    else:
        m_rec = inv_format_message(x_dec)
        print("Розшифровано (HEX):", m_rec.hex().upper())
        print("Розшифровано (TEXT):", m_rec.decode())

    msg_B_to_A = b"Hi from B"
    print("\nB → A")
    print("Відкритий текст (HEX):", msg_B_to_A.hex().upper())
    print("Відкритий текст (TEXT):", msg_B_to_A.decode())

    x = format_message(msg_B_to_A, nA)
    y, parity, jac = Encrypt(x, nA, bA)

    print("Шифротекст:", format(y, "X"))
    print("Parity:", parity)
    print("Jacobi:", jac)

    x_dec = Decrypt(y, parity, jac, nA, bA, pA, qA)
    if x_dec is None:
        print("Розшифрування не вдалося")
    else:
        m_rec = inv_format_message(x_dec)
        print("Розшифровано (HEX):", m_rec.hex().upper())
        print("Розшифровано (TEXT):", m_rec.decode())

    msg_sig_A = b"Doc A"
    print("\nПідпис абонента A")
    print("Повідомлення (HEX):", msg_sig_A.hex().upper())
    print("Повідомлення (TEXT):", msg_sig_A.decode())

    sA, xA = Sign(msg_sig_A, nA, pA, qA)
    print("Підпис s_A:", format(sA, "X"))
    print("Блок x_A:", format(xA, "X"))
    print("Перевірка:", "OK" if Verify(sA, xA, nA) else "FAIL")

    msg_sig_B = b"Doc B"
    print("\n[Підпис абонента B]")
    print("Повідомлення (HEX):", msg_sig_B.hex().upper())
    print("Повідомлення (TEXT):", msg_sig_B.decode())

    sB, xB = Sign(msg_sig_B, nB, pB, qB)
    print("Підпис s_B:", format(sB, "X"))
    print("Блок x_B:", format(xB, "X"))
    print("Перевірка:", "OK" if Verify(sB, xB, nB) else "FAIL")

    print("\n" + "=" * 70)
    print("ГОТОВО — усі значення для звіту згенеровано")
    print("=" * 70)


def rabin_example(bits=256):

    nA, bA, pA, qA = generate_keypair(bits)

    print("Абонент A:")
    print("p_A =", format(pA, "X"))
    print("q_A =", format(qA, "X"))
    print("n_A =", format(nA, "X"))
    print("b_A =", format(bA, "X"))

    nB, bB, pB, qB = generate_keypair(bits)

    print("\nАбонент B:")
    print("p_B =", format(pB, "X"))
    print("q_B =", format(qB, "X"))
    print("n_B =", format(nB, "X"))
    print("b_B =", format(bB, "X"))

    m = b"Hi"
    print("\nВідкритий текст:")
    print("TEXT =", m.decode())
    print("HEX  =", m.hex().upper())

    x = format_message(m, nB)
    y, parity, jac = Encrypt(x, nB, bB)

    print("\nШифрування (A → B):")
    print("Ciphertext =", format(y, "X"))
    print("Parity     =", parity)
    print("Jacobi     =", jac)

    x_dec = Decrypt(y, parity, jac, nB, bB, pB, qB)
    m_dec = inv_format_message(x_dec)

    print("\nРозшифрування:")
    print("HEX  =", m_dec.hex().upper())
    print("TEXT =", m_dec.decode())

    sig, x_sig = Sign(m, nA, pA, qA)

    print("\nЦифровий підпис (A):")
    print("Message =", format(x_sig, "X"))
    print("Signature     =", format(sig, "X"))

    ok = Verify(sig, x_sig, nA)

    print("\nПеревірка підпису:")
    print("VALID =", ok)


# encrypt_for_site()
# keygen_and_decrypt_for_site()
# keygen_and_sign_for_site()
# verify_for_site()
# attack()
rabin_example()
