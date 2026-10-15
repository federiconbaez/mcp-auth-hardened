"""RS256 (RSASSA-PKCS1-v1_5 + SHA-256) by hand: big-int modular exponentiation, Miller-Rabin keygen, EMSA-PKCS1-v1_5.

NEW code for mcp-auth-hardened. Python's built-in ``pow(a, b, n)`` provides the big-integer modular exponentiation; everything
else (prime generation, padding, DigestInfo, verification, DER/PEM export of the public key) is written here.

Safety choices:
  * verification re-encodes the expected EMSA block and compares the FULL block in constant time, so there is no ASN.1 parsing of
    attacker-controlled padding (no Bleichenbacher-style low-exponent forgeries);
  * the signature integer must be < n and exactly k bytes long;
  * sign() uses no blinding and no CRT-fault protection: this signer is for tests/demos and the mock issuer, not for hostile hosts.
"""

import base64
import hashlib
import hmac
import secrets

# DER prefix of DigestInfo for SHA-256 (RFC 8017 section 9.2, note 1)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
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


def _gen_prime(bits):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1  # top two bits set => n has full length
        if _is_probable_prime(cand):
            return cand


def generate_key(bits=2048, e=65537):
    """Return {"n", "e", "d"} (ints). bits must be >= 512 and a multiple of 16 (tests use 1024; production-ish default is 2048)."""
    if bits < 512 or bits % 16:
        raise ValueError("bits must be >= 512 and a multiple of 16")
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        return {"n": n, "e": e, "d": pow(e, -1, phi)}


def _k(n):
    return (n.bit_length() + 7) // 8


def emsa_pkcs1_v15(message, k):
    digest = hashlib.sha256(message).digest()
    t = SHA256_PREFIX + digest
    if k < len(t) + 11:
        raise ValueError("modulus too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign(message, n, d):
    k = _k(n)
    em = emsa_pkcs1_v15(message, k)
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def verify(message, signature, n, e):
    """True iff ``signature`` is a valid RSASSA-PKCS1-v1_5/SHA-256 signature of ``message`` under (n, e)."""
    k = _k(n)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n or e < 3 or e % 2 == 0:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    try:
        expected = emsa_pkcs1_v15(message, k)
    except ValueError:
        return False
    return hmac.compare_digest(em, expected)


# ---- minimal DER encoding so the public key can be handed to `openssl` (cross-check) -------------------------
def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")  # leading 0x00 when the top bit is set
    return _der(0x02, b)


def public_key_pem(n, e):
    """SubjectPublicKeyInfo PEM (RFC 5280 / 8017 A.1.1)."""
    rsa_pub = _der(0x30, _der_int(n) + _der_int(e))
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + bytes.fromhex("0500"))
    spki = _der(0x30, alg + _der(0x03, b"\x00" + rsa_pub))
    b64 = base64.encodebytes(spki).decode("ascii").replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def int_to_b64u(v):
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
