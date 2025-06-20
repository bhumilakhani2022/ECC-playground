print("ecc_math.py loaded")
# ECC Math Engine
# Supports Weierstrass curves: y^2 = x^3 + ax + b (mod p)

from typing import Tuple, Optional
import hashlib
import random

Point = Optional[Tuple[int, int]]  # None represents the point at infinity

def modinv(a: int, p: int) -> int:
    # Modular inverse using extended Euclidean algorithm
    if a == 0:
        raise ZeroDivisionError('division by zero')
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def is_on_curve(point: Point, a: int, b: int, p: int) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + a * x + b)) % p == 0

print("is_on_curve defined")

def point_add(P: Point, Q: Point, a: int, p: int) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # Point at infinity
    if P == Q:
        return point_double(P, a, p)
    # Slope
    m = ((y2 - y1) * modinv(x2 - x1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P: Point, a: int, p: int) -> Point:
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None
    m = ((3 * x * x + a) * modinv(2 * y, p)) % p
    x3 = (m * m - 2 * x) % p
    y3 = (m * (x - x3) - y) % p
    return (x3, y3)

def scalar_mult(k: int, P: Point, a: int, p: int, return_steps: bool = False):
    # Standard left-to-right double-and-add algorithm
    Q = None  # Point at infinity
    steps = []
    for bit in bin(k)[2:]:
        if Q is not None:
            Q = point_double(Q, a, p)
            if return_steps:
                steps.append((Q, f"Double: {Q}"))
        if bit == '1':
            Q = point_add(Q, P, a, p)
            if return_steps:
                steps.append((Q, f"Add: {Q}"))
    if return_steps:
        return Q, steps
    return Q

print("scalar_mult defined")

def get_public_key(priv_key: int, G: Point, a: int, p: int) -> Point:
    """Compute public key from private key (ECDH/ECDSA)."""
    return scalar_mult(priv_key, G, a, p)


def ecdh_shared_secret(priv_key: int, other_pub: Point, a: int, p: int) -> Point:
    """Compute ECDH shared secret: priv_key * other_pub."""
    return scalar_mult(priv_key, other_pub, a, p)


def ecdsa_sign(msg: bytes, priv_key: int, G: Point, a: int, p: int, n: int) -> Tuple[int, int]:
    """Sign a message using ECDSA. Returns (r, s)."""
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    while True:
        k = random.randrange(1, n)
        R = scalar_mult(k, G, a, p)
        if R is None:
            continue
        r = R[0] % n
        if r == 0:
            continue
        try:
            k_inv = modinv(k, n)
        except ZeroDivisionError:
            continue
        s = (k_inv * (z + r * priv_key)) % n
        if s == 0:
            continue
        return (r, s)


def ecdsa_verify(msg: bytes, signature: Tuple[int, int], pub_key: Point, G: Point, a: int, p: int, n: int) -> bool:
    """Verify an ECDSA signature (r, s) for a message and public key."""
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    # Check that the public key is on the curve
    if not is_on_curve(pub_key, a, b=G[1]**2 - (G[0]**3 + a*G[0]), p=p):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    try:
        s_inv = modinv(s, n)
    except ZeroDivisionError:
        return False
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n
    P1 = scalar_mult(u1, G, a, p)
    P2 = scalar_mult(u2, pub_key, a, p)
    if P1 is None and P2 is None:
        return False
    R = point_add(P1, P2, a, p)
    if R is None:
        return False
    xR = R[0]
    # Always compare modulo n, and ensure both are positive
    return (xR % n) == (r % n)

def compress_point(P: Point) -> tuple:
    """Compress an ECC point (x, y) to (x, ybit) where ybit is 0 or 1."""
    if P is None:
        return None
    x, y = P
    return (x, y % 2)

def decompress_point(x: int, ybit: int, a: int, b: int, p: int) -> Point:
    """Decompress a point from (x, ybit) to (x, y) on the curve y^2 = x^3 + ax + b mod p."""
    rhs = (x**3 + a*x + b) % p
    # Find y such that y^2 = rhs mod p
    for y in range(p):
        if (y*y) % p == rhs and (y % 2) == ybit:
            return (x, y)
    return None  # No valid y found