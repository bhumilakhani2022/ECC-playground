# ECC Math Engine
# Supports Weierstrass curves: y^2 = x^3 + ax + b (mod p)

from typing import Tuple, Optional
import random
import hashlib

Point = Optional[Tuple[int, int]]  # None represents the point at infinity

def modinv(a: int, p: int) -> int:
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

def point_add(P: Point, Q: Point, a: int, p: int) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        return point_double(P, a, p)
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
    N = P
    Q = P  # Start with the base point
    steps = [(0, "start", P)] if return_steps else []
    bits = bin(k)[2:]  # Convert k to binary
    
    for i, bit in enumerate(bits):
        # Double in each iteration
        if i > 0:  # Don't double in first iteration
            prev = Q
            Q = point_double(Q, a, p)
            if return_steps:
                steps.append((i, "double", Q, prev))
        
        # Add if bit is 1
        if bit == '1' and i > 0:  # Skip first 1 as we already have P
            prev = Q
            Q = point_add(Q, N, a, p)
            if return_steps:
                steps.append((i, "add", Q, prev))

    if return_steps:
        return Q, steps
    else:
        return Q


def get_public_key(private_key: int, generator: Point, a: int, p: int) -> Point:
    return scalar_mult(private_key, generator, a, p)

def ecdh_shared_secret(private_key: int, other_public_key: Point, a: int, p: int) -> Point:
    return scalar_mult(private_key, other_public_key, a, p)

def ecdsa_sign(message: bytes, private_key: int, generator: Point, a: int, p: int, n: int) -> Tuple[int, int]:
    z = int(hashlib.sha256(message).hexdigest(), 16)
    while True:
        k = random.randrange(1, n)
        x, _ = scalar_mult(k, generator, a, p)
        r = x % n
        if r == 0:
            continue
        k_inv = modinv(k, n)
        s = (k_inv * (z + r * private_key)) % n
        if s == 0:
            continue
        return (r, s)

def ecdsa_verify(message: bytes, signature: Tuple[int, int], public_key: Point, generator: Point, a: int, p: int, n: int) -> bool:
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int(hashlib.sha256(message).hexdigest(), 16)
    s_inv = modinv(s, n)
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n
    P = point_add(
        scalar_mult(u1, generator, a, p),
        scalar_mult(u2, public_key, a, p),
        a, p
    )
    if P is None:
        return False
    x, _ = P
    return (x % n) == r

def compress_point(P: Point) -> Optional[Tuple[int, int]]:
    if P is None:
        return None
    x, y = P
    prefix = 2 + (y % 2)  # 0x02 if y is even, 0x03 if y is odd
    return (prefix, x)

def decompress_point(comp: Tuple[int, int], a: int, b: int, p: int) -> Point:
    prefix, x = comp
    y_squared = (x ** 3 + a * x + b) % p
    
    # Find a modular square root.
    if p % 4 == 3:
        y = pow(y_squared, (p + 1) // 4, p)
    else:
        # Simple search for other cases (like Toy Curve p=17 where p%4==1)
        # Inefficient for large primes, but works for the demo.
        y_candidate = -1
        for i in range(p):
            if (i * i) % p == y_squared:
                y_candidate = i
                break
        if y_candidate == -1:
            # This means y_squared is not a quadratic residue, so the point is invalid.
            raise ValueError("Point cannot be decompressed: no modular square root.")
        y = y_candidate

    # The prefix (2 for even, 3 for odd) determines which root to use.
    if (y % 2) != (prefix - 2):
        y = p - y

    # Final check to ensure the point is valid.
    if (y * y) % p != y_squared:
         raise ValueError("Decompressed point is not on the curve.")

    return (x, y)
