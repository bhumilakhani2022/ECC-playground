import os
import hashlib
from ecc_math import scalar_mult, get_public_key, compress_point, decompress_point
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def kdf(shared_secret: int, key_len: int = 32) -> bytes:
    """Derive a symmetric key from shared secret using SHA-256."""
    return hashlib.sha256(str(shared_secret).encode()).digest()[:key_len]

def ecies_encrypt(msg: bytes, pub_key, G, a, p, n) -> dict:
    """Encrypt a message using ECIES (returns dict with ephemeral pubkey, ciphertext, iv)."""
    # Generate ephemeral key pair
    eph_priv = int.from_bytes(os.urandom(32), 'big') % n
    eph_pub = get_public_key(eph_priv, G, a, p)
    # Derive shared secret
    shared = scalar_mult(eph_priv, pub_key, a, p)
    if shared is None:
        raise ValueError("Invalid shared secret")
    key = kdf(shared[0])
    # Encrypt message with AES
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return {
        'ephemeral_pub': compress_point(eph_pub),
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex()
    }

def ecies_decrypt(enc_dict, priv_key, G, a, b, p, n) -> bytes:
    """Decrypt a message using ECIES (input dict from ecies_encrypt)."""
    eph_pub = decompress_point(enc_dict['ephemeral_pub'], a, b, p)
    shared = scalar_mult(priv_key, eph_pub, a, p)
    if shared is None:
        raise ValueError("Invalid shared secret")
    key = kdf(shared[0])
    iv = bytes.fromhex(enc_dict['iv'])
    ciphertext = bytes.fromhex(enc_dict['ciphertext'])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    msg = unpadder.update(padded_msg) + unpadder.finalize()
    return msg 