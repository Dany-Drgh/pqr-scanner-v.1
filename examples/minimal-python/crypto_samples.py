import hashlib
from cryptography.hazmat.primitives.ciphers import modes


def weak_hash():
    return hashlib.md5(b"abc").hexdigest()


def ecb_demo():
    m = modes.ECB()
    return m
