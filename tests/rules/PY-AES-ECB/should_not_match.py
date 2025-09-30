# should_not_match.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

a = AESGCM(b"0" * 32)
