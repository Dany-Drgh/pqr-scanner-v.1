# should_not_match.py
import hashlib

hashlib.sha256(b"x").hexdigest()
