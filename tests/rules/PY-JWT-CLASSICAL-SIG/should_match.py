# should_match.py
import jwt

jwt.encode({"sub": "u"}, "k", algorithm="RS256")
