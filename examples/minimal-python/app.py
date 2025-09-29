import requests
import jwt


def bad_requests():
    requests.get("https://example.com/api", verify=False)


def bad_jwt():
    jwt.encode({"sub": "u"}, "secret", algorithm="RS256")


if __name__ == "__main__":
    bad_requests()
    bad_jwt()
