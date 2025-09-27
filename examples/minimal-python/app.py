import requests

def bad():
    requests.get("https://example.com/api", verify=False)

if __name__ == "__main__":
    bad()
