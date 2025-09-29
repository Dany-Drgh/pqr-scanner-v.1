import ssl


def old_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx
