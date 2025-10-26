import hmac, hashlib, base64

def hmac_signature(api_key: str, payload: bytes) -> str:
    sig = hmac.new(api_key.encode(), payload, hashlib.sha256).digest()
    return "v1=" + base64.b64encode(sig).decode()
