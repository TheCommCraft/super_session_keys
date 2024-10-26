from cryptography.fernet import Fernet
import os, requests, json
from cachetools import LRUCache
from hashlib import sha3_512, sha3_256
from base64 import urlsafe_b64encode, urlsafe_b64decode
from contextlib import contextmanager

b64encode = urlsafe_b64encode
b64decode = urlsafe_b64decode

def _encrypt_data(data : str, key : Fernet) -> bytes:
    return key.encrypt(data.encode("utf-8"))

def _decrypt_data(data : bytes, key : Fernet) -> str:
    return key.decrypt(data).decode("utf-8")

def _gen_data_from(data : bytes) -> tuple[bytes, Fernet, bytes, bytes]:
    key_data = b64encode(sha3_256(data))
    key = Fernet(key_data)
    hashed_key = sha3_512(key_data).digest()
    data_id = hashed_key[:16]
    auth_key = hashed_key[16:]
    return key_data, key, data_id, auth_key

def _gen_data() -> tuple[bytes, Fernet, bytes, bytes]:
    key_data = Fernet.generate_key()
    key = Fernet(key_data)
    hashed_key = sha3_512(key_data).digest()
    data_id = hashed_key[:16]
    auth_key = hashed_key[16:]
    return key_data, key, data_id, auth_key

URL = "https://securesessions.thecommcraft.de/"

def _set_data(data_id : bytes, data : str, auth_key : bytes, key : Fernet) -> bool:
    encrypted_data = _encrypt_data(data, key)
    request_data = {
        "data_id": b64encode(data_id).decode("utf-8"),
        "auth_key": b64encode(auth_key).decode("utf-8"),
        "data": b64encode(encrypted_data).decode("utf-8"),
    }
    return requests.post(URL, timeout=5, json=request_data).json()["success"]

def _get_data(data_id : bytes, key : Fernet) -> str:
    return _decrypt_data(b64decode(requests.get(URL, json={"data_id": b64encode(data_id).decode("utf-8")}).json().get("data").encode("utf-8")), key)

def create_key() -> bytes:
    key_data, key, data_id, auth_key = _gen_data()
    key_data = {"key_data": b64encode(key_data).decode("utf-8"), "data_id": b64encode(data_id).decode("utf-8"), "auth_key": b64encode(auth_key).decode("utf-8"), "data_type": "keyv1"}
    return b64encode(json.dumps(key_data).encode("utf-8"))

def _load_key(key : bytes) -> tuple[bytes, Fernet, bytes, bytes]:
    key_data = json.loads(b64decode(key))
    assert key_data["data_type"] == "keyv1"
    return (key := b64decode(key_data["key_data"].encode("utf-8"))), Fernet(key), b64decode(key_data["data_id"].encode("utf-8")), b64decode(key_data["auth_key"].encode("utf-8"))

def set_data(key : bytes, data : str) -> bool:
    key_data, key, data_id, auth_key = _load_key(key)
    return _set_data(data_id, data, auth_key, key)

def _set_url(url : str):
    global URL
    URL = url

def _get_url() -> str:
    return URL

def get_data(key : bytes) -> str:
    key_data, key, data_id, auth_key = _load_key(key)
    return _get_data(data_id, key)
    
@contextmanager
def use_url(url):
    previous_url = _get_url()
    try:
        yield
    finally:
        _set_url(previous_url)
