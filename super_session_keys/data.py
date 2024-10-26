"""
Controls data directly on a server/url with a key.
"""
from __future__ import annotations
from hashlib import sha3_512, sha3_256
from base64 import urlsafe_b64encode, urlsafe_b64decode
from contextlib import contextmanager
from threading import local
from typing import Any, Optional, Self
from collections.abc import Iterator
import json
from attrs import define, field
from cryptography.fernet import Fernet, InvalidToken
import requests

thread_data = local()

def get_local_data(name : str, default : Any = None):
    """
    Get an attribute of `thread_data`.
    """
    return getattr(thread_data, name, default)

STANDARD_URL = "https://securesessions.thecommcraft.de/"

b64encode = urlsafe_b64encode
b64decode = urlsafe_b64decode

@define
class CloudKey:
    """
    Representation of a cloud key.
    """
    key_data : bytes = field(kw_only=True, repr=False)
    _key : Optional[Fernet] = field(init=False, default=None, repr=False)
    data_id : bytes = field(kw_only=True, repr=True)
    auth_key : bytes = field(kw_only=True, repr=False)

    @property
    def key(self):
        """
        The corresponding Fernet key.
        """
        if self._key is None:
            self._key = Fernet(self.key_data)
        return self._key

    def to_bytes(self) -> bytes:
        """
        Convert to a bytes representation.
        """
        key_data = {
            "key_data": b64encode(self.key_data).decode("utf-8"),
            "data_id": b64encode(self.data_id).decode("utf-8"),
            "auth_key": b64encode(self.auth_key).decode("utf-8"),
            "data_type": "keyv1"
        }
        return b64encode(json.dumps(key_data).encode("utf-8"))

    @property
    def attributes(self) -> tuple[bytes, Fernet, bytes, bytes]:
        """
        Return the attributes of the key in order.
        """
        return (self.key_data, self.key, self.data_id, self.auth_key)

    @classmethod
    def from_bytes(cls : type[Self], key : bytes) -> Self:
        """
        Load a key from the bytes representation.
        """
        key_data = json.loads(b64decode(key))
        assert key_data["data_type"] == "keyv1"
        return cls(
            key_data=(key := b64decode(key_data["key_data"].encode("utf-8"))),
            data_id=b64decode(key_data["data_id"].encode("utf-8")),
            auth_key=b64decode(key_data["auth_key"].encode("utf-8"))
        )

    @classmethod
    def generate(cls : type[Self], data : Optional[bytes] = None) -> Self:
        """
        Generate a new Cloud Key.
        """
        key_data, data_id, auth_key = _gen_data() if data is None else _gen_data_from(data)
        return cls(key_data=key_data, data_id=data_id, auth_key=auth_key)

def _encrypt_data(data : str, key : Fernet) -> bytes:
    """
    Encrypt data with a key.
    """
    return key.encrypt(data.encode("utf-8"))

def _decrypt_data(data : bytes, key : Fernet) -> str:
    """
    Decrypt data with a key.
    """
    return key.decrypt(data).decode("utf-8")

def _gen_data_from(data : bytes) -> tuple[bytes, bytes, bytes]:
    """
    Generate key data from data.
    """
    key_data = b64encode(sha3_256(data).digest())
    hashed_key = sha3_512(key_data).digest()
    data_id = hashed_key[:16]
    auth_key = hashed_key[16:]
    return key_data, data_id, auth_key

def _gen_data() -> tuple[bytes, bytes, bytes]:
    """
    Generate key data.
    """
    key_data = Fernet.generate_key()
    hashed_key = sha3_512(key_data).digest()
    data_id = hashed_key[:16]
    auth_key = hashed_key[16:]
    return key_data, data_id, auth_key

def _set_data(
    data_id : bytes, data : str,
    auth_key : bytes,
    key : Fernet,
    url : Optional[str] = None
) -> bool:
    """
    Set a piece of data with the key data.
    """
    url = url or _get_url()
    encrypted_data = _encrypt_data(data, key)
    request_data = {
        "data_id": b64encode(data_id).decode("utf-8"),
        "auth_key": b64encode(auth_key).decode("utf-8"),
        "data": b64encode(encrypted_data).decode("utf-8"),
    }
    return requests.post(url, timeout=5, json=request_data).json()["success"]

def _get_data(data_id : bytes, key : Fernet, url : Optional[str] = None) -> str:
    """
    Get a piece of data with the key data.
    """
    url = url or _get_url()
    request_data = {"data_id": b64encode(data_id).decode("utf-8")}
    data = requests.get(url, timeout=5, json=request_data).json().get("data").encode("utf-8")
    try:
        return _decrypt_data(b64decode(data), key)
    except InvalidToken:
        raise KeyError("Key doesn't exist.") from None

def _get_url() -> str:
    """
    Get the current url
    """
    return get_local_data("current_url", "https://securesessions.thecommcraft.de/")

def _set_url(url : str) -> str:
    """
    Set the current url
    """
    previous_url = _get_url()
    thread_data.current_url = url
    return previous_url

def set_data(key : CloudKey, data : str, url : Optional[str] = None) -> bool:
    """
    Set the corresponding data of a key.
    """
    url = url or _get_url()
    _, fkey, data_id, auth_key = key.attributes
    return _set_data(data_id, data, auth_key, fkey, url)

def get_data(key : CloudKey, url : Optional[str] = None) -> str:
    """
    Get the corresponding data of a key.
    """
    url = url or _get_url()
    _, fkey, data_id, _ = key.attributes
    return _get_data(data_id, fkey, url)

@contextmanager
def using_url(url : str) -> Iterator[None]:
    """
    Use a url.
    """
    previous_url = _set_url(url)
    try:
        yield
    finally:
        _set_url(previous_url)
