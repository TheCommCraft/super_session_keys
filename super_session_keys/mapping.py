"""
Higher level implementation using a mapping.
"""
from __future__ import annotations
from collections.abc import Mapping, Iterator
from threading import Lock
from typing import Union, Optional, assert_never, Never
from .data import CloudKey, set_data, get_data

STANDARD_URL = "https://securesessions.thecommcraft.de/"

class SessionKeysServer(Mapping):
    """
    A server for super session keys.
    """
    _keys : dict
    mapping_id : bytes
    url : str
    lookup_keys : Lock

    def __init__(
        self,
        url : Optional[str] = None,
        *,
        mapping_id : bytes,
        keys : Optional[Mapping[str, CloudKey]] = None
    ):
        self._keys = dict(keys or {})
        self.mapping_id = mapping_id
        self.url = url or STANDARD_URL
        self.lookup_keys = Lock()

    def _get_key(self, key_name : str):
        """
        Lookup or create a key for a key name.
        """
        with self.lookup_keys:
            if key_name not in self._keys:
                key_origin = key_name.encode("utf-8") + b" <= " + self.mapping_id
                self._keys[key_name] = CloudKey.generate(key_origin)
            return self._keys[key_name]

    def __len__(self) -> int:
        with self.lookup_keys:
            return len(self._keys)

    def __getitem__(self, item : Union[str, CloudKey, bytes, Never]) -> str:
        match item:
            case bytes():
                key = CloudKey.from_bytes(item)
            case str():
                key = self._get_key(item)
            case CloudKey():
                key = item
            case _:
                assert_never(type(item))
        return get_data(key, self.url)

    def __setitem__(self, item : Union[str, CloudKey, bytes, Never], value : str) -> None:
        match item:
            case bytes():
                key = CloudKey.from_bytes(item)
            case str():
                key = self._get_key(item)
            case CloudKey():
                key = item
            case _:
                assert_never(type(item))
        set_data(key, value, self.url)

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)
