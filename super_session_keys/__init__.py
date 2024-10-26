"""
Save a little bit of data online secretly.
"""

from . import mapping, data
from .mapping import SessionKeysServer
from .data import CloudKey

generate_key = CloudKey.generate
