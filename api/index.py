from flask import Flask, request, jsonify, redirect
import os, sys, pickle, random, hmac
from cachetools import LRUCache
from base64 import b64encode, b64decode
app = Flask(__name__)

data_dictionary = LRUCache(2048 * 8096, sys.getsizeof)

def is_allowed(data_id, auth_key, data):
    if sys.getsizeof(data) > 1024:
        return False
    if (not isinstance(data_id, bytes)) or len(data_id) > 64:
        return False
    if (not isinstance(auth_key, bytes)) or len(auth_key) > 512:
        return False
    return True

def decode_data(data):
    return pickle.loads(data)

def encode_data(data):
    return pickle.dumps(data)

def insert_new_data(data_id, auth_key, data):
    if not is_allowed(data_id, auth_key, data):
        return False
    if data_id in data_dictionary:
        return False
    data_dictionary[data_id] = encode_data({"data_id": data_id, "auth_key": auth_key, "data": data})
    return True

def all_data(data_id):
    if data_id not in data_dictionary:
        insert_new_data(data_id, os.urandom(16), os.urandom(random.randrange(256, 512)))
    data = data_dictionary.get(data_id)
    return decode_data(data)

def data_from_id(data_id):
    return all_data(data_id).get("data")

def update_data(data_id, auth_key, data):
    old_data = all_data(data_id)
    if not is_allowed(data_id, auth_key, data):
        return False
    if not hmac.compare_digest(auth_key, old_data.get("auth_key", os.urandom(16))):
        return False
    data_dictionary[data_id] = encode_data({"data_id": data_id, "auth_key": auth_key, "data": data})
    return True

def post_data(data_id, auth_key, data):
    if data_id in data_dictionary:
        return update_data(data_id, auth_key, data)
    return insert_new_data(data_id, auth_key, data)

def get_data(data_id):
    return data_from_id(data_id)


@app.get("/")
def retrieve_data():
    try:
        data = request.json
        data = {key: b64decode(value.encode("utf-8")) for key, value in data.items()}
    except Exception:
        if request.args.get("key") and hmac.compare_digest(request.args.get("key"), os.getenv("accesskey")):
            return jsonify({**data_dictionary})
        return redirect("https://github.com/TheCommCraft/super_session_keys/")
    data_id = data["data_id"]
    return jsonify({"data": b64encode(get_data(data_id)).decode("utf-8")})

@app.post("/")
def set_data():
    data = request.json
    data = {key: b64decode(value.encode("utf-8")) for key, value in data.items()}
    data_id = data["data_id"]
    auth_key = data["auth_key"]
    data = data["data"]
    return jsonify({"success": post_data(data_id, auth_key, data)})
