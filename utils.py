
import os
from zlib import compress, decompress

from Crypto.Util.py3compat import tobytes, tostr

try:
    import simplejson as json  # type: ignore
except ImportError:
    import json

PRINT = True


def toStr(data):
    return tostr(data)


def toBytes(data):
    return tobytes(data)


def pad(message: bytes, length: int = 16):
    """Pad or unpad a message to the nearest multiple of the given length."""
    return message + bytes([length - len(message) % length]) * (
        length - len(message) % length
    )


def unpad(message: bytes):
    return message[: -message[-1]]


def _zip(data):
    data = tobytes(data)
    data = pad(data)
    return compress(data)


def _unzip(data):
    data = tobytes(data)
    data = decompress(data)
    return unpad(data)


def write_json(new_data, filename='data.json'):
    try:
        if os.stat(filename).st_size == 0:
            with open(filename, 'w') as f:
                json.dump(new_data, f)
        else:
            with open(filename, 'r+') as file:
                filedata = json.load(file)
                data = filedata.update(new_data)
                print(data)
                return json.dump(data, file, indent=4)
    except FileNotFoundError:
        with open(filename, 'w') as file:
            json.dump(new_data, file, indent=4)
