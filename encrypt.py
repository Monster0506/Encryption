from Crypto.Cipher import PKCS1_OAEP

from utils import _unzip, _zip, tobytes

global hashFunc
hashFunc = "SHA-256"


def _encrypt(message, pub_key):
    message = _zip(tobytes(message))
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


def _decrypt(ciphertext, priv_key) -> bytes:
    # RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return _unzip(cipher.decrypt(ciphertext))
