from typing import List, Tuple

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA, SHA256, SHA384, SHA512
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from utils import toBytes

global hashFunction
hashFunction = "SHA-256"


def _split_private_key(
    private_key: RSA, nShares: int
) -> Tuple[List[Tuple[int, bytes]], bytes, bytes, bytes]:
    key = Random.new().read(16)
    shares = Shamir.split(k=nShares, n=nShares, secret=key)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    enc, tag = cipher.encrypt_and_digest(private_key)
    return shares, enc, nonce, tag


def _combine_split_key(shares, enc, nonce, tag, passphrase=None):
    key = Shamir.combine(shares)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return RSA.importKey(cipher.decrypt_and_verify(enc, tag), passphrase)


def _newkeys(keysize=1024, e=65537, rand_func=None):
    if rand_func is None:
        rand_func = Random.new().read
    key = RSA.generate(keysize, rand_func, e)
    private, public = key, key.publickey()
    return public, private


def _importKey(externKey, passphrase=None):
    with open(externKey, "rb") as f:
        return _import_key(f.read(), passphrase)


def _import_key(key, passphrase=None):
    return RSA.importKey(key, passphrase)


def _getpublickey(priv_key):
    return priv_key.publickey()


def _exportKey(key, filename, passphrase=None):
    with open(filename, "wb") as f:
        f.write(key.exportKey("PEM", passphrase))
    return key.exportKey("PEM", passphrase)


def _getAlg(hashAlg):
    hashFunction = hashAlg
    if hashFunction == "SHA-512":
        return SHA512.new()
    elif hashFunction == "SHA-384":
        return SHA384.new()
    elif hashFunction == "MD5":
        return MD5.new()
    elif hashFunction == "SHA-1":
        return SHA.new()
    else:
        return SHA256.new()


def _sign(message, priv_key, hashAlg="SHA-256"):
    global hashFunction
    message = toBytes(message)
    hashFunction = hashAlg
    signer = PKCS1_v1_5.new(priv_key)
    digest = _getAlg(hashFunction)
    digest.update(message)
    return signer.sign(digest)


def _verify(message, signature, pub_key):
    message = toBytes(message)
    verifier = PKCS1_v1_5.new(pub_key)
    digest = _getAlg(hashFunction)
    digest.update(message)
    return verifier.verify(digest, signature)
