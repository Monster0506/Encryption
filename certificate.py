import os
from re import S
from typing import List

from Crypto.PublicKey import RSA

import KeyTrust
from main import generate_key_pair, sign
from main import verify as vfy
from utils import PRINT, json, toStr, write_json


def has_sufficient_trust(keys: List[KeyTrust.KeyTrust], level: int = 5):
    """Given a list of TrustedKeys, determine if the list has sufficient trust (sum of at least 5, or at least a 'high' trust level).

    Args:
        keys (List[TrustedKeys]): All of the keys to check.
            Possible trust levels are: "UNTRUSTED", "LOW", "MEDIUM", "HIGH", "AUTHORITY", "OVERRIDE"
        level (int, optional): The level to verify keys add up to. Defaults to 5.
            levels with weights are: UNTRUSTED : -5, LOW : -1, MEDIUM : 1, HIGH : 5, AUTHORITY : 100, OVERRIDE : 1000000000000.


    Returns:
        _type_: _description_
    """
    required = {"UNTRUSTED": -5, "LOW": -1,
                "MEDIUM": 1, "HIGH": 5, "AUTHORITY": 100, "OVERRIDE": 1000000000000}
    total = sum(required[key.level] for key in keys)
    # print(total)
    return total >= level


class Credentials(dict):
    def __init__(self, id, **kwargs):
        super().__init__(id=id, **kwargs)

    def __dict__(self):
        return json.dumps(self)


class Certificate(dict):
    def __init__(
        self,
        public_key: RSA.RsaKey,
        credentials: Credentials,
        key_alg="RSA",
        hash_alg="SHA-512",
        enc_alg="PKCS1_OAEP",
        signature="TEMPORARY",
    ):
        public_key = toStr(public_key.publickey().exportKey())
        key_alg = key_alg.upper()
        enc_alg = enc_alg.upper()
        hash_alg = hash_alg.upper()
        credentials = json.loads(credentials.__dict__())
        signature = str(signature)
        super().__init__(
            public_key=public_key,
            key_alg=key_alg,
            hash_alg=hash_alg,
            enc_alg=enc_alg,
            credentials=credentials,
            signature=signature

        )

    def sign(self, private_key: RSA.RsaKey):
        return sign(str(self.copy()), private_key)

    def verify(self, publicKey: RSA.RsaKey, digest):
        return vfy(str(self.copy()), digest, publicKey)

    def get(self, name):
        names = ["KEY_ALG", "HASH_ALG", "ENC_ALG",
                 "PUBLIC_KEY", "CREDENTIALS", "SIGNATURE"]
        if name.upper() in names:
            return (self[name.lower()])
        else:
            raise KeyError("Invalid key")

    def store(self):
        # print(self)
        return json.loads(json.dumps(self))

    @ staticmethod
    def read(file):
        """Return a new Certificate object from a file stored using the store method.

        Args:
            file (str): The name of the file

        Returns:
            Certificate: The new Certificate object.
        """
        with open(file, "r") as f:
            decoded = json.loads((f.read()).replace("'", '"'))
            public_key = RSA.importKey((decoded.get("public_key")))
            credentials = Credentials(**decoded.get("credentials"))

            digest = (decoded.get("digest")).decode(
                'utf-8') if "digest" in decoded else None

            yield Certificate(public_key, credentials, (decoded.get("key_alg")), (decoded.get("hash_alg")), (decoded.get("enc_alg")), signature=digest)


if __name__ == "__main__" and PRINT:
    pubkey, priv = generate_key_pair()
    creds = Credentials("test", username="test", password="test")
    certif = Certificate(pubkey, creds)
    stored = certif.store()
    write_json(stored, 'certifs.json',)

    certif = list(Certificate.read("certifs.json"))
    for cert in certif:
        # print(cert)
        print(cert.store())
        print(cert.get("KEY_ALG"))
        print(cert.get("HASH_ALG"))
        print(cert.get("ENC_ALG"))
        print(cert.get("PUBLIC_KEY"))
        print(cert.get("CREDENTIALS"))
        signed = cert.sign(priv)
        print(cert.verify(pubkey, signed))
        print(cert)
