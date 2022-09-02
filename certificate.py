import csv
import os
from typing import List

from Crypto.PublicKey import RSA

import KeyTrust
from keys import _import_key
from main import generate_key_pair, public_key, sign
from main import verify as vfy
from utils import PRINT, json, toBytes, toStr, write_json


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
    def __init__(self, id,  **kwargs):
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
        self.__dict__ = {
            "public_key": public_key,
            "key_alg": key_alg,
            "hash_alg": hash_alg,
            "enc_alg": enc_alg,
            "credentials": credentials,
            "signature": signature

        }

    def sign(self, private_key: RSA.RsaKey):
        return sign(str(self.copy()), private_key)

    def verify(self, publicKey: RSA.RsaKey, digest):
        return vfy(str(self.copy()), digest, publicKey)

    def __str__(self) -> str:
        return str(self.__dict__)

    def get(self, name):
        names = ["KEY_ALG", "HASH_ALG", "ENC_ALG",
                 "PUBLIC_KEY", "CREDENTIALS", "SIGNATURE"]
        if name.upper() in names:
            return (self.__dict__[name.lower()])
        else:
            raise KeyError("Invalid key")

    def store(self, filename):
        # print(self)
        with open(filename, "a") as f:
            writer = csv.DictWriter(f, fieldnames=self.__dict__.keys())
            if os.stat(filename).st_size == 0:
                writer.writeheader()
            writer.writerow(self.__dict__)

    @ staticmethod
    def read(file):
        """Return a new Certificate object from a file stored using the store method.

        Args:
            file (str): The name of the file

        Returns:
            Certificate: The new Certificate object.
        """
        with open(file, 'r') as f:
            reader = csv.DictReader(f)
            line_num = 0
            for row in reader:
                if line_num == 0:
                    line_num += 1
                public_key = _import_key(toBytes(row["public_key"]))
                key_alg = row["key_alg"]
                hash_alg = row["hash_alg"]
                enc_alg = row["enc_alg"]
                signature = row["signature"]
                credentials = row["credentials"]

                creds = Credentials(credentials)
                yield Certificate(public_key, creds, key_alg, hash_alg, enc_alg, signature)

                line_num += 1


if __name__ == "__main__" and PRINT:
    pubkey, priv = generate_key_pair()
    creds = Credentials(id="test", username="test", password="test")
    certif = Certificate(pubkey, creds)
    certif.store("certificate.csv")

    certif = list(Certificate.read("certificate.csv"))
    keys = ["KEY_ALG", "HASH_ALG", "ENC_ALG",
            "PUBLIC_KEY", "CREDENTIALS", "SIGNATURE"]
    for cert in certif:
        for key in keys:
            print(f'{key}: {cert.get(key)}')
        signed = cert.sign(priv)
        print(cert.verify(pubkey, signed))
        print(cert.get("SIGNATURE"))
