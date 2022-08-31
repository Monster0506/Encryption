import csv
import os

from Crypto.PublicKey import RSA

import KeyTrust
from certificate import Certificate, Credentials
from keys import _import_key
from main import import_key
from utils import PRINT, toStr


class KeyRing():
    """
    Takes:
        public key,
        trust level,
        user credentials
    Returns KeyRing -> Certificate, TrustLevel
    """

    def __init__(self, public_key: RSA.RsaKey, trust_level: KeyTrust.KeyTrust, user_credentials: Credentials):
        self.public_key: RSA.RsaKey = public_key
        self.trust_level = trust_level.level
        self.user_credentials = user_credentials
        private_key = RSA.import_key(
            open('private.pem', 'rb').read(), passphrase='TOPSECRETPASSWORD')
        self.certificate = Certificate(self.public_key, self.user_credentials)
        signature = self.certificate.sign(private_key)
        self.signer = signature
        self.__dict__ = {"public_key": toStr(self.public_key.export_key()), "trust_level": self.trust_level,
                         "user_credentials": self.user_credentials, "signature": self.signer}

    def store(self, filename):
        with open(filename, 'a') as f:
            fieldnames = self.__dict__.keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if os.stat(filename).st_size == 0:
                writer.writeheader()
            writer.writerow(self.__dict__)

    @staticmethod
    def read(filename):
        """Return a new KeyRing object from a file stored using the store method.

        Args:
            file (str): The name of the file

        Returns:
            KeyRing: The new KeyRing object.
        """
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            line_num = 0
            for row in reader:
                if line_num == 0:
                    line_num += 1
                line_num += 1
                yield KeyRing(_import_key(row["public_key"]), KeyTrust.new(_import_key(row["public_key"]), row["trust_level"]), Credentials(row["user_credentials"]))


if __name__ == "__main__" and PRINT:
    keyring = KeyRing(import_key('public.pem'), KeyTrust.new(import_key(
        'public.pem'), KeyTrust.LEVEL_HIGH), Credentials('admin', email='admin'))
    keyring.store('keyring.csv')
    kr2 = KeyRing.read('keyring.csv')
    for key in kr2:
        print(_import_key(key.public_key))
