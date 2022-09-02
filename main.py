import base64 as b64

from Crypto.PublicKey import RSA

import encrypt as rsa
import keys as rsa_key
from utils import PRINT


public_key_file = "public.pem"
private_key_file = "private.pem"


def public_key(private_key: RSA.RsaKey):
    """Get the public key of a private key.
    Args:
        private_key (RsaKey): The private key to get the public key of.
    Returns:
        RsaKey: The public key of the private key."""

    return rsa_key._getpublickey(private_key)


def decrypt(ciphertext: bytes, private_key: RSA.RsaKey):
    """Decrypt a message with a private key.
    The sender can use the 'encrypt' function to encrypt a message, using their public key.
    Args:
        ciphertext (bytes): The message to decrypt.
        private_key (RsaKey): The private key of the sender of the message.

    Returns:
        bytes: The decrypted message.
    """
    return rsa._decrypt(b64.b64decode(ciphertext), private_key)


def encrypt(message, recipient_key: RSA.RsaKey):
    """Encrypt a message with a public key.
    The recipient can use the 'decrypt' function to decrypt the message, using their private key.

    Args:
        message (any 'tobytes'able): The message to encrypt.
        recipient_key (RsaKey): The public key of the recipient of the message.

    Returns:
        bytes: The encrypted message.
    """
    return b64.b64encode(rsa._encrypt(message, recipient_key))


def export_key(key: RSA.RsaKey, filename: str, passphrase=None):
    """Export a key to a file.
    Args:
        key (RsaKey): The key to export.
        filename (str): The name of the file to export the key to.
    """
    return rsa_key._exportKey(key, filename, passphrase)


def import_key(filename: str, passphrase=None):
    """Import a key from a file.

    Args:
        filename (str): The name of the file to import the key from.
        passphrase (str, optional): The encryption passphrase the key was stored with. Defaults to None.

    Returns:
        RsaKey: The imported key.
    """
    return rsa_key._importKey(filename, passphrase)


def sign(message, private_key: RSA.RsaKey, hashAlg: str = "SHA-512"):
    """Sign a message with a private key.

    Args:
        message (any 'tobytes'able): The message to sign.
        private_key (RsaKey): The private key to use for signing.
        hashAlg (str, optional): The hashing algorithm to use for hashing. Defaults to "SHA-512".
            Options are "SHA-512", "SHA-384", "SHA-256", "SHA-1", and "MD5".
            Please compare these choices as you see fit.

    Returns:
        bytes: The signature of the message.
    """
    return rsa_key._sign(message, private_key, hashAlg=hashAlg)


def verify(msg, signature, public):
    """Verify a signature, given the original text, and the public key corresponding to the private key that signed the message.
    Args:
        msg (any 'tobytes'able): The original message.
        signature (bytes): The signature to verify.
        public (RsaKey): The public key of the private key that signed the message.
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    return rsa_key._verify(msg, signature, public)


def generate_key_pair(keysize: int = 1024):
    """Generate a linked pair of RSA keys.
    See  https://en.wikipedia.org/wiki/RSA_(cryptosystem) for more information.

    Args:
        keysize (int): The size of the key to generate. Defaults to 1024.

    Returns:
        Tuple: (public_key: RsaKey, private_key: RsaKey)
    """
    return rsa_key._newkeys(keysize)


def share_key(key, nShares=3):
    return rsa_key._split_private_key(key, nShares)


def combine_shares(share, enc, nonce, tag, passphrase=None):
    return rsa_key._combine_split_key(share, enc, nonce, tag, passphrase)


if __name__ == "__main__" and PRINT:
    msg1 = b"Hello Tony, I am Jarvis!"
    msg2 = b"Hello Tony, I am Toni!"
    keysize = 2048
    public, private = generate_key_pair(keysize)

    encrypted = encrypt(msg1, public)
    decrypted = decrypt(encrypted, private)

    signature = sign(msg1, private)
    fake_signature = sign(msg2, private)

    verify1 = verify(msg1, signature, public)
    verify_false = verify(msg1, fake_signature, public)

    export_key(public, public_key_file)
    export_key(private, private_key_file, "TOPSECRETPASSWORD")

    shares, enc, nonce, tag = share_key(
        private.export_key(passphrase="password"), nShares=3
    )
    dec = combine_shares(shares, enc, nonce, tag, "password")

    print(f"Encrypted: {encrypted}")
    print("Decrypted: '%s'" % decrypted)
    print(f"Signature: {signature}")
    print(f"Verify: {verify1}")
    print(f"Verify False: {verify_false}")
    print(import_key(public_key_file))
    print(import_key(private_key_file, "TOPSECRETPASSWORD"))
    print(decrypt(encrypted, dec))
