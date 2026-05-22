"""rsa_pkcs1v15_encryption: RSA encrypt/decrypt with PKCS#1 v1.5 padding.

PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher-style oracle
attacks. For RSA encryption/decryption, use OAEP instead.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def encrypt_with_module_padding(public_key: RSAPublicKey, message: bytes) -> bytes:
    # VULN: RSA encryption uses PKCS#1 v1.5 padding instead of OAEP
    return public_key.encrypt(message, padding.PKCS1v15())


def decrypt_with_module_padding(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    # VULN: RSA decryption uses PKCS#1 v1.5 padding instead of OAEP
    return private_key.decrypt(ciphertext, padding.PKCS1v15())


def encrypt_with_padding_alias(public_key: RSAPublicKey, message: bytes) -> bytes:
    # VULN: RSA encryption uses PKCS#1 v1.5 padding via an import alias
    return public_key.encrypt(message, asym_padding.PKCS1v15())


def decrypt_with_direct_import(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    # VULN: RSA decryption uses directly imported PKCS#1 v1.5 padding
    return private_key.decrypt(ciphertext, PKCS1v15())
