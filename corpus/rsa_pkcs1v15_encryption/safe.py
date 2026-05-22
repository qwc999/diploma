"""rsa_pkcs1v15_encryption: safe OAEP analogs and signature-only PKCS1v15 use."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def encrypt_with_module_padding(public_key: RSAPublicKey, message: bytes) -> bytes:
    # SAFE: RSA encryption uses OAEP with MGF1 and SHA-256
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_module_padding(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    # SAFE: RSA decryption uses OAEP with MGF1 and SHA-256
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_with_padding_alias(public_key: RSAPublicKey, message: bytes) -> bytes:
    # SAFE: RSA encryption uses OAEP through the same import alias
    return public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_direct_import(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    # SAFE: RSA decryption uses directly imported OAEP helpers
    return private_key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_with_pkcs1v15(private_key: RSAPrivateKey, message: bytes) -> bytes:
    # SAFE: PKCS#1 v1.5 padding is allowed for RSA signatures
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def verify_with_pkcs1v15(
    public_key: RSAPublicKey,
    signature: bytes,
    message: bytes,
) -> None:
    # SAFE: PKCS#1 v1.5 padding is allowed for RSA signature verification
    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
