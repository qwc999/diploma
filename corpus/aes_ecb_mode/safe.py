"""aes_ecb_mode: безопасные аналоги из vulnerable.py.

Каждая функция решает ту же задачу шифрования, что в vulnerable.py,
но с режимом, отличным от ECB. Линтер не должен выдавать ни одного
срабатывания на этом файле.

Зеркальные пять сценариев — на AES-GCM (рекомендованный AEAD по умолчанию,
suggestion правила CRYPTO003). Дополнительно два сценария на AES-CBC и
AES-CTR с уникальными IV/nonce — чтобы убедиться, что любой не-ECB режим
не флагуется правилом, а не только GCM.
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
from Crypto.Cipher import AES as A


KEY = b"x" * 16
PLAINTEXT = b"data" * 4


def encrypt_pyca_modes_gcm(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: PyCA Hazmat, AEAD-режим GCM через `modes.GCM(iv)`
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_pyca_direct_gcm(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: PyCA Hazmat, AEAD-режим GCM через прямой импорт `GCM(iv)`
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_pycryptodome_gcm_positional(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: pycryptodome, AEAD-режим GCM как позиционный аргумент
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, _tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext


def encrypt_pycryptodome_gcm_kwarg(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: pycryptodome, AEAD-режим GCM как kwarg `mode=`
    nonce = os.urandom(12)
    cipher = AES.new(key, mode=AES.MODE_GCM, nonce=nonce)
    ciphertext, _tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext


def encrypt_pycryptodome_gcm_aliased(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: pycryptodome через алиас импорта (`AES as A`), AEAD-режим GCM
    nonce = os.urandom(12)
    cipher = A.new(key, A.MODE_GCM, nonce=nonce)
    ciphertext, _tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext


def encrypt_pycryptodome_cbc(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: AES-CBC с уникальным IV — не AEAD, но и не ECB; правило молчит
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(plaintext)


def encrypt_pycryptodome_ctr(key: bytes, plaintext: bytes) -> bytes:
    # SAFE: AES-CTR с уникальным nonce — не AEAD, но и не ECB; правило молчит
    nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext)
