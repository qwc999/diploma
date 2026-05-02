"""aes_ecb_mode: AES в режиме ECB (CWE-327).

Электронный режим Codebook не скрывает паттерны в открытом тексте
(одинаковые 16-байтовые блоки дают одинаковые шифро-блоки) и не
обеспечивает аутентификацию. Любое его использование в backend-коде
трактуется как уязвимость; промежуточного «менее опасного» ECB
не существует, поэтому severity всегда `high`.

Покрываются обе распространённые библиотеки и пять форм вызова:

- cryptography (PyCA Hazmat):
    - Cipher(algorithms.AES(key), modes.ECB(), backend=...)
    - Cipher(algorithms.AES(key), ECB(), backend=...)         # прямой импорт
- pycryptodome (Crypto.Cipher.AES):
    - AES.new(key, AES.MODE_ECB)                              # позиционно
    - AES.new(key, mode=AES.MODE_ECB)                         # kwarg
    - A.new(key, A.MODE_ECB)                                  # импорт с алиасом
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
from Crypto.Cipher import AES as A


KEY = b"x" * 16
PLAINTEXT = b"data" * 4


def encrypt_pyca_modes_ecb(key: bytes, plaintext: bytes) -> bytes:
    # VULN: PyCA Hazmat, режим задан через `modes.ECB()` (B305 у Bandit)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_pyca_direct_ecb(key: bytes, plaintext: bytes) -> bytes:
    # VULN: PyCA Hazmat, режим задан через прямой импорт `ECB()` (B305 у Bandit)
    cipher = Cipher(algorithms.AES(key), ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_pycryptodome_positional(key: bytes, plaintext: bytes) -> bytes:
    # VULN: pycryptodome, AES.MODE_ECB как позиционный аргумент (Bandit пропускает)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encrypt_pycryptodome_kwarg(key: bytes, plaintext: bytes) -> bytes:
    # VULN: pycryptodome, MODE_ECB как kwarg `mode=` (Bandit пропускает)
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encrypt_pycryptodome_aliased(key: bytes, plaintext: bytes) -> bytes:
    # VULN: pycryptodome через алиас импорта (`AES as A`); MODE_ECB через A
    cipher = A.new(key, A.MODE_ECB)
    return cipher.encrypt(plaintext)
