from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_KEY = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def aes_encrypt(plaintext, iv):
    cipher = Cipher(algorithms.AES(_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_decrypt(ciphertext, iv):
    cipher = Cipher(algorithms.AES(_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
