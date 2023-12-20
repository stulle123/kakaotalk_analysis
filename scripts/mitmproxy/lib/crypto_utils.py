import math

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Key used by Frida script to patch KakaoTalk's AES encryption key
_AES_KEY = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def aes_encrypt(plaintext, iv):
    cipher = Cipher(algorithms.AES(_AES_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def aes_decrypt(ciphertext, iv):
    cipher = Cipher(algorithms.AES(_AES_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_e2e_decrypt(ciphertext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def get_rsa_key_pair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def get_rsa_public_key_pem(key_pair):
    return key_pair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def rsa_encrypt(plaintext: bytes, public_key_pem: str, add_header_footer: bool = False):
    if add_header_footer:
        header = "-----BEGIN RSA PUBLIC KEY-----\n"
        footer = "\n-----END RSA PUBLIC KEY-----\n"
        public_key_pem = header + public_key_pem + footer
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    return ciphertext


def rsa_decrypt(ciphertext: bytes, key_pair) -> bytes:
    plaintext = key_pair.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    return plaintext


def compute_key(shared_secret: bytes, salt: bytes, length):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=length, salt=salt, iterations=2048)
    key = kdf.derive(shared_secret)
    return key


def compute_hmac(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def byte_juggling_1(i, i2, b_arr):
    z = i <= i2

    if z:
        length = len(b_arr)
        if 0 <= i <= length:
            i3 = i2 - i
            i4 = length - i
            if i3 <= i4:
                i4 = i3
            b_arr_2 = bytearray(i3)
            b_arr_2[:i4] = b_arr[i : i + i4]

            return b_arr_2

    return None


def byte_juggling_2(b_arr, b_arr2):
    length = len(b_arr2)

    for b_arr3 in b_arr:
        length += len(b_arr3)

    b_arr4 = bytearray(length)
    length2 = len(b_arr2)
    b_arr4[:length2] = b_arr2

    for b_arr5 in b_arr:
        b_arr4[length2 : length2 + len(b_arr5)] = b_arr5
        length2 += len(b_arr5)

    return b_arr4


def compute_nonce(shared_secret: bytes, message_id):
    message_id_bytes = message_id.to_bytes(8, "little")
    salt_1 = b"53656372657443686174526f6f6d4b6579"  # SecretChatRoomKey
    salt_2 = b"4d6573736167654e6f6e6365486d6163"  # MessageNonceHmac
    key = compute_key(shared_secret, salt_1, 64)
    nonce_input = salt_2 + message_id_bytes
    length = len(key) - 32

    if length <= 0:
        length = 0

    mac_key = byte_juggling_1(length, len(key), key)
    new_mac_key = compute_hmac(mac_key, shared_secret)

    b_arr_2 = b""
    b_arr_3 = b""

    ceil = int(math.floor(40 / 32))

    for i4 in range(ceil):
        hex_i4 = format(i4 + 1, "x").zfill(2)
        hex_bytes = bytes.fromhex(hex_i4)
        mac_msg = byte_juggling_2([nonce_input, hex_bytes], b_arr_3)
        b_arr_3 = compute_hmac(new_mac_key, mac_msg)
        b_arr_2 = byte_juggling_2([b_arr_3], b_arr_2)

    nonce = byte_juggling_1(0, 40, b_arr_2)

    return nonce[:8] + (8 * b"\x00")
