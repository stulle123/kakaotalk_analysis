import io
import logging
import struct

import bson

from lib.crypto_utils import aes_encrypt


class LocoPacket:
    def __init__(
        self,
        identifier=0,
        status_code=0,
        loco_command="",
        body_type=0,
        body_length=0,
        body_payload=b"",
    ):
        self.id = identifier
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
            loco_dict = {}
            logging.error(
                "Couldn't decode BSON body of %s packet. Exception: %s.",
                self.loco_command,
                general_exception,
            )

        return loco_dict


class LocoEncryptedPacket:
    def __init__(self, length=0, iv=b"", payload=b"", is_fragmented=False):
        self.length = length
        self.iv = iv
        self.payload = payload
        self.is_fragmented = is_fragmented

    def create_new_packet(self, loco_packet: LocoPacket) -> bytes:
        if not loco_packet:
            logging.error(
                "Could not create LOCO encrypted packet: LOCO packet data is None."
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
    def __init__(self, length=256, handshake_type=0, block_cipher_mode=0, payload=b""):
        self.length = length
        self.type = handshake_type
        self.block_cipher_mode = block_cipher_mode
        self.payload = payload

        self.cipher_mode_map = {1: "CBC", 2: "AES/CFB/NoPadding", 3: "OFB"}
        self.encryption_mode_map = {15: "RSA/NONE/OAEPWithSHA1AndMGF1Padding"}
