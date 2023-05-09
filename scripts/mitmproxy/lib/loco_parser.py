import bson, logging, struct, io
from .crypto_utils import aes_encrypt, aes_decrypt


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

    # TODO: Add exception handling
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
        except Exception as e:
            logging.error(f"Could not create LOCO packet: {e}")
            return None

    def get_packet_as_dict(self) -> dict:
        loco_dict = vars(self)

        try:
            if loco_dict["body_payload"]:
                loco_dict["body_payload"] = bson.loads(self.body_payload)
        except:
            logging.error("Could not decode BSON body.")

        return loco_dict


class LocoEncryptedPacket:
    def __init__(self, length=0, iv=b"", payload=b""):
        self.length = length
        self.iv = iv
        self.payload = payload

    # TODO: Add exception handling
    def get_packet_bytes(self, loco_packet: LocoPacket) -> bytes:
        # new_iv = os.urandom(16)

        if not loco_packet:
            logging.error(
                f"Could not create LOCO encrypted packet: Loco packet data is None."
            )
            return None

        encrypted_packet = aes_encrypt(loco_packet, self.iv)

        if not encrypted_packet:
            logging.error(f"Could not encrypt LOCO packet.")
            return None

        try:
            f = io.BytesIO()
            f.write(struct.pack("<I", len(encrypted_packet) + len(self.iv)))
            f.write(self.iv)
            f.write(encrypted_packet)
            return f.getvalue()
        except Exception as e:
            logging.error(f"Could not create LOCO encrypted packet: {e}")
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

    # TODO: Add exception handling
    def parse_loco_packet(self, data):
        if not data:
            logging.error(
                f"Could not parse LOCO encrypted packet: Packet data is None."
            )
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
        except Exception as e:
            logging.error(f"Could not parse LOCO packet: {e}")
            return None

    # TODO: Add exception handling
    def parse_loco_encrypted_packet(self, data):
        if not data:
            logging.error(
                f"Could not parse LOCO encrypted packet: Packet data is None."
            )
            return None

        try:
            length = struct.unpack("<I", data[0:4])[0]
            iv = data[4:20]
            payload = data[20:]
            return LocoEncryptedPacket(length, iv, payload)
        except Exception as e:
            logging.error(f"Could not parse LOCO encrypted packet: {e}")
            return None

    # TODO: Add exception handling
    def parse_handshake_packet(self, data):
        if not data:
            logging.error(
                f"Could not parse LOCO handshake packet: Packet data is None."
            )
            return None

        try:
            type = struct.unpack("<I", data[4:8])[0]
            block_cipher_mode = struct.unpack("<I", data[8:12])[0]
            payload = data[22:]
            return LocoHandshakePacket(type, block_cipher_mode, payload)
        except Exception as e:
            logging.error(f"Could not parse LOCO handshake packet: {e}")
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

        if not self.loco_packet.loco_command == "MSG":
            return None

        body_json = self.bson_decode(self.loco_packet.body_payload)

        if (
            "chatLog" in body_json
            and body_json["chatLog"]["message"] == trigger_message
        ):
            body_json["chatLog"]["message"] = payload
            self.loco_packet.body_payload = self.bson_encode(body_json)
            self.loco_packet.body_length = len(self.loco_packet.body_payload)
            return self.loco_encrypted_packet.get_packet_bytes(
                self.loco_packet.get_packet_bytes()
            )

    def bson_encode(self, data):
        return bson.dumps(data)

    def bson_decode(self, data):
        return bson.loads(data)
